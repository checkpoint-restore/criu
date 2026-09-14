#include "criu-log.h"
#include "cuda_checkpoint.h"
#include "cuda_driver_worker.h"
#include "cuda_wait.h"
#include "cuda_plugin.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "seize.h"

#include <common/list.h>
#include <compel/ksigset.h>

#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

/* CRIU owns ptrace; only the worker enters libcuda. */
static bool driver_failed;
static int running_restore_tid;
static int restore_thread_status = -1;

typedef enum {
	CUDA_TASK_RUNNING = 0,
	CUDA_TASK_LOCKED,
	CUDA_TASK_CHECKPOINTED,
	CUDA_TASK_FAILED,
	CUDA_TASK_UNKNOWN = -1
} cuda_task_state_t;

enum cuda_restore_tid_result {
	CUDA_RESTORE_TID_FOUND,
	CUDA_RESTORE_TID_NOT_FOUND,
	CUDA_RESTORE_TID_ERROR,
};

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

struct pid_info {
	int pid;
	cuda_task_state_t current_task_state;
	cuda_task_state_t initial_task_state;
	struct list_head list;
};

/* Used to track which PID's we've paused CUDA operations on so far so we can
 * release them after we're done with the DUMP
 */
static LIST_HEAD(cuda_pids);

static void free_cuda_pid_list(void)
{
	struct pid_info *info;
	struct pid_info *n;

	list_for_each_entry_safe(info, n, &cuda_pids, list) {
		list_del(&info->list);
		xfree(info);
	}
}

static int track_cuda_pid(int pid, cuda_task_state_t initial_state, cuda_task_state_t current_state)
{
	struct pid_info *info = xmalloc(sizeof(*info));

	if (!info)
		return -1;

	info->pid = pid;
	info->current_task_state = current_state;
	info->initial_task_state = initial_state;
	list_add_tail(&info->list, &cuda_pids);

	return 0;
}

static struct pid_info *find_cuda_pid(int pid)
{
	struct pid_info *info;

	list_for_each_entry(info, &cuda_pids, list) {
		if (info->pid == pid)
			return info;
	}

	return NULL;
}

static CUresult cuda_driver_call(enum cuda_driver_operation op, int pid, unsigned int timeout_ms,
				 int *value)
{
	struct cuda_driver_request request = { .op = op, .pid = pid, .timeout_ms = timeout_ms };
	struct cuda_driver_reply reply;

	if (driver_failed)
		return -1;

	if (cuda_driver_worker_call(&request, &reply, running_restore_tid, &restore_thread_status) || reply.error) {
		driver_failed = true;
		pr_err("CUDA Driver API helper failed for pid %d; GPU state cannot be recovered through this helper\n", pid);
		return -1;
	}
	if (value)
		*value = reply.value;
	return reply.result;
}

static int cuda_driver_probe(void)
{
	struct cuda_driver_request request = { .op = CUDA_DRIVER_PROBE };
	struct cuda_driver_reply reply;
	int ret;

	/* Do not leave a worker or its socket for restore children to inherit.
	 * The operational worker starts at the first device hook, after forking
	 * the restored tree, and keeps driver state until plugin finalization.
	 */
	ret = cuda_driver_worker_call(&request, &reply, 0, NULL);
	if (!ret)
		ret = reply.error;
	if (cuda_driver_worker_fini() && !ret)
		ret = -1;
	return ret;
}

/* Retrieve the cuda restore thread TID from the root pid */
static enum cuda_restore_tid_result get_cuda_restore_tid(int root_pid, int *tid)
{
	CUresult res;

	res = cuda_driver_call(CUDA_DRIVER_GET_TID, root_pid, 0, tid);
	if (res != CUDA_SUCCESS) {
		if (res == CUDA_ERROR_INVALID_VALUE || res == CUDA_ERROR_NOT_INITIALIZED) {
			pr_debug("PID %d has no CUDA restore thread\n", root_pid);
			return CUDA_RESTORE_TID_NOT_FOUND;
		}

		return CUDA_RESTORE_TID_ERROR;
	}

	if (*tid <= 0) {
		pr_err("Invalid CUDA restore tid %d for pid %d\n", *tid, root_pid);
		return CUDA_RESTORE_TID_ERROR;
	}

	return CUDA_RESTORE_TID_FOUND;
}

static cuda_task_state_t get_cuda_state(pid_t pid)
{
	int state;
	CUresult res;

	res = cuda_driver_call(CUDA_DRIVER_GET_STATE, pid, 0, &state);
	if (res != CUDA_SUCCESS)
		return CUDA_TASK_UNKNOWN;

	switch (state) {
	case CU_PROCESS_STATE_RUNNING:
		return CUDA_TASK_RUNNING;
	case CU_PROCESS_STATE_LOCKED:
		return CUDA_TASK_LOCKED;
	case CU_PROCESS_STATE_CHECKPOINTED:
		return CUDA_TASK_CHECKPOINTED;
	case CU_PROCESS_STATE_FAILED:
		return CUDA_TASK_FAILED;
	default:
		pr_err("Unknown CUDA process state for pid %d: %d\n", pid, state);
		return CUDA_TASK_UNKNOWN;
	}
}

static int unlock_cuda_process(int pid)
{
	CUresult res;

	res = cuda_driver_call(CUDA_DRIVER_UNLOCK, pid, 0, NULL);
	if (res != CUDA_SUCCESS)
		return -1;

	return 0;
}

static int stop_restore_thread(int restore_tid, k_rtsigset_t *restore_sigset)
{
	struct cuda_wait wait;
	const unsigned long ptrace_options = PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD;
	int ret = 0;

	running_restore_tid = 0;
	/* The worker monitor already consumed this wait event. Waiting for an
	 * interrupt here would either hang again or deliver the fault signal.
	 * Keep the thread stopped while restoring CRIU's ptrace settings.
	 */
	if (restore_thread_status != -1) {
		if (!WIFSTOPPED(restore_thread_status)) {
			pr_err("CUDA restore thread %d exited during a Driver API call\n", restore_tid);
			return -1;
		}
		goto restore_settings;
	}

	if (cuda_wait_init(&wait, "stop CUDA restore thread", restore_tid, 0, NULL, cuda_plugin_timeout))
		return -1;
	wait.ignore_criu_timeout = true;

	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, restore_tid, NULL, 0)) {
		pr_perror("Could not interrupt CUDA restore tid %d after checkpoint", restore_tid);
		return -1;
	}

	if (cuda_wait_child(&wait, restore_tid, __WALL, &restore_thread_status)) {
		driver_failed = true;
		return -1;
	}
	if (!WIFSTOPPED(restore_thread_status)) {
		pr_err("CUDA restore thread %d exited before it could be stopped\n", restore_tid);
		driver_failed = true;
		return -1;
	}
	if (WSTOPSIG(restore_thread_status) != SIGTRAP || (restore_thread_status >> 16) != PTRACE_EVENT_STOP) {
		pr_err("CUDA restore thread %d stopped unexpectedly with signal %d: %s\n", restore_tid,
		       WSTOPSIG(restore_thread_status), strsignal(WSTOPSIG(restore_thread_status)));
		driver_failed = true;
		ret = -1;
	}

restore_settings:
	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, ptrace_options)) {
		pr_perror("Failed to set ptrace options on interrupt for restore tid %d", restore_tid);
		ret = -1;
	}

	if (ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(*restore_sigset), restore_sigset)) {
		pr_perror("Unable to restore original sigmask to restore tid %d", restore_tid);
		ret = -1;
	}

	return ret;
}

static int interrupt_restore_thread(int restore_tid, k_rtsigset_t *restore_sigset)
{
	sigset_t blocked, saved;
	int ret;

	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blocked, &saved)) {
		pr_perror("Cannot block SIGCHLD while stopping CUDA restore tid %d", restore_tid);
		return -1;
	}
	ret = stop_restore_thread(restore_tid, restore_sigset);
	if (sigprocmask(SIG_SETMASK, &saved, NULL)) {
		pr_perror("Cannot restore signal mask after stopping CUDA restore tid %d", restore_tid);
		ret = -1;
	}
	if (ret)
		driver_failed = true;
	return ret;
}

static int resume_restore_thread(int restore_tid, k_rtsigset_t *save_sigset)
{
	const unsigned long ptrace_options = PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD;
	k_rtsigset_t block;
	bool options_cleared = false;
	bool sigmask_changed = false;

	if (driver_failed) {
		pr_err("Cannot resume CUDA thread %d after Driver API helper failure\n", restore_tid);
		return -1;
	}

	if (ptrace(PTRACE_GETSIGMASK, restore_tid, sizeof(*save_sigset), save_sigset)) {
		pr_perror("Failed to get current sigmask for restore tid %d", restore_tid);
		return -1;
	}

	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);

	if (ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(block), &block)) {
		pr_perror("Failed to block signals on restore tid %d", restore_tid);
		return -1;
	}
	sigmask_changed = true;

	/* Clear PTRACE_O_SUSPEND_SECCOMP when resuming the restore thread. */
	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, 0)) {
		pr_perror("Could not clear ptrace options on restore tid %d", restore_tid);
		goto unwind;
	}
	options_cleared = true;

	if (ptrace(PTRACE_CONT, restore_tid, NULL, 0)) {
		pr_perror("Could not resume cuda restore tid %d", restore_tid);
		goto unwind;
	}

	running_restore_tid = restore_tid;
	restore_thread_status = -1;

	return 0;

unwind:
	if (options_cleared && ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, ptrace_options))
		pr_perror("Unable to restore ptrace options for CUDA restore tid %d", restore_tid);
	if (sigmask_changed &&
	    ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(*save_sigset), save_sigset))
		pr_perror("Unable to restore signal mask for CUDA restore tid %d", restore_tid);

	return -1;
}

static int cuda_driver_checkpoint_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	struct pid_info *task_info;
	cuda_task_state_t observed_task_state;
	k_rtsigset_t save_sigset;
	CUresult res;
	int restore_tid;
	int int_ret;
	int ret = 0;

	tid_result = get_cuda_restore_tid(pid, &restore_tid);

	/* We can possibly hit a race with cuInit() where we are past the point of
	 * locking the process but at lock time cuInit() hadn't completed in which
	 * case the CUDA Driver API will report an invalid state to checkpoint.
	 */
	if (tid_result == CUDA_RESTORE_TID_NOT_FOUND) {
		pr_info("No need to checkpoint devices on pid %d\n", pid);
		return -ENOTSUP;
	}
	if (tid_result == CUDA_RESTORE_TID_ERROR)
		return -1;

	task_info = find_cuda_pid(pid);
	if (!task_info) {
		/* We return an error here. The task should be restored
		 * to its original state at cuda_plugin_dump_finish().
		 */
		pr_err("Failed to track pid %d\n", pid);
		return -1;
	}

	if (task_info->initial_task_state == CUDA_TASK_CHECKPOINTED) {
		pr_info("pid %d already in a checkpointed state\n", pid);
		return 0;
	}

	pr_info("Checkpointing CUDA devices on pid %d restore_tid %d\n", pid, restore_tid);

	/* Keep the process snapshot immutable while checkpointing GPU state. Only
	 * the driver's dedicated restore thread may run after CRIU has seized the
	 * task; every application thread remains in its ptrace stop.
	 */
	if (resume_restore_thread(restore_tid, &save_sigset))
		return -1;

	/* If the API fails before reporting its final state, CHECKPOINTED is the
	 * conservative rollback assumption. Replace it below whenever the driver
	 * can report the actual state while its restore thread is running.
	 */
	task_info->current_task_state = CUDA_TASK_CHECKPOINTED;
	res = cuda_driver_call(CUDA_DRIVER_CHECKPOINT, pid, 0, NULL);
	if (res != CUDA_SUCCESS)
		ret = -1;

	if (driver_failed) {
		task_info->current_task_state = CUDA_TASK_FAILED;
		goto interrupt;
	}

	observed_task_state = get_cuda_state(pid);
	if (observed_task_state != CUDA_TASK_UNKNOWN)
		task_info->current_task_state = observed_task_state;
	else {
		pr_err("Unable to determine CUDA state after checkpointing pid %d\n", pid);
		ret = -1;
	}

	if (res == CUDA_SUCCESS && task_info->current_task_state != CUDA_TASK_CHECKPOINTED) {
		pr_err("CUDA checkpoint succeeded for pid %d but process state is %d\n", pid,
		       task_info->current_task_state);
		ret = -1;
	}

interrupt:
	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);
	if (!ret)
		ret = int_ret;

	return ret;
}

static int cuda_driver_pause_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	cuda_task_state_t task_state;
	int restore_tid;
	CUresult res;

	tid_result = get_cuda_restore_tid(pid, &restore_tid);

	if (tid_result == CUDA_RESTORE_TID_NOT_FOUND) {
		pr_info("no need to pause devices on pid %d\n", pid);
		return -ENOTSUP;
	}
	if (tid_result == CUDA_RESTORE_TID_ERROR)
		return -1;

	task_state = get_cuda_state(pid);
	if (task_state == CUDA_TASK_UNKNOWN) {
		pr_err("Failed to get CUDA state for pid %d\n", pid);
		return -1;
	}
	if (task_state == CUDA_TASK_FAILED) {
		pr_err("CUDA pid %d is in an unrecoverable failed state\n", pid);
		return -1;
	}

	if (cuda_plugin_add_inventory())
		return -1;

	if (task_state == CUDA_TASK_LOCKED) {
		pr_info("pid %d already in a locked state\n", pid);
		/* Leave this PID in a "locked" state at resume_device() */
		return track_cuda_pid(pid, CUDA_TASK_LOCKED, CUDA_TASK_LOCKED);
	}

	if (task_state == CUDA_TASK_CHECKPOINTED) {
		/* We need to skip this PID in cuda_plugin_checkpoint_devices(),
		 * and leave it in a "checkpointed" state at resume_device(). */
		return track_cuda_pid(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_CHECKPOINTED);
	}

	pr_info("pausing devices on pid %d\n", pid);
	res = cuda_driver_call(CUDA_DRIVER_LOCK, pid, opts.timeout * 1000, NULL);
	if (res != CUDA_SUCCESS) {
		task_state = get_cuda_state(pid);
		if (task_state != CUDA_TASK_LOCKED)
			return -1;

		pr_warn("CUDA lock failed but pid %d is locked; unlocking it\n", pid);
		if (unlock_cuda_process(pid))
			pr_err("Failed to unlock pid %d after lock failure; process may hang\n", pid);
		return -1;
	}

	task_state = get_cuda_state(pid);
	if (task_state != CUDA_TASK_LOCKED) {
		pr_err("CUDA lock succeeded for pid %d but state is %d\n", pid, task_state);
		if (task_state == CUDA_TASK_RUNNING)
			return -1;
		if (unlock_cuda_process(pid))
			pr_err("Failed to unlock pid %d after state mismatch; process may hang\n", pid);
		return -1;
	}

	if (track_cuda_pid(pid, CUDA_TASK_RUNNING, CUDA_TASK_LOCKED)) {
		pr_err("unable to track paused pid %d\n", pid);
		if (unlock_cuda_process(pid))
			pr_err("Failed to unlock pid %d after tracking failure; process may hang\n", pid);
		return -1;
	}

	return 0;
}

static int resume_device(int pid, cuda_task_state_t current_task_state,
			 cuda_task_state_t initial_task_state)
{
	cuda_task_state_t observed_task_state;
	enum cuda_restore_tid_result tid_result;
	k_rtsigset_t save_sigset;
	int restore_tid;
	CUresult res;
	int ret = 0;
	int int_ret;

	if (driver_failed) {
		pr_err("Cannot recover CUDA state for pid %d after Driver API helper failure\n", pid);
		return -1;
	}

	if (initial_task_state == CUDA_TASK_UNKNOWN || initial_task_state == CUDA_TASK_FAILED) {
		pr_err("Cannot restore pid %d to invalid CUDA state %d\n", pid, initial_task_state);
		return -1;
	}

	if (current_task_state == CUDA_TASK_FAILED) {
		pr_err("Cannot resume pid %d from failed CUDA state\n", pid);
		return -1;
	}

	if (current_task_state == initial_task_state)
		return 0;

	if (initial_task_state == CUDA_TASK_CHECKPOINTED) {
		pr_err("Cannot return pid %d from CUDA state %d to checkpointed state\n",
		       pid, current_task_state);
		return -1;
	}

	tid_result = get_cuda_restore_tid(pid, &restore_tid);
	if (tid_result == CUDA_RESTORE_TID_NOT_FOUND) {
		pr_info("No need to resume devices on pid %d\n", pid);
		return -ENOTSUP;
	}
	if (tid_result == CUDA_RESTORE_TID_ERROR) {
		pr_err("Unable to find CUDA restore thread for pid %d\n", pid);
		return -1;
	}

	pr_info("resuming devices on pid %d\n", pid);
	/* The resuming process has to stay frozen during this time otherwise
	 * attempting to access a UVM pointer will crash if we haven't restored the
	 * underlying mappings yet
	 */
	pr_debug("Restore thread pid %d found for real pid %d\n", restore_tid, pid);
	/* wakeup the restore thread so we can handle the restore for this pid,
	 * rseq_cs has to be restored before execution
	 */
	if (resume_restore_thread(restore_tid, &save_sigset)) {
		return -1;
	}

	/* State queries can block while the CUDA restore thread is frozen. Query
	 * only after resuming it, and prefer the driver's state over the state
	 * recorded around the checkpoint call.
	 */
	observed_task_state = get_cuda_state(pid);
	if (observed_task_state != CUDA_TASK_UNKNOWN)
		current_task_state = observed_task_state;
	else {
		pr_warn("Unable to query CUDA state for pid %d; using tracked state %d\n",
			pid, current_task_state);
		ret = -1;
	}
	if (current_task_state == CUDA_TASK_UNKNOWN) {
		pr_err("Unable to determine CUDA state for pid %d\n", pid);
		ret = -1;
		goto interrupt;
	}

	if (current_task_state == CUDA_TASK_FAILED) {
		pr_err("Cannot resume pid %d from failed CUDA state\n", pid);
		ret = -1;
		goto interrupt;
	}
	if (current_task_state == initial_task_state)
		goto interrupt;

	if (current_task_state == CUDA_TASK_CHECKPOINTED) {
		/* If the process was "locked" or "running" before checkpointing it, we need to restore it */
		if (cuda_driver_call(CUDA_DRIVER_INIT, pid, 0, NULL) != CUDA_SUCCESS) {
			ret = -1;
		} else {
			res = cuda_driver_call(CUDA_DRIVER_RESTORE, pid, 0, NULL);
			if (res != CUDA_SUCCESS) {
				/* Preserve this operation failure even if cleanup below reaches
				 * LOCKED or RUNNING successfully.
				 */
				ret = -1;
			} else
				current_task_state = CUDA_TASK_LOCKED;

			observed_task_state = get_cuda_state(pid);
			if (observed_task_state != CUDA_TASK_UNKNOWN)
				current_task_state = observed_task_state;
			else {
				pr_warn("Unable to query CUDA state after restoring pid %d; using state %d\n",
					pid, current_task_state);
				ret = -1;
			}

			if (res == CUDA_SUCCESS && current_task_state != CUDA_TASK_LOCKED) {
				pr_err("CUDA restore succeeded for pid %d but state is %d\n", pid,
				       current_task_state);
				ret = -1;
			}
		}
	}

	if (initial_task_state == CUDA_TASK_RUNNING) {
		if (current_task_state == CUDA_TASK_LOCKED) {
			/* If the process was running before we paused it, unlock it. */
			if (unlock_cuda_process(pid))
				ret = -1;

			observed_task_state = get_cuda_state(pid);
			if (observed_task_state != CUDA_TASK_UNKNOWN)
				current_task_state = observed_task_state;
			else {
				pr_warn("Unable to query CUDA state after unlocking pid %d\n", pid);
				ret = -1;
			}
		}

		if (current_task_state != CUDA_TASK_RUNNING) {
			pr_err("Unable to return pid %d to running state from CUDA state %d\n",
			       pid, current_task_state);
			ret = -1;
		}
	} else if (current_task_state != CUDA_TASK_LOCKED) {
		pr_err("Unable to return pid %d to locked state from CUDA state %d\n", pid, current_task_state);
		ret = -1;
	}

interrupt:
	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);

	return ret != 0 ? ret : int_ret;
}

static int cuda_driver_resume_devices_late(int pid)
{
	/* RESUME_DEVICES_LATE is used during `criu restore`.
	 * Here, we assume that users expect the target process
	 * to be in a "running" state after restore, even if it was
	 * in a "locked" or "checkpointed" state during `criu dump`.
	 */
	return resume_device(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_RUNNING);
}

static int cuda_driver_backend_init(int stage)
{
	driver_failed = false;
	running_restore_tid = 0;
	restore_thread_status = -1;
	/* In the DUMP stage track all the PID's we've paused CUDA operations on to
	 * release them when we're done if the user requested the leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&cuda_pids);
	}

	return 0;
}

static int cuda_driver_backend_dump_finish(int ret)
{
	struct pid_info *info;
	int err = 0;

	if (opts.final_state != TASK_ALIVE && !ret)
		return 0;

	/* Attempt rollback for every task even when an earlier rollback fails. */
	list_for_each_entry(info, &cuda_pids, list) {
		if (resume_device(info->pid, info->current_task_state, info->initial_task_state)) {
			pr_err("Unable to restore CUDA state for pid %d during dump cleanup\n", info->pid);
			err = -1;
		}
	}
	return err;
}

static void cuda_driver_backend_fini(int stage, int ret)
{
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		free_cuda_pid_list();
	}

	cuda_driver_worker_fini();
}

const struct cuda_plugin_backend cuda_driver_backend = {
	.name = "Driver API",
	.probe = cuda_driver_probe,
	.init = cuda_driver_backend_init,
	.fini = cuda_driver_backend_fini,
	.dump_finish = cuda_driver_backend_dump_finish,
	.pause_devices = cuda_driver_pause_devices,
	.checkpoint_devices = cuda_driver_checkpoint_devices,
	.resume_devices_late = cuda_driver_resume_devices_late,
};
