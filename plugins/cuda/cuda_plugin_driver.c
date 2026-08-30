#include "criu-log.h"
#include "cuda_checkpoint.h"
#include "cuda_device_map.h"
#include "cuda_plugin.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "proc_parse.h"
#include "seize.h"

#include <common/list.h>
#include <compel/infect.h>

#include <dlfcn.h>
#include <string.h>
#include <sys/ptrace.h>

static void *cuda_handle;
static bool cuda_driver_initialized;

struct cuda_driver_api {
	CUresult (*init)(unsigned int flags);
	CUresult (*driver_get_version)(int *driver_version);
	CUresult (*get_error_name)(CUresult error, const char **pstr);
	CUresult (*get_error_string)(CUresult error, const char **pstr);
	CUresult (*lock)(int pid, CUcheckpointLockArgs *args);
	CUresult (*checkpoint)(int pid, CUcheckpointCheckpointArgs *args);
	CUresult (*restore)(int pid, CUcheckpointRestoreArgs *args);
	CUresult (*unlock)(int pid, CUcheckpointUnlockArgs *args);
	CUresult (*get_state)(int pid, CUprocessState *state);
	CUresult (*get_restore_tid)(int pid, int *tid);
};

static struct cuda_driver_api cuda_api;

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

static void cuda_api_fini(void)
{
	if (cuda_handle) {
		dlclose(cuda_handle);
		cuda_handle = NULL;
	}

	memset(&cuda_api, 0, sizeof(cuda_api));
	cuda_driver_initialized = false;
}

static void *cuda_get_symbol(const char *name)
{
	const char *err;
	void *symbol;

	dlerror();
	symbol = dlsym(cuda_handle, name);
	err = dlerror();
	if (err) {
		pr_debug("Unable to resolve %s from libcuda.so.1: %s\n", name, err);
		return NULL;
	}

	return symbol;
}

static const char *cuda_result_name(CUresult res)
{
	const char *name = NULL;

	if (!cuda_api.get_error_name)
		return "CUDA_ERROR_UNKNOWN";

	if (cuda_api.get_error_name(res, &name) != CUDA_SUCCESS || !name)
		return "CUDA_ERROR_UNKNOWN";

	return name;
}

static const char *cuda_result_string(CUresult res)
{
	const char *str = NULL;

	if (!cuda_api.get_error_string)
		return NULL;

	if (cuda_api.get_error_string(res, &str) != CUDA_SUCCESS || !str)
		return NULL;

	return str;
}

static void cuda_log_error(const char *op, int pid, CUresult res)
{
	const char *name = cuda_result_name(res);
	const char *str = cuda_result_string(res);

	if (str)
		pr_err("%s(%d) failed: %s (%d): %s\n", op, pid, name, res, str);
	else
		pr_err("%s(%d) failed: %s (%d)\n", op, pid, name, res);
}

#define LOAD_CUDA_SYMBOL(member, symbol)                                            \
	do {                                                                        \
		cuda_api.member = (typeof(cuda_api.member))cuda_get_symbol(symbol); \
	} while (0)

static int cuda_driver_probe(bool device_map_requested)
{
	int driver_version;
	CUresult res;

	(void)device_map_requested;

	/* RTLD_NODELETE keeps libcuda mapped after dlclose(); once cuInit()
	 * has run, the driver may have internal threads and state that do not
	 * survive unmapping the library.
	 */
	cuda_handle = dlopen("libcuda.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE);
	if (!cuda_handle) {
		pr_info("Cannot load libcuda.so.1: %s\n", dlerror());
		return -ENOTSUP;
	}

	LOAD_CUDA_SYMBOL(get_error_name, "cuGetErrorName");
	LOAD_CUDA_SYMBOL(get_error_string, "cuGetErrorString");
	LOAD_CUDA_SYMBOL(init, "cuInit");
	LOAD_CUDA_SYMBOL(driver_get_version, "cuDriverGetVersion");
	LOAD_CUDA_SYMBOL(lock, "cuCheckpointProcessLock");
	LOAD_CUDA_SYMBOL(checkpoint, "cuCheckpointProcessCheckpoint");
	LOAD_CUDA_SYMBOL(restore, "cuCheckpointProcessRestore");
	LOAD_CUDA_SYMBOL(unlock, "cuCheckpointProcessUnlock");
	LOAD_CUDA_SYMBOL(get_state, "cuCheckpointProcessGetState");
	LOAD_CUDA_SYMBOL(get_restore_tid, "cuCheckpointProcessGetRestoreThreadId");

	if (!cuda_api.init || !cuda_api.driver_get_version || !cuda_api.lock || !cuda_api.checkpoint || !cuda_api.restore ||
	    !cuda_api.unlock || !cuda_api.get_state || !cuda_api.get_restore_tid) {
		pr_warn("CUDA checkpoint Driver API not available in libcuda.so.1\n");
		cuda_api_fini();
		return -ENOTSUP;
	}

	driver_version = 0;
	res = cuda_api.driver_get_version(&driver_version);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuDriverGetVersion", 0, res);
		cuda_api_fini();
		return -1;
	}

	if (driver_version < CUDA_DIRECT_MIN_DRIVER_API_VERSION) {
		pr_info("CUDA Driver API version %d is older than the direct backend minimum %d\n",
			driver_version, CUDA_DIRECT_MIN_DRIVER_API_VERSION);
		cuda_api_fini();
		return -ENOTSUP;
	}

	pr_info("CUDA Driver API backend supported (driver API version %d, minimum %d)\n",
		driver_version, CUDA_DIRECT_MIN_DRIVER_API_VERSION);
	return 0;
}

#undef LOAD_CUDA_SYMBOL

/* cuCheckpointProcessRestore() requires the driver to be initialized in the
 * calling process unless persistence mode is enabled. Defer cuInit() until
 * the first restore so that a dump on a host with a GPU does not pay the
 * driver initialization cost for tasks that do not use CUDA.
 */
static int cuda_driver_init(void)
{
	CUresult res;

	if (cuda_driver_initialized)
		return 0;

	/* The CUDA Driver API currently requires Flags to be zero. */
	res = cuda_api.init(0);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuInit", 0, res);
		return -1;
	}

	cuda_driver_initialized = true;
	return 0;
}

/* Retrieve the cuda restore thread TID from the root pid */
static enum cuda_restore_tid_result get_cuda_restore_tid(int root_pid, int *tid)
{
	CUresult res;

	res = cuda_api.get_restore_tid(root_pid, tid);
	if (res != CUDA_SUCCESS) {
		if (res == CUDA_ERROR_INVALID_VALUE || res == CUDA_ERROR_NOT_INITIALIZED) {
			pr_debug("PID %d has no CUDA restore thread\n", root_pid);
			return CUDA_RESTORE_TID_NOT_FOUND;
		}

		cuda_log_error("cuCheckpointProcessGetRestoreThreadId", root_pid, res);
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
	CUprocessState state;
	CUresult res;

	res = cuda_api.get_state(pid, &state);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuCheckpointProcessGetState", pid, res);
		return CUDA_TASK_UNKNOWN;
	}

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
	CUcheckpointUnlockArgs args = { 0 };
	CUresult res;

	res = cuda_api.unlock(pid, &args);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuCheckpointProcessUnlock", pid, res);
		return -1;
	}

	return 0;
}

static int interrupt_restore_thread(int restore_tid, k_rtsigset_t *restore_sigset)
{
	struct proc_status_creds creds;
	const unsigned long ptrace_options = PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD;
	int ret = 0;

	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, restore_tid, NULL, 0)) {
		pr_perror("Could not interrupt CUDA restore tid %d after checkpoint", restore_tid);
		return -1;
	}

	if (compel_wait_task(restore_tid, -1, parse_pid_status, NULL,
			     &creds.s, NULL) != COMPEL_TASK_ALIVE) {
		pr_err("compel_wait_task failed after interrupt\n");
		return -1;
	}

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

static int resume_restore_thread(int restore_tid, k_rtsigset_t *save_sigset)
{
	const unsigned long ptrace_options = PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD;
	k_rtsigset_t block;
	bool options_cleared = false;
	bool sigmask_changed = false;

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
	CUcheckpointCheckpointArgs args = { 0 };
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
		 * to its original state at cuda_plugin_fini().
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
	res = cuda_api.checkpoint(pid, &args);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuCheckpointProcessCheckpoint", pid, res);
		ret = -1;
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

	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);
	if (!ret)
		ret = int_ret;

	return ret;
}

static int cuda_driver_pause_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	CUcheckpointLockArgs args = { 0 };
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
	args.timeoutMs = opts.timeout * 1000;

	res = cuda_api.lock(pid, &args);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuCheckpointProcessLock", pid, res);
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
			 cuda_task_state_t initial_task_state,
			 const struct cuda_device_map *device_map)
{
	cuda_task_state_t observed_task_state;
	enum cuda_restore_tid_result tid_result;
	k_rtsigset_t save_sigset;
	int restore_tid;
	CUresult res;
	int ret = 0;
	int int_ret;

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
		CUcheckpointRestoreArgs args = { 0 };

		if (device_map) {
			args.gpuPairs = device_map->pairs;
			args.gpuPairsCount = device_map->count;
		}

		if (cuda_driver_init()) {
			ret = -1;
		} else {
			res = cuda_api.restore(pid, &args);
			if (res != CUDA_SUCCESS) {
				cuda_log_error("cuCheckpointProcessRestore", pid, res);
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

static int cuda_driver_resume_devices_late(int pid, const struct cuda_device_map *device_map)
{
	/* RESUME_DEVICES_LATE is used during `criu restore`.
	 * Here, we assume that users expect the target process
	 * to be in a "running" state after restore, even if it was
	 * in a "locked" or "checkpointed" state during `criu dump`.
	 */
	return resume_device(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_RUNNING, device_map);
}

static int cuda_driver_backend_init(int stage)
{
	/* In the DUMP stage track all the PID's we've paused CUDA operations on to
	 * release them when we're done if the user requested the leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&cuda_pids);
	}

	return 0;
}

static void cuda_driver_backend_fini(int stage, int ret)
{
	/* Release all the paused PID's at the end of the DUMP stage in case the
	 * user provides the -R (leave-running) flag or an error occurred
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && (opts.final_state == TASK_ALIVE || ret != 0)) {
		struct pid_info *info;
		list_for_each_entry(info, &cuda_pids, list) {
			if (resume_device(info->pid, info->current_task_state, info->initial_task_state, NULL))
				pr_err("Unable to restore CUDA state for pid %d during dump cleanup\n", info->pid);
		}
	}
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		free_cuda_pid_list();
	}

	cuda_api_fini();
}

const struct cuda_plugin_backend cuda_driver_backend = {
	.name = "Driver API",
	.probe = cuda_driver_probe,
	.init = cuda_driver_backend_init,
	.fini = cuda_driver_backend_fini,
	.pause_devices = cuda_driver_pause_devices,
	.checkpoint_devices = cuda_driver_checkpoint_devices,
	.resume_devices_late = cuda_driver_resume_devices_late,
};
