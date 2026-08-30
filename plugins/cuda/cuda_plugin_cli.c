#include "criu-log.h"
#include "cuda_device_map.h"
#include "cuda_plugin.h"
#include "cuda_wait.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "proc_parse.h"
#include "seize.h"

#include <common/list.h>
#include <compel/infect.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

/* cuda-checkpoint binary should live in your PATH */
#define CUDA_CHECKPOINT "cuda-checkpoint"

/* cuda-checkpoint --action flags */
#define ACTION_LOCK	  "lock"
#define ACTION_CHECKPOINT "checkpoint"
#define ACTION_RESTORE	  "restore"
#define ACTION_UNLOCK	  "unlock"

typedef enum {
	CUDA_TASK_RUNNING = 0,
	CUDA_TASK_LOCKED,
	CUDA_TASK_CHECKPOINTED,
	CUDA_TASK_UNKNOWN = -1
} cuda_task_state_t;

enum cuda_restore_tid_result {
	CUDA_RESTORE_TID_FOUND,
	CUDA_RESTORE_TID_NOT_FOUND,
	CUDA_RESTORE_TID_ERROR,
};

#define CUDA_CKPT_BUF_SIZE (128)

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

struct pid_info {
	int pid;
	cuda_task_state_t current_task_state;
	cuda_task_state_t initial_task_state;
	bool lock_pending;
	struct list_head list;
};

/* Used to track which PID's we've paused CUDA operations on so far so we can
 * release them after we're done with the DUMP
 */
static LIST_HEAD(cuda_pids);
static bool backend_failed;
static bool dump_rollback;
static int running_restore_tid;
static int restore_thread_status = -1;

static void dealloc_pid_buffer(struct list_head *pid_buf)
{
	struct pid_info *info;
	struct pid_info *n;

	list_for_each_entry_safe(info, n, pid_buf, list) {
		list_del(&info->list);
		xfree(info);
	}
}

static int add_pid_to_buf(struct list_head *pid_buf, int pid, cuda_task_state_t initial_state,
			  cuda_task_state_t current_state)
{
	struct pid_info *new = xmalloc(sizeof(*new));

	if (new == NULL) {
		return -1;
	}

	new->pid = pid;
	new->initial_task_state = initial_state;
	new->current_task_state = current_state;
	new->lock_pending = false;
	list_add_tail(&new->list, pid_buf);

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

static int launch_cuda_checkpoint(const char **args, const char *operation, int pid, char *buf, int buf_size)
{
	struct cuda_wait wait;
	sigset_t blocked, saved;
	int fd[2], child_pid = -1, buf_off = 0;
	int status, exit_code;

	buf[0] = '\0';
	if (backend_failed) {
		pr_err("Cannot run cuda-checkpoint %s for pid %d after an earlier helper failure\n", operation, pid);
		return -1;
	}

	/* The CRIU SIGCHLD handler must not reap this child or the CUDA thread. */
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blocked, &saved)) {
		pr_perror("Cannot block SIGCHLD while running cuda-checkpoint");
		backend_failed = true;
		return -1;
	}
	exit_code = cuda_wait_init(&wait, operation, pid, running_restore_tid, &restore_thread_status,
				   cuda_plugin_timeout);
	if (exit_code)
		goto failed;
	wait.ignore_criu_timeout = dump_rollback;
	if (pipe(fd)) {
		pr_perror("Couldn't create pipes for reading cuda-checkpoint output");
		exit_code = -1;
		goto failed;
	}

	child_pid = fork();
	if (child_pid == -1) {
		pr_perror("Failed to fork to exec cuda-checkpoint");
		close(fd[0]);
		close(fd[1]);
		exit_code = -1;
		goto failed;
	}
	if (child_pid == 0) {
		if (dup2(fd[1], STDOUT_FILENO) == -1 || dup2(fd[1], STDERR_FILENO) == -1) {
			pr_perror("Unable to redirect cuda-checkpoint output");
			_exit(EXIT_FAILURE);
		}
		close(fd[0]);
		close_fds(STDERR_FILENO + 1);
		if (sigprocmask(SIG_SETMASK, &saved, NULL)) {
			fprintf(stderr, "Cannot restore cuda-checkpoint signal mask: %s\n", strerror(errno));
			_exit(EXIT_FAILURE);
		}
		execvp(args[0], (char **)args);
		/* The log file fd is closed. */
		fprintf(stderr, "execvp(\"%s\") failed: %s\n", args[0], strerror(errno));
		_exit(EXIT_FAILURE);
	}

	close(fd[1]);
	for (;;) {
		char scratch[1024];
		ssize_t size;
		size_t keep;

		exit_code = cuda_wait_fd(&wait, fd[0]);
		if (exit_code)
			break;
		size = read(fd[0], scratch, sizeof(scratch));
		if (size < 0) {
			pr_perror("Unable to read output of cuda-checkpoint");
			exit_code = -1;
			break;
		}
		if (!size)
			break;
		/* Retain a terminated prefix, but drain all output before waiting. */
		keep = size;
		if (keep > (size_t)(buf_size - buf_off - 1))
			keep = buf_size - buf_off - 1;
		memcpy(buf + buf_off, scratch, keep);
		buf_off += keep;
		buf[buf_off] = '\0';
	}
	close(fd[0]);
	if (exit_code)
		goto failed;
	exit_code = cuda_wait_child(&wait, child_pid, 0, &status);
	if (exit_code)
		goto failed;
	child_pid = -1;
	exit_code = cuda_wait_check_thread(&wait);
	if (exit_code)
		goto failed;
	if (WIFSIGNALED(status)) {
		pr_err("cuda-checkpoint unexpectedly signaled with %d: %s\n",
		       WTERMSIG(status), strsignal(WTERMSIG(status)));
		exit_code = -1;
		goto failed;
	}
	if (!WIFEXITED(status)) {
		pr_err("cuda-checkpoint exited improperly: %u\n", status);
		exit_code = -1;
		goto failed;
	}
	exit_code = WEXITSTATUS(status);
	if (exit_code != EXIT_SUCCESS) {
		pr_debug("cuda-checkpoint output ===>\n%s\n<=== cuda-checkpoint output\n", buf);
		if (!strncmp(buf, "execvp(\"", 8))
			exit_code = -ENOENT;
	}
	goto out;

failed:
	/* Recover a timed-out lock only after its helper exits. Calls made with
	 * a resumed restore thread still forbid further CUDA operations.
	 */
	backend_failed = exit_code != -ETIMEDOUT || running_restore_tid;
	if (child_pid > 0) {
		struct cuda_wait cleanup;

		if (kill(child_pid, SIGKILL) < 0 && errno != ESRCH) {
			pr_perror("Unable to kill cuda-checkpoint process %d during cleanup", child_pid);
			backend_failed = true;
		}
		/* Preserve a consumed CUDA thread event and bound helper cleanup too. */
		if (!cuda_wait_init(&cleanup, "cuda-checkpoint cleanup", pid, 0, NULL,
				    CUDA_HELPER_CLEANUP_TIMEOUT)) {
			cleanup.ignore_criu_timeout = true;
			if (cuda_wait_child(&cleanup, child_pid, 0, &status))
				backend_failed = true;
		} else {
			backend_failed = true;
		}
	}
out:
	if (sigprocmask(SIG_SETMASK, &saved, NULL)) {
		pr_perror("Cannot restore signal mask after cuda-checkpoint");
		backend_failed = true;
		exit_code = -1;
	}
	return exit_code;
}

/**
 * Checks if a given flag is supported by the cuda-checkpoint utility
 *
 * Returns 0 if the flag is supported, -ENOTSUP if cuda-checkpoint ran but the
 * flag is unavailable, -ENOENT if cuda-checkpoint could not be executed, and
 * another negative error for a broken probe.
 */
static int cuda_checkpoint_supports_flag(const char *flag)
{
	char msg_buf[2048];
	const char *args[] = { CUDA_CHECKPOINT, "-h", NULL };
	int ret;

	ret = launch_cuda_checkpoint(args, "help", 0, msg_buf, sizeof(msg_buf));
	if (ret < 0)
		return ret;
	if (ret > 0) {
		pr_err("%s help probe failed with exit status %d: %s\n",
		       CUDA_CHECKPOINT, ret, msg_buf);
		return -EIO;
	}

	if (strstr(msg_buf, flag) == NULL)
		return -ENOTSUP;

	return 0;
}

/* Retrieve the CUDA restore thread TID from the root pid. */
static enum cuda_restore_tid_result get_cuda_restore_tid(int root_pid, int *tid)
{
	char pid_buf[16];
	char pid_out[CUDA_CKPT_BUF_SIZE];
	const char *args[] = { CUDA_CHECKPOINT, "--get-restore-tid", "--pid", pid_buf, NULL };
	char *end;
	long value;
	int ret;

	snprintf(pid_buf, sizeof(pid_buf), "%d", root_pid);

	ret = launch_cuda_checkpoint(args, "get-restore-tid", root_pid, pid_out, sizeof(pid_out));
	if (ret < 0) {
		pr_err("Failed to run cuda-checkpoint to retrieve the restore tid\n");
		return CUDA_RESTORE_TID_ERROR;
	}
	if (ret > 0) {
		pr_debug("PID %d has no CUDA restore thread: %s\n", root_pid, pid_out);
		return CUDA_RESTORE_TID_NOT_FOUND;
	}

	errno = 0;
	value = strtol(pid_out, &end, 10);
	while (isspace((unsigned char)*end))
		end++;
	if (errno || end == pid_out || *end || value <= 0 || value > INT_MAX) {
		pr_err("Invalid CUDA restore tid for pid %d: %s\n", root_pid, pid_out);
		return CUDA_RESTORE_TID_ERROR;
	}

	*tid = (int)value;
	return CUDA_RESTORE_TID_FOUND;
}

static cuda_task_state_t get_task_state_enum(const char *state_str)
{
	if (strncmp(state_str, "running", 7) == 0)
		return CUDA_TASK_RUNNING;

	if (strncmp(state_str, "locked", 6) == 0)
		return CUDA_TASK_LOCKED;

	if (strncmp(state_str, "checkpointed", 12) == 0)
		return CUDA_TASK_CHECKPOINTED;

	pr_err("Unknown CUDA state: %s\n", state_str);
	return CUDA_TASK_UNKNOWN;
}

static cuda_task_state_t get_cuda_state(pid_t pid)
{
	char pid_buf[16];
	char state_str[CUDA_CKPT_BUF_SIZE];
	const char *args[] = { CUDA_CHECKPOINT, "--get-state", "--pid", pid_buf, NULL };

	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

	if (launch_cuda_checkpoint(args, "get-state", pid, state_str, sizeof(state_str))) {
		pr_err("Failed to launch cuda-checkpoint to retrieve state: %s\n", state_str);
		return CUDA_TASK_UNKNOWN;
	}

	return get_task_state_enum(state_str);
}

static int cuda_process_checkpoint_action(int pid, const char *action, unsigned int timeout,
					  const char *device_map, char *msg_buf, int buf_size)
{
	char pid_buf[16];
	char timeout_buf[16];
	const char *args[10];
	size_t index = 0;

	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

	args[index++] = CUDA_CHECKPOINT;
	args[index++] = "--action";
	args[index++] = action;
	args[index++] = "--pid";
	args[index++] = pid_buf;
	if (timeout > 0) {
		snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout);
		args[index++] = "--timeout";
		args[index++] = timeout_buf;
	}
	if (device_map) {
		args[index++] = "--device-map";
		args[index++] = device_map;
	}
	args[index] = NULL;

	return launch_cuda_checkpoint(args, action, pid, msg_buf, buf_size);
}

static int interrupt_restore_thread(int restore_tid, k_rtsigset_t *restore_sigset)
{
	struct cuda_wait wait;
	sigset_t blocked, saved;
	int status = restore_thread_status;
	int ret = -1;

	running_restore_tid = 0;
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blocked, &saved)) {
		pr_perror("Cannot block SIGCHLD while stopping CUDA restore tid %d", restore_tid);
		return -1;
	}
	/* A monitored fault already consumed the stop event. Keep the thread
	 * stopped without delivering that fault or waiting for another event.
	 */
	if (status == -1) {
		/* Since we resumed a thread that CRIU previously already froze we need to
		 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
		 * a compel_interrupt_task()
		 */
		if (ptrace(PTRACE_INTERRUPT, restore_tid, NULL, 0)) {
			pr_perror("Could not interrupt CUDA restore tid %d after checkpoint", restore_tid);
			goto out;
		}
		if (cuda_wait_init(&wait, "stop CUDA restore thread", restore_tid, 0, NULL,
				   CUDA_RESTORE_THREAD_STOP_TIMEOUT))
			goto out;
		wait.ignore_criu_timeout = true;
		if (cuda_wait_child(&wait, restore_tid, __WALL, &status))
			goto out;
	}
	if (!WIFSTOPPED(status)) {
		pr_err("CUDA restore tid %d exited before it could be stopped\n", restore_tid);
		goto out;
	}
	ret = 0;
	if (restore_thread_status == -1 &&
	    (WSTOPSIG(status) != SIGTRAP || (unsigned int)status >> 16 != PTRACE_EVENT_STOP)) {
		pr_err("CUDA restore tid %d stopped unexpectedly with signal %d\n", restore_tid, WSTOPSIG(status));
		ret = -1;
	}
	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD)) {
		pr_perror("Failed to set ptrace options on interrupt for restore tid %d", restore_tid);
		ret = -1;
	}
	if (ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(*restore_sigset), restore_sigset)) {
		pr_perror("Unable to restore original sigmask to restore tid %d", restore_tid);
		ret = -1;
	}
out:
	if (sigprocmask(SIG_SETMASK, &saved, NULL)) {
		pr_perror("Cannot restore signal mask after stopping CUDA restore tid %d", restore_tid);
		ret = -1;
	}
	if (ret)
		backend_failed = true;
	return ret;
}

static int resume_restore_thread(int restore_tid, k_rtsigset_t *save_sigset)
{
	const unsigned long ptrace_options = PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD;
	k_rtsigset_t block;
	bool options_cleared = false;
	bool sigmask_changed = false;

	if (backend_failed) {
		pr_err("Cannot resume CUDA restore tid %d after a helper failure\n", restore_tid);
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
		goto err_restore;
	}
	options_cleared = true;

	if (ptrace(PTRACE_CONT, restore_tid, NULL, 0)) {
		pr_perror("Could not resume cuda restore tid %d", restore_tid);
		goto err_restore;
	}

	running_restore_tid = restore_tid;
	restore_thread_status = -1;
	return 0;

err_restore:
	if (options_cleared && ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, ptrace_options))
		pr_perror("Unable to restore ptrace options for CUDA restore tid %d", restore_tid);
	if (sigmask_changed &&
	    ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(*save_sigset), save_sigset))
		pr_perror("Unable to restore signal mask for CUDA restore tid %d", restore_tid);

	return -1;
}

static int cuda_cli_checkpoint_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	cuda_task_state_t observed_task_state;
	int restore_tid;
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	int int_ret;
	int ret = 0;
	int status;
	k_rtsigset_t save_sigset;
	struct pid_info *task_info;

	tid_result = get_cuda_restore_tid(pid, &restore_tid);

	/* We can possibly hit a race with cuInit() where we are past the point of
	 * locking the process but at lock time cuInit() hadn't completed in which
	 * case cuda-checkpoint will report that we're in an invalid state to
	 * checkpoint
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
	/* We need to resume the checkpoint thread to prepare the mappings for
	 * checkpointing
	 */
	if (resume_restore_thread(restore_tid, &save_sigset)) {
		return -1;
	}

	/* A failed checkpoint may leave the task LOCKED or CHECKPOINTED. Assume
	 * CHECKPOINTED until a failure-state query proves otherwise.
	 */
	task_info->current_task_state = CUDA_TASK_CHECKPOINTED;
	status = cuda_process_checkpoint_action(pid, ACTION_CHECKPOINT, 0, NULL, msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("CHECKPOINT_DEVICES failed with %s\n", msg_buf);
		ret = -1;

		/* The restore thread must be running while cuda-checkpoint asks the
		 * driver for the state reached by the failed action.
		 */
		observed_task_state = get_cuda_state(pid);
		if (observed_task_state != CUDA_TASK_UNKNOWN)
			task_info->current_task_state = observed_task_state;
		else
			pr_err("Unable to determine CUDA state after checkpoint failure for pid %d\n", pid);
	}

	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);
	if (!ret)
		ret = int_ret;

	return ret;
}

static int cuda_cli_pause_devices(int pid)
{
	struct pid_info *info;
	enum cuda_restore_tid_result tid_result;
	int restore_tid;
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	cuda_task_state_t task_state;
	int status;

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

	if (cuda_plugin_add_inventory())
		return -1;

	if (task_state == CUDA_TASK_LOCKED) {
		pr_info("pid %d already in a locked state\n", pid);
		/* Leave this PID in a "locked" state at resume_device() */
		return add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_LOCKED, CUDA_TASK_LOCKED);
	}

	if (task_state == CUDA_TASK_CHECKPOINTED) {
		/* We need to skip this PID in cuda_plugin_checkpoint_devices(),
		 * and leave it in a "checkpointed" state at resume_device(). */
		return add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_CHECKPOINTED);
	}

	/* Track the task before lock: a failed helper may already have locked it. */
	if (add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_RUNNING, CUDA_TASK_UNKNOWN))
		return -1;
	info = find_cuda_pid(pid);
	info->lock_pending = true;
	pr_info("pausing devices on pid %d\n", pid);
	status = cuda_process_checkpoint_action(pid, ACTION_LOCK, opts.timeout * 1000, NULL,
						msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("PAUSE_DEVICES failed with %s\n", msg_buf);
		/* collect_pstree() must cancel its alarm before rollback can wait. */
		return -1;
	}

	info->current_task_state = CUDA_TASK_LOCKED;
	info->lock_pending = false;
	return 0;
}

static int resume_device(int pid, cuda_task_state_t current_task_state,
			 cuda_task_state_t initial_task_state,
			 const struct cuda_device_map *device_map)
{
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	enum cuda_restore_tid_result tid_result;
	cuda_task_state_t observed_task_state;
	int restore_tid;
	int status;
	int ret = 0;
	int int_ret;
	k_rtsigset_t save_sigset;

	if (backend_failed) {
		pr_err("Cannot recover CUDA state for pid %d after a cuda-checkpoint helper failure\n", pid);
		return -1;
	}
	if (initial_task_state == CUDA_TASK_UNKNOWN) {
		pr_info("skip resume for PID %d (unknown state)\n", pid);
		return 0;
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
	if (tid_result == CUDA_RESTORE_TID_ERROR)
		return -1;

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

	/* cuda-checkpoint state queries may wait for the dedicated restore thread,
	 * so refresh the tracked state only after that thread is running.
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
		goto interrupt;
	}
	if (current_task_state == initial_task_state)
		goto interrupt;

	if (current_task_state == CUDA_TASK_CHECKPOINTED) {
		/* If the process was "locked" or "running" before checkpointing it, we need to restore it */
		status = cuda_process_checkpoint_action(pid, ACTION_RESTORE, 0,
							device_map ? device_map->cli_value : NULL,
							msg_buf, sizeof(msg_buf));
		if (status) {
			pr_err("RESUME_DEVICES RESTORE failed with %s\n", msg_buf);
			ret = -1;

			observed_task_state = get_cuda_state(pid);
			if (observed_task_state != CUDA_TASK_UNKNOWN)
				current_task_state = observed_task_state;
			else
				pr_err("Unable to determine CUDA state after restore failure for pid %d\n", pid);
		} else {
			current_task_state = CUDA_TASK_LOCKED;
		}
	}

	if (initial_task_state == CUDA_TASK_RUNNING) {
		if (current_task_state == CUDA_TASK_LOCKED) {
			/* If the process was running before we paused it, unlock it. */
			status = cuda_process_checkpoint_action(pid, ACTION_UNLOCK, 0, NULL,
								msg_buf, sizeof(msg_buf));
			if (status) {
				pr_err("RESUME_DEVICES UNLOCK failed with %s\n", msg_buf);
				ret = -1;

				observed_task_state = get_cuda_state(pid);
				if (observed_task_state != CUDA_TASK_UNKNOWN)
					current_task_state = observed_task_state;
				else
					pr_err("Unable to determine CUDA state after unlock failure for pid %d\n", pid);
			} else {
				current_task_state = CUDA_TASK_RUNNING;
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

static int cuda_cli_resume_devices_late(int pid, const struct cuda_device_map *device_map)
{
	/* RESUME_DEVICES_LATE is used during `criu restore`.
	 * Here, we assume that users expect the target process
	 * to be in a "running" state after restore, even if it was
	 * in a "locked" or "checkpointed" state during `criu dump`.
	 */
	return resume_device(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_RUNNING, device_map);
}

static int cuda_cli_probe(bool device_map_requested)
{
	int ret;

	backend_failed = false;
	dump_rollback = false;
	running_restore_tid = 0;
	restore_thread_status = -1;
	ret = cuda_checkpoint_supports_flag("--action");
	if (ret == -ENOTSUP || ret == -ENOENT) {
		pr_info("%s with --action support is unavailable\n", CUDA_CHECKPOINT);
		return -ENOTSUP;
	}
	if (ret)
		return ret;

	if (device_map_requested) {
		ret = cuda_checkpoint_supports_flag("--device-map");
		if (ret == -ENOTSUP)
			pr_info("%s with --device-map support is unavailable\n", CUDA_CHECKPOINT);
	}

	return ret;
}

static int cuda_cli_init(int stage)
{
	backend_failed = false;
	dump_rollback = false;
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

static int rollback_pending_lock(struct pid_info *info)
{
	char msg_buf[CUDA_CKPT_BUF_SIZE];

	/* PAUSE_DEVICES failed before CRIU seized this task. Its CUDA thread is
	 * still running, so query and unlock without changing its ptrace state.
	 */
	info->current_task_state = get_cuda_state(info->pid);
	if (info->current_task_state == CUDA_TASK_RUNNING) {
		info->lock_pending = false;
		return 0;
	}
	if (info->current_task_state != CUDA_TASK_LOCKED)
		return -1;
	if (cuda_process_checkpoint_action(info->pid, ACTION_UNLOCK, 0, NULL, msg_buf, sizeof(msg_buf))) {
		pr_err("Failed to unlock pid %d after lock failure: %s\n", info->pid, msg_buf);
		return -1;
	}
	info->current_task_state = CUDA_TASK_RUNNING;
	info->lock_pending = false;
	return 0;
}

static int cuda_cli_dump_finish(int ret)
{
	struct pid_info *info;
	int err = 0;

	if (opts.final_state != TASK_ALIVE && !ret)
		return 0;

	/* collect_pstree() cancels the alarm but leaves its expiration latched.
	 * Rollback must ignore that timeout and use cuda_plugin_timeout instead.
	 */
	dump_rollback = true;
	/* Attempt rollback for every task even when an earlier rollback fails. */
	list_for_each_entry(info, &cuda_pids, list) {
		int status;

		if (info->lock_pending)
			status = rollback_pending_lock(info);
		else
			status = resume_device(info->pid, info->current_task_state, info->initial_task_state, NULL);
		if (status) {
			pr_err("Unable to restore CUDA state for pid %d during dump cleanup\n", info->pid);
			err = -1;
		}
	}
	dump_rollback = false;
	return err;
}

static void cuda_cli_fini(int stage, int ret)
{
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		dealloc_pid_buffer(&cuda_pids);
	}
}

const struct cuda_plugin_backend cuda_cli_backend = {
	.name = "cuda-checkpoint CLI",
	.probe = cuda_cli_probe,
	.init = cuda_cli_init,
	.fini = cuda_cli_fini,
	.dump_finish = cuda_cli_dump_finish,
	.pause_devices = cuda_cli_pause_devices,
	.checkpoint_devices = cuda_cli_checkpoint_devices,
	.resume_devices_late = cuda_cli_resume_devices_late,
};
