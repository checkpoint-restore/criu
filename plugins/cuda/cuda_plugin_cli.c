#include "criu-log.h"
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
	struct list_head list;
};

/* Used to track which PID's we've paused CUDA operations on so far so we can
 * release them after we're done with the DUMP
 */
static LIST_HEAD(cuda_pids);

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

static int launch_cuda_checkpoint(const char **args, char *buf, int buf_size)
{
#define READ  0
#define WRITE 1
	int fd[2], buf_off;

	if (pipe(fd) != 0) {
		pr_perror("Couldn't create pipes for reading cuda-checkpoint output");
		return -1;
	}

	buf[0] = '\0';

	int child_pid = fork();
	if (child_pid == -1) {
		pr_perror("Failed to fork to exec cuda-checkpoint");
		close(fd[READ]);
		close(fd[WRITE]);
		return -1;
	}

	if (child_pid == 0) { /* child */
		if (dup2(fd[WRITE], STDOUT_FILENO) == -1) {
			pr_perror("unable to clone fd %d->%d", fd[WRITE], STDOUT_FILENO);
			_exit(EXIT_FAILURE);
		}
		if (dup2(fd[WRITE], STDERR_FILENO) == -1) {
			pr_perror("unable to clone fd %d->%d", fd[WRITE], STDERR_FILENO);
			_exit(EXIT_FAILURE);
		}
		close(fd[READ]);

		close_fds(STDERR_FILENO + 1);

		execvp(args[0], (char **)args);

		/* We can't use pr_error() as log file fd is closed. */
		fprintf(stderr, "execvp(\"%s\") failed: %s\n", args[0], strerror(errno));

		_exit(EXIT_FAILURE);
	}

	close(fd[WRITE]);
	buf_off = 0;
	/* Reserve one byte for the null character. */
	buf_size--;
	while (buf_off < buf_size) {
		int bytes_read;
		bytes_read = read(fd[READ], buf + buf_off, buf_size - buf_off);
		if (bytes_read == -1) {
			pr_perror("Unable to read output of cuda-checkpoint");
			goto err;
		}
		if (bytes_read == 0)
			break;
		buf_off += bytes_read;
	}
	buf[buf_off] = '\0';

	/* Clear out any of the remaining output in the pipe in case the buffer wasn't large enough */
	while (true) {
		char scratch[1024];
		int bytes_read;
		bytes_read = read(fd[READ], scratch, sizeof(scratch));
		if (bytes_read == -1) {
			pr_perror("Unable to read output of cuda-checkpoint");
			goto err;
		}
		if (bytes_read == 0)
			break;
	}
	close(fd[READ]);

	int status, exit_code = -1;
	if (waitpid(child_pid, &status, 0) == -1) {
		pr_perror("Unable to wait for the cuda-checkpoint process %d", child_pid);
		goto err;
	}
	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		pr_err("cuda-checkpoint unexpectedly signaled with %d: %s\n", sig, strsignal(sig));
	} else if (WIFEXITED(status)) {
		exit_code = WEXITSTATUS(status);
	} else {
		pr_err("cuda-checkpoint exited improperly: %u\n", status);
	}

	if (exit_code != EXIT_SUCCESS)
		pr_debug("cuda-checkpoint output ===>\n%s\n"
			 "<=== cuda-checkpoint output\n",
			 buf);

	if (exit_code != EXIT_SUCCESS && !strncmp(buf, "execvp(\"", 8))
		return -ENOENT;

	return exit_code;
err:
	kill(child_pid, SIGKILL);
	waitpid(child_pid, NULL, 0);
	return -1;
}

/**
 * Checks if a given flag is supported by the cuda-checkpoint utility
 *
 * Returns 0 if the flag is supported, -ENOTSUP if cuda-checkpoint is absent or
 * the flag is unavailable, and another negative error for a broken probe.
 */
static int cuda_checkpoint_supports_flag(const char *flag)
{
	char msg_buf[2048];
	const char *args[] = { CUDA_CHECKPOINT, "-h", NULL };
	int ret;

	ret = launch_cuda_checkpoint(args, msg_buf, sizeof(msg_buf));
	if (ret == -ENOENT)
		return -ENOTSUP;
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
	char *end;
	long value;
	int ret;

	snprintf(pid_buf, sizeof(pid_buf), "%d", root_pid);

	const char *args[] = { CUDA_CHECKPOINT, "--get-restore-tid", "--pid", pid_buf, NULL };
	ret = launch_cuda_checkpoint(args, pid_out, sizeof(pid_out));
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

	if (launch_cuda_checkpoint(args, state_str, sizeof(state_str))) {
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

	return launch_cuda_checkpoint(args, msg_buf, buf_size);
}

static int interrupt_restore_thread(int restore_tid, k_rtsigset_t *restore_sigset)
{
	int ret = 0;

	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, restore_tid, NULL, 0)) {
		pr_perror("Could not interrupt cuda restore tid %d after checkpoint, process may be in strange state",
			  restore_tid);
		return -1;
	}

	struct proc_status_creds creds;
	if (compel_wait_task(restore_tid, -1, parse_pid_status, NULL, &creds.s, NULL) != COMPEL_TASK_ALIVE) {
		pr_err("compel_wait_task failed after interrupt\n");
		return -1;
	}

	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD)) {
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
	enum cuda_restore_tid_result tid_result;
	int restore_tid;
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	cuda_task_state_t task_state;

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

	pr_info("pausing devices on pid %d\n", pid);
	int status = cuda_process_checkpoint_action(pid, ACTION_LOCK, opts.timeout * 1000, NULL,
						    msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("PAUSE_DEVICES failed with %s\n", msg_buf);
		task_state = get_cuda_state(pid);
		if (task_state == CUDA_TASK_LOCKED || alarm_timeouted())
			goto unlock;
		return -1;
	}

	if (add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_RUNNING, CUDA_TASK_LOCKED)) {
		pr_err("unable to track paused pid %d\n", pid);
		goto unlock;
	}

	return 0;
unlock:
	status = cuda_process_checkpoint_action(pid, ACTION_UNLOCK, 0, NULL, msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("Failed to unlock process status %s, pid %d may hang\n", msg_buf, pid);
	}
	return -1;
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

	ret = cuda_checkpoint_supports_flag("--action");
	if (ret == -ENOTSUP) {
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
	/* In the DUMP stage track all the PID's we've paused CUDA operations on to
	 * release them when we're done if the user requested the leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&cuda_pids);
	}

	return 0;
}

static void cuda_cli_fini(int stage, int ret)
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
		dealloc_pid_buffer(&cuda_pids);
	}
}

const struct cuda_plugin_backend cuda_cli_backend = {
	.name = "cuda-checkpoint CLI",
	.probe = cuda_cli_probe,
	.init = cuda_cli_init,
	.fini = cuda_cli_fini,
	.pause_devices = cuda_cli_pause_devices,
	.checkpoint_devices = cuda_cli_checkpoint_devices,
	.resume_devices_late = cuda_cli_resume_devices_late,
};
