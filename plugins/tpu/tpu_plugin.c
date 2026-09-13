#include "criu-log.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "proc_parse.h"
#include "seize.h"

#include <common/list.h>
#include <compel/infect.h>

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>

/* tpucheckpoint binary should live in your PATH */
#define TPU_CHECKPOINT "tpucheckpoint"

/* tpucheckpoint --action flags */
#define ACTION_CHECKPOINT "checkpoint"
#define ACTION_RESTORE	  "restore"

/* libtpu advertises its control channel with a thread named
 * "libtpu{XXXXYYYY}" where the 8-character hex suffix encodes the
 * request/response pipe FDs. comm names are at most 15 characters, and
 * "libtpu" + 8 hex characters is exactly 14.
 */
#define TPU_THREAD_PREFIX     "libtpu"
#define TPU_THREAD_PREFIX_LEN 6
#define TPU_THREAD_HEX_LEN    8
#define TPU_THREAD_NAME_LEN   (TPU_THREAD_PREFIX_LEN + TPU_THREAD_HEX_LEN)

/* One control thread per libtpu client is expected today; leave headroom. */
#define TPU_MAX_CONTROL_THREADS 16

#define TPU_CKPT_BUF_SIZE (128)

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "tpu_plugin: "

/* Disable plugin functionality if tpucheckpoint is not in $PATH or no TPU
 * device is present.
 */
static bool plugin_disabled = false;

static bool plugin_added_to_inventory = false;

struct pid_info {
	int pid;
	char checkpointed;
	struct list_head list;
};

/* Tracks the PIDs with libtpu control threads seen during DUMP so their
 * device state can be restored if the user requested the leave-running
 * option or an error occurred.
 */
static LIST_HEAD(tpu_pids);

static void dealloc_pid_buffer(struct list_head *pid_buf)
{
	struct pid_info *info;
	struct pid_info *n;

	list_for_each_entry_safe(info, n, pid_buf, list) {
		list_del(&info->list);
		xfree(info);
	}
}

static int add_pid_to_buf(struct list_head *pid_buf, int pid)
{
	struct pid_info *new = xmalloc(sizeof(*new));

	if (new == NULL) {
		return -1;
	}

	new->pid = pid;
	new->checkpointed = 0;
	list_add_tail(&new->list, pid_buf);

	return 0;
}

static struct pid_info *find_pid_in_buf(struct list_head *pid_buf, int pid)
{
	struct pid_info *info;

	list_for_each_entry(info, pid_buf, list) {
		if (info->pid == pid)
			return info;
	}

	return NULL;
}

/* Find the libtpu control threads of a process by scanning
 * /proc/<pid>/task/<tid>/comm for the "libtpu{XXXXYYYY}" naming pattern.
 *
 * Returns the number of control threads found (0 if the process is not a
 * TPU workload), or -1 on error.
 */
static int find_libtpu_tids(int pid, int *tids, int max_tids)
{
	char path[64];
	DIR *dir;
	struct dirent *ent;
	int n = 0;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (dir == NULL) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	while (n < max_tids && (ent = readdir(dir)) != NULL) {
		char comm_path[sizeof("/proc/2147483647/task//comm") + NAME_MAX];
		char comm[32];
		FILE *f;
		int i, len;

		if (!isdigit(ent->d_name[0]))
			continue;

		snprintf(comm_path, sizeof(comm_path), "/proc/%d/task/%s/comm", pid, ent->d_name);
		f = fopen(comm_path, "r");
		if (f == NULL)
			continue;
		if (fgets(comm, sizeof(comm), f) == NULL) {
			fclose(f);
			continue;
		}
		fclose(f);

		len = strlen(comm);
		if (len > 0 && comm[len - 1] == '\n')
			comm[--len] = '\0';

		if (len != TPU_THREAD_NAME_LEN)
			continue;
		if (strncmp(comm, TPU_THREAD_PREFIX, TPU_THREAD_PREFIX_LEN) != 0)
			continue;
		for (i = TPU_THREAD_PREFIX_LEN; i < TPU_THREAD_NAME_LEN; i++) {
			if (!isxdigit(comm[i]))
				break;
		}
		if (i != TPU_THREAD_NAME_LEN)
			continue;

		tids[n++] = atoi(ent->d_name);
	}

	closedir(dir);
	return n;
}

static int launch_tpu_checkpoint(const char **args, char *buf, int buf_size)
{
#define READ  0
#define WRITE 1
	int fd[2], buf_off;

	if (pipe(fd) != 0) {
		pr_perror("Couldn't create pipes for reading tpucheckpoint output");
		return -1;
	}

	buf[0] = '\0';

	int child_pid = fork();
	if (child_pid == -1) {
		pr_perror("Failed to fork to exec tpucheckpoint");
		close(fd[READ]);
		close(fd[WRITE]);
		return -1;
	}

	if (child_pid == 0) { // child
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
			pr_perror("Unable to read output of tpucheckpoint");
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
			pr_perror("Unable to read output of tpucheckpoint");
			goto err;
		}
		if (bytes_read == 0)
			break;
	}
	close(fd[READ]);

	int status, exit_code = -1;
	if (waitpid(child_pid, &status, 0) == -1) {
		pr_perror("Unable to wait for the tpucheckpoint process %d", child_pid);
		goto err;
	}
	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		pr_err("tpucheckpoint unexpectedly signaled with %d: %s\n", sig, strsignal(sig));
	} else if (WIFEXITED(status)) {
		exit_code = WEXITSTATUS(status);
	} else {
		pr_err("tpucheckpoint exited improperly: %u\n", status);
	}

	if (exit_code != EXIT_SUCCESS)
		pr_debug("tpucheckpoint output ===>\n%s\n"
			 "<=== tpucheckpoint output\n",
			 buf);

	return exit_code;
err:
	kill(child_pid, SIGKILL);
	waitpid(child_pid, NULL, 0);
	return -1;
}

/**
 * Checks if a given flag is supported by the tpucheckpoint utility
 *
 * Returns:
 *  1 if the flag is supported,
 *  0 if the flag is not supported,
 *  -1 if there was an error launching the tpucheckpoint utility.
 */
static int tpu_checkpoint_supports_flag(const char *flag)
{
	char msg_buf[2048];
	const char *args[] = { TPU_CHECKPOINT, "--help", NULL };

	if (launch_tpu_checkpoint(args, msg_buf, sizeof(msg_buf)) != 0)
		return -1;

	if (strstr(msg_buf, flag) == NULL)
		return 0;

	return 1;
}

static int tpu_process_checkpoint_action(int pid, const char *action, unsigned int timeout, char *msg_buf,
					 int buf_size)
{
	char pid_buf[16];
	char timeout_buf[16];

	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

	const char *args[] = { TPU_CHECKPOINT, "--action", action, "--pid", pid_buf, NULL /* --timeout */,
			       NULL /* timeout_val */, NULL };
	if (timeout > 0) {
		snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout);
		args[5] = "--timeout";
		args[6] = timeout_buf;
	}

	return launch_tpu_checkpoint(args, msg_buf, buf_size);
}

static int interrupt_control_thread(int tid, k_rtsigset_t *sigset)
{
	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, tid, NULL, 0)) {
		pr_perror("Could not interrupt libtpu control tid %d, process may be in strange state", tid);
		return -1;
	}

	struct proc_status_creds creds;
	if (compel_wait_task(tid, -1, parse_pid_status, NULL, &creds.s, NULL) != COMPEL_TASK_ALIVE) {
		pr_err("compel_wait_task failed after interrupt\n");
		return -1;
	}

	if (ptrace(PTRACE_SETOPTIONS, tid, NULL, PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD)) {
		pr_perror("Failed to set ptrace options on interrupt for libtpu control tid %d", tid);
		return -1;
	}

	if (ptrace(PTRACE_SETSIGMASK, tid, sizeof(*sigset), sigset)) {
		pr_perror("Unable to restore original sigmask to libtpu control tid %d", tid);
		return -1;
	}

	return 0;
}

static int resume_control_thread(int tid, k_rtsigset_t *save_sigset)
{
	k_rtsigset_t block;

	if (ptrace(PTRACE_GETSIGMASK, tid, sizeof(*save_sigset), save_sigset)) {
		pr_perror("Failed to get current sigmask for libtpu control tid %d", tid);
		return -1;
	}

	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);

	if (ptrace(PTRACE_SETSIGMASK, tid, sizeof(block), &block)) {
		pr_perror("Failed to block signals on libtpu control tid %d", tid);
		return -1;
	}

	// Clear out PTRACE_O_SUSPEND_SECCOMP when we resume the control thread
	if (ptrace(PTRACE_SETOPTIONS, tid, NULL, 0)) {
		pr_perror("Could not clear ptrace options on libtpu control tid %d", tid);
		return -1;
	}

	if (ptrace(PTRACE_CONT, tid, NULL, 0)) {
		pr_perror("Could not resume libtpu control tid %d", tid);
		return -1;
	}

	return 0;
}

/* Run a tpucheckpoint action against a frozen process. The libtpu control
 * threads must be running to service the request, so resume them for the
 * duration of the action and interrupt them again afterwards.
 */
static int tpu_run_action_frozen(int pid, const char *action, unsigned int timeout)
{
	char msg_buf[TPU_CKPT_BUF_SIZE];
	int tids[TPU_MAX_CONTROL_THREADS];
	k_rtsigset_t sigsets[TPU_MAX_CONTROL_THREADS];
	int n_tids, i, resumed;
	int status = -1;
	int int_ret = 0;

	n_tids = find_libtpu_tids(pid, tids, TPU_MAX_CONTROL_THREADS);
	if (n_tids < 0)
		return -1;
	if (n_tids == 0) {
		pr_info("No libtpu control threads on pid %d\n", pid);
		return 0;
	}

	for (resumed = 0; resumed < n_tids; resumed++) {
		if (resume_control_thread(tids[resumed], &sigsets[resumed]))
			goto interrupt;
	}

	status = tpu_process_checkpoint_action(pid, action, timeout, msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("--action %s failed on pid %d with %s\n", action, pid, msg_buf);
	}

interrupt:
	for (i = 0; i < resumed; i++) {
		if (interrupt_control_thread(tids[i], &sigsets[i]))
			int_ret = -1;
	}

	return status != 0 ? -1 : int_ret;
}

int tpu_plugin_pause_devices(int pid)
{
	int tids[TPU_MAX_CONTROL_THREADS];
	int n_tids;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	n_tids = find_libtpu_tids(pid, tids, TPU_MAX_CONTROL_THREADS);
	if (n_tids < 0)
		return -1;
	if (n_tids == 0) {
		pr_info("no need to pause devices on pid %d\n", pid);
		return 0;
	}

	/* This hook does not quiesce the device: it does not gate new TPU
	 * work or drain in-flight programs. The caller must guarantee the
	 * workload is TPU-idle before dumping. The tpu_control protocol
	 * defines a lock action, and this hook is the natural place to
	 * invoke it, mirroring the CUDA plugin.
	 */
	pr_warn("TPU quiesce is not performed; pid %d must be TPU-idle before dump\n", pid);

	if (!plugin_added_to_inventory) {
		if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
			pr_err("Failed to add TPU plugin to inventory image\n");
			return -1;
		}
		plugin_added_to_inventory = true;
	}

	if (add_pid_to_buf(&tpu_pids, pid)) {
		pr_err("unable to track pid %d\n", pid);
		return -1;
	}

	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, tpu_plugin_pause_devices)

int tpu_plugin_checkpoint_devices(int pid)
{
	struct pid_info *task_info;
	int ret;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	task_info = find_pid_in_buf(&tpu_pids, pid);
	if (task_info == NULL) {
		/* The process had no libtpu control threads at PAUSE_DEVICES
		 * time (or gained them since; libtpu initialization after the
		 * pause is not checkpointable in this pass).
		 */
		pr_info("No need to checkpoint devices on pid %d\n", pid);
		return 0;
	}

	pr_info("Checkpointing TPU state on pid %d\n", pid);

	ret = tpu_run_action_frozen(pid, ACTION_CHECKPOINT, opts.timeout);
	if (ret == 0)
		task_info->checkpointed = 1;

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, tpu_plugin_checkpoint_devices);

static int resume_device(int pid, int checkpointed)
{
	if (!checkpointed)
		return 0;

	pr_info("resuming devices on pid %d\n", pid);

	/* The resuming process has to stay frozen during this time otherwise
	 * accessing TPU state before the HBM contents are restored will fault.
	 */
	return tpu_run_action_frozen(pid, ACTION_RESTORE, opts.timeout);
}

int tpu_plugin_resume_devices_late(int pid)
{
	if (plugin_disabled) {
		return -ENOTSUP;
	}

	return resume_device(pid, 1);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, tpu_plugin_resume_devices_late)

/**
 * Check if a TPU device is available on the system.
 *
 * TPUs are PCI devices with the Google vendor ID (0x1ae0).
 */
static bool is_tpu_device_available(void)
{
	const char *pci_path = "/sys/bus/pci/devices";
	DIR *dir;
	struct dirent *ent;
	bool found = false;

	dir = opendir(pci_path);
	if (dir == NULL)
		return false;

	while (!found && (ent = readdir(dir)) != NULL) {
		char vendor_path[512];
		char vendor[16];
		FILE *f;

		if (ent->d_name[0] == '.')
			continue;

		snprintf(vendor_path, sizeof(vendor_path), "%s/%s/vendor", pci_path, ent->d_name);
		f = fopen(vendor_path, "r");
		if (f == NULL)
			continue;
		if (fgets(vendor, sizeof(vendor), f) != NULL && strncmp(vendor, "0x1ae0", 6) == 0)
			found = true;
		fclose(f);
	}

	closedir(dir);
	return found;
}

int tpu_plugin_init(int stage)
{
	int ret;

	/* Disable TPU checkpointing with pre-dump */
	if (stage == CR_PLUGIN_STAGE__PRE_DUMP) {
		plugin_disabled = true;
		return 0;
	}

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (!check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name, strlen(CR_PLUGIN_DESC.name))) {
			plugin_disabled = true;
			return 0;
		}
	}

	if (!is_tpu_device_available()) {
		pr_info("No TPU device found; TPU plugin is disabled\n");
		plugin_disabled = true;
		return 0;
	}

	ret = tpu_checkpoint_supports_flag("--action");
	if (ret == -1) {
		pr_warn("check that %s is present in $PATH\n", TPU_CHECKPOINT);
		plugin_disabled = true;
		return 0;
	}

	if (ret == 0) {
		pr_warn("tpucheckpoint --action flag not supported. Disabling TPU plugin\n");
		plugin_disabled = true;
		return 0;
	}

	pr_info("initialized: %s stage %d\n", CR_PLUGIN_DESC.name, stage);

	/* In the DUMP stage track all the PIDs with libtpu control threads to
	 * restore their device state when we're done if the user requested the
	 * leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&tpu_pids);
	}

	set_compel_interrupt_only_mode();

	return 0;
}

void tpu_plugin_fini(int stage, int ret)
{
	if (plugin_disabled) {
		return;
	}

	pr_info("finished %s stage %d err %d\n", CR_PLUGIN_DESC.name, stage, ret);

	/* Restore the device state of all checkpointed PIDs at the end of the
	 * DUMP stage in case the user provides the -R (leave-running) flag or
	 * an error occurred
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && (opts.final_state == TASK_ALIVE || ret != 0)) {
		struct pid_info *info;
		list_for_each_entry(info, &tpu_pids, list) {
			resume_device(info->pid, info->checkpointed);
		}
	}
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		dealloc_pid_buffer(&tpu_pids);
	}
}
CR_PLUGIN_REGISTER("tpu_plugin", tpu_plugin_init, tpu_plugin_fini)
