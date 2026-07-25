#include "criu-log.h"
#include "cuda_checkpoint.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "proc_parse.h"
#include "seize.h"
#include "fault-injection.h"
#include "cuda_device_map.h"

#include <common/list.h>
#include <compel/infect.h>

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>

static void *cuda_handle;
static bool cuda_driver_initialized;

struct cuda_driver_api {
	CUresult (*init)(unsigned int flags);
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

/* Disable plugin functionality if libcuda is unavailable or the driver does
 * not expose the CUDA checkpoint Driver API.
 */
static bool plugin_disabled;

static bool plugin_added_to_inventory;
static CUcheckpointGpuPair *cuda_restore_gpu_pairs;
static unsigned int cuda_restore_gpu_pairs_count;

struct pid_info {
	int pid;
	cuda_task_state_t current_task_state;
	cuda_task_state_t initial_task_state;
	struct list_head list;
};

struct cuda_thread_info {
	pid_t tid;
	k_rtsigset_t sigset;
	bool sigset_blocked;
	bool options_cleared;
	bool resumed;
	bool interrupt_sent;
	bool stopped;
};

struct cuda_thread_group {
	struct cuda_thread_info *threads;
	size_t nr;
	size_t capacity;
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

#define LOAD_CUDA_SYMBOL(member, symbol) \
	do { \
		cuda_api.member = (typeof(cuda_api.member))cuda_get_symbol(symbol); \
	} while (0)

static int cuda_api_init(void)
{
	/* RTLD_NODELETE keeps libcuda mapped after dlclose(); once cuInit()
	 * has run, the driver may have internal threads and state that do not
	 * survive unmapping the library.
	 */
	cuda_handle = dlopen("libcuda.so.1", RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE);
	if (!cuda_handle) {
		pr_info("Cannot load libcuda.so.1: %s\n", dlerror());
		return -1;
	}

	LOAD_CUDA_SYMBOL(get_error_name, "cuGetErrorName");
	LOAD_CUDA_SYMBOL(get_error_string, "cuGetErrorString");
	LOAD_CUDA_SYMBOL(init, "cuInit");
	LOAD_CUDA_SYMBOL(lock, "cuCheckpointProcessLock");
	LOAD_CUDA_SYMBOL(checkpoint, "cuCheckpointProcessCheckpoint");
	LOAD_CUDA_SYMBOL(restore, "cuCheckpointProcessRestore");
	LOAD_CUDA_SYMBOL(unlock, "cuCheckpointProcessUnlock");
	LOAD_CUDA_SYMBOL(get_state, "cuCheckpointProcessGetState");
	LOAD_CUDA_SYMBOL(get_restore_tid, "cuCheckpointProcessGetRestoreThreadId");

	if (!cuda_api.init || !cuda_api.lock || !cuda_api.checkpoint || !cuda_api.restore ||
	    !cuda_api.unlock || !cuda_api.get_state || !cuda_api.get_restore_tid) {
		pr_warn("CUDA checkpoint Driver API not available in libcuda.so.1\n");
		cuda_api_fini();
		return -1;
	}

	pr_info("CUDA checkpoint Driver API loaded via libcuda.so.1\n");
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
		if (res == CUDA_ERROR_INVALID_VALUE) {
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
		return -1;
	}

	if (ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(*restore_sigset), restore_sigset)) {
		pr_perror("Unable to restore original sigmask to restore tid %d", restore_tid);
		return -1;
	}

	return 0;
}

static int resume_restore_thread(int restore_tid, k_rtsigset_t *save_sigset)
{
	k_rtsigset_t block;

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

	/* Clear PTRACE_O_SUSPEND_SECCOMP when resuming the restore thread. */
	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, 0)) {
		pr_perror("Could not clear ptrace options on restore tid %d", restore_tid);
		return -1;
	}

	if (ptrace(PTRACE_CONT, restore_tid, NULL, 0)) {
		pr_perror("Could not resume cuda restore tid %d", restore_tid);
		return -1;
	}

	return 0;
}

static void free_cuda_thread_group(struct cuda_thread_group *group)
{
	xfree(group->threads);
	group->threads = NULL;
	group->nr = 0;
	group->capacity = 0;
}

static int add_cuda_thread(pid_t pid, struct cuda_thread_group *group, pid_t tid)
{
	size_t capacity;
	size_t alloc_size;

	if (group->nr == group->capacity) {
		/* Grow the array geometrically, starting with one entry. */
		if (__builtin_mul_overflow(group->capacity, (size_t)2, &capacity) ||
		    __builtin_add_overflow(capacity, (size_t)1, &capacity)) {
			pr_err("Too many threads in CUDA pid %d\n", pid);
			return -1;
		}

		if (__builtin_mul_overflow(capacity, sizeof(*group->threads), &alloc_size)) {
			pr_err("CUDA thread array size overflows for pid %d\n", pid);
			return -1;
		}

		if (xrealloc_safe(&group->threads, alloc_size)) {
			pr_err("Unable to allocate CUDA thread information for pid %d\n", pid);
			return -1;
		}

		group->capacity = capacity;
	}

	group->threads[group->nr++] = (struct cuda_thread_info) {
		.tid = tid,
		.stopped = true,
	};

	return 0;
}

static int collect_cuda_thread_group(pid_t pid, struct cuda_thread_group *group)
{
	char task_path[64];
	struct dirent *de;
	int ret = -1;
	DIR *dir;
	int len;

	len = snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
	if (len < 0 || (size_t)len >= sizeof(task_path)) {
		pr_err("Unable to build CUDA task path for pid %d\n", pid);
		return -1;
	}

	dir = opendir(task_path);
	if (!dir) {
		pr_perror("Unable to open %s", task_path);
		return -1;
	}

	for (;;) {
		char *end;
		long tid;

		/*
		 * readdir() returns NULL both at end-of-directory and on error.
		 * Clear errno first so the two cases can be distinguished.
		 */
		errno = 0;
		de = readdir(dir);
		if (!de) {
			if (errno)
				pr_perror("Unable to read %s", task_path);
			else
				ret = 0;
			break;
		}

		errno = 0;
		tid = strtol(de->d_name, &end, 10);
		if (errno || end == de->d_name || *end != '\0' || tid <= 0 || tid > INT_MAX)
			continue;

		if (add_cuda_thread(pid, group, tid))
			break;
	}

	if (closedir(dir)) {
		pr_perror("Unable to close %s", task_path);
		ret = -1;
	}

	if (ret || group->nr == 0) {
		if (!ret)
			pr_err("No threads found for CUDA pid %d\n", pid);
		free_cuda_thread_group(group);
		return -1;
	}

	return 0;
}

static int restore_cuda_thread_context(struct cuda_thread_info *thread)
{
	int ret = 0;

	if (!thread->stopped)
		return -1;

	if (thread->options_cleared) {
		if (ptrace(PTRACE_SETOPTIONS, thread->tid, NULL,
			   PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD)) {
			pr_perror("Unable to restore ptrace options for CUDA tid %d", thread->tid);
			ret = -1;
		} else {
			thread->options_cleared = false;
		}
	}

	if (thread->sigset_blocked) {
		if (ptrace(PTRACE_SETSIGMASK, thread->tid, sizeof(thread->sigset), &thread->sigset)) {
			pr_perror("Unable to restore signal mask for CUDA tid %d", thread->tid);
			ret = -1;
		} else {
			thread->sigset_blocked = false;
		}
	}

	return ret;
}

static int interrupt_cuda_thread_group(struct cuda_thread_group *group)
{
	int ret = 0;
	size_t i;

	/* Interrupt every running thread before waiting for any one of them. */
	for (i = 0; i < group->nr; i++) {
		struct cuda_thread_info *thread;

		thread = &group->threads[i];

		if (!thread->resumed)
			continue;
		if (ptrace(PTRACE_INTERRUPT, thread->tid, NULL, 0)) {
			pr_perror("Unable to interrupt CUDA tid %d", thread->tid);
			ret = -1;
			continue;
		}
		thread->interrupt_sent = true;
	}

	for (i = 0; i < group->nr; i++) {
		struct cuda_thread_info *thread;
		struct proc_status_creds creds;

		thread = &group->threads[i];

		if (!thread->interrupt_sent)
			continue;
		if (compel_wait_task(thread->tid, -1, parse_pid_status, NULL,
				     &creds.s, NULL) != COMPEL_TASK_ALIVE) {
			pr_err("Unable to wait for CUDA tid %d after interrupt\n", thread->tid);
			ret = -1;
			continue;
		}

		thread->interrupt_sent = false;
		thread->resumed = false;
		thread->stopped = true;
	}

	for (i = 0; i < group->nr; i++) {
		if (restore_cuda_thread_context(&group->threads[i]))
			ret = -1;
	}

	return ret;
}

static int resume_cuda_thread_group(pid_t pid, pid_t restore_tid, struct cuda_thread_group *group)
{
	bool restore_tid_found = false;
	k_rtsigset_t block;
	size_t i;

	if (collect_cuda_thread_group(pid, group))
		return -1;

	/* Resume the dedicated restore thread last, after potential lock holders. */
	for (i = 0; i < group->nr; i++) {
		if (group->threads[i].tid != restore_tid)
			continue;
		if (i != group->nr - 1) {
			struct cuda_thread_info tmp = group->threads[i];

			group->threads[i] = group->threads[group->nr - 1];
			group->threads[group->nr - 1] = tmp;
		}
		restore_tid_found = true;
		break;
	}
	if (!restore_tid_found) {
		pr_err("CUDA restore tid %d is not part of pid %d\n", restore_tid, pid);
		goto err;
	}

	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);

	/* Prepare every thread before allowing any of them to execute. Block signal
	 * delivery during this temporary resume, just as resume_restore_thread()
	 * does for the dedicated restore thread.
	 */
	for (i = 0; i < group->nr; i++) {
		struct cuda_thread_info *thread;

		thread = &group->threads[i];

		if (ptrace(PTRACE_GETSIGMASK, thread->tid, sizeof(thread->sigset), &thread->sigset)) {
			pr_perror("Unable to read signal mask for CUDA tid %d", thread->tid);
			goto err;
		}
		if (ptrace(PTRACE_SETSIGMASK, thread->tid, sizeof(block), &block)) {
			pr_perror("Unable to block signals for CUDA tid %d", thread->tid);
			goto err;
		}
		thread->sigset_blocked = true;

		if (ptrace(PTRACE_SETOPTIONS, thread->tid, NULL, 0)) {
			pr_perror("Unable to clear ptrace options for CUDA tid %d", thread->tid);
			goto err;
		}
		thread->options_cleared = true;
	}

	for (i = 0; i < group->nr; i++) {
		struct cuda_thread_info *thread = &group->threads[i];

		if (ptrace(PTRACE_CONT, thread->tid, NULL, 0)) {
			pr_perror("Unable to resume CUDA tid %d", thread->tid);
			goto err;
		}
		thread->resumed = true;
		thread->stopped = false;
	}

	pr_debug("Resumed %zu threads for CUDA pid %d\n", group->nr, pid);
	return 0;

err:
	if (interrupt_cuda_thread_group(group))
		pr_err("Unable to restore CUDA thread group for pid %d after resume failure\n", pid);
	free_cuda_thread_group(group);
	return -1;
}

static int validate_cuda_thread_group(pid_t pid, const struct cuda_thread_group *expected)
{
	struct cuda_thread_group current = {};
	size_t i, j;
	int ret = -1;

	if (collect_cuda_thread_group(pid, &current))
		return -1;
	if (current.nr != expected->nr) {
		pr_err("CUDA pid %d changed thread count during checkpoint: %zu -> %zu\n", pid, expected->nr,
		       current.nr);
		goto out;
	}

	for (i = 0; i < expected->nr; i++) {
		for (j = 0; j < current.nr; j++) {
			if (expected->threads[i].tid == current.threads[j].tid)
				break;
		}
		if (j == current.nr) {
			pr_err("CUDA tid %d disappeared during checkpoint of pid %d\n", expected->threads[i].tid, pid);
			goto out;
		}
	}

	ret = 0;
out:
	free_cuda_thread_group(&current);
	return ret;
}

int cuda_plugin_checkpoint_devices(int pid)
{
	CUcheckpointCheckpointArgs args = { 0 };
	enum cuda_restore_tid_result tid_result;
	struct cuda_thread_group threads = {};
	struct pid_info *task_info;
	CUresult res;
	int restore_tid;
	int ret = 0;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

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

	/* The CUDA driver may need a target thread that CRIU stopped while it held
	 * an internal driver lock. Resume the whole thread group for the checkpoint
	 * operation, then put every thread back into its ptrace stop below.
	 */
	if (resume_cuda_thread_group(pid, restore_tid, &threads))
		return -1;

	res = cuda_api.checkpoint(pid, &args);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuCheckpointProcessCheckpoint", pid, res);
		ret = -1;
	}

	/* A failed checkpoint is not guaranteed to leave the process LOCKED. Query
	 * the actual state so dump finalization can restore a CHECKPOINTED process
	 * or unlock a LOCKED one instead of guessing from the API return code. The
	 * restore thread must still be running while the driver answers this query.
	 */
	task_info->current_task_state = get_cuda_state(pid);
	if (res == CUDA_SUCCESS && task_info->current_task_state != CUDA_TASK_CHECKPOINTED) {
		pr_err("CUDA checkpoint succeeded for pid %d but process state is %d\n", pid,
		       task_info->current_task_state);
		ret = -1;
	}

	if (interrupt_cuda_thread_group(&threads))
		ret = -1;
	if (validate_cuda_thread_group(pid, &threads))
		ret = -1;
	free_cuda_thread_group(&threads);

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, cuda_plugin_checkpoint_devices);

int cuda_plugin_pause_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	CUcheckpointLockArgs args = { 0 };
	cuda_task_state_t task_state;
	int restore_tid;
	CUresult res;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

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

	if (!plugin_added_to_inventory) {
		if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
			pr_err("Failed to add CUDA plugin to inventory image\n");
			return -1;
		}
		plugin_added_to_inventory = true;
	}

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
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, cuda_plugin_pause_devices)

int cuda_plugin_dump_devices_late(int id)
{
	(void)id;

	if (plugin_disabled || !plugin_added_to_inventory)
		return -ENOTSUP;

	return cuda_gpu_inventory_dump();
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_DEVICES_LATE, cuda_plugin_dump_devices_late)

static int resume_device(int pid, cuda_task_state_t current_task_state,
			 cuda_task_state_t initial_task_state)
{
	cuda_task_state_t observed_task_state;
	enum cuda_restore_tid_result tid_result;
	bool restore_failed = false;
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
	else
		pr_warn("Unable to query CUDA state for pid %d; using tracked state %d\n",
			pid, current_task_state);
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

		if (cuda_driver_init()) {
			ret = -1;
			goto interrupt;
		}
		args.gpuPairs = cuda_restore_gpu_pairs;
		args.gpuPairsCount = cuda_restore_gpu_pairs_count;

		res = cuda_api.restore(pid, &args);
		if (res != CUDA_SUCCESS) {
			cuda_log_error("cuCheckpointProcessRestore", pid, res);
			restore_failed = true;
			ret = -1;

			/* If checkpoint failed before transitioning the process, the
			 * conservative CHECKPOINTED fallback above reaches this path while
			 * the target is actually LOCKED. Detect that and continue with the
			 * required unlock.
			 */
			observed_task_state = get_cuda_state(pid);
			if (observed_task_state == CUDA_TASK_LOCKED) {
				current_task_state = CUDA_TASK_LOCKED;
				restore_failed = false;
				ret = 0;
			} else if (observed_task_state != CUDA_TASK_UNKNOWN) {
				current_task_state = observed_task_state;
			}
		} else {
			current_task_state = get_cuda_state(pid);
			if (current_task_state != CUDA_TASK_LOCKED) {
				pr_err("CUDA restore succeeded for pid %d but state is %d\n", pid,
				       current_task_state);
				ret = -1;
				goto interrupt;
			}
		}
	}

	if (initial_task_state == CUDA_TASK_RUNNING) {
		if (current_task_state == CUDA_TASK_RUNNING) {
			/* The driver reports the desired state despite the restore error.
			 * The process is already running, so no further restore is needed.
			 */
			if (restore_failed)
				ret = 0;
		} else {
			/* If the process was running before we paused it, unlock it. */
			if (unlock_cuda_process(pid)) {
				ret = -1;
			} else {
				current_task_state = get_cuda_state(pid);
				if (current_task_state != CUDA_TASK_RUNNING) {
					pr_err("CUDA unlock succeeded for pid %d but state is %d\n", pid,
					       current_task_state);
					ret = -1;
				} else if (restore_failed) {
					/* The process is running after unlock, so the restore error did
					 * not prevent it from reaching the requested state.
					 */
					ret = 0;
				}
			}
		}
	} else if (current_task_state != CUDA_TASK_LOCKED) {
		pr_err("Unable to return pid %d to locked state from CUDA state %d\n", pid, current_task_state);
		ret = -1;
	}

interrupt:
	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);

	return ret != 0 ? ret : int_ret;
}

int cuda_plugin_resume_devices_late(int pid)
{
	if (plugin_disabled) {
		return -ENOTSUP;
	}

	/* RESUME_DEVICES_LATE is used during `criu restore`.
	 * Here, we assume that users expect the target process
	 * to be in a "running" state after restore, even if it was
	 * in a "locked" or "checkpointed" state during `criu dump`.
	 */
	return resume_device(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_RUNNING);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cuda_plugin_resume_devices_late)

int cuda_plugin_restore_init(void)
{
	int ret;

	if (plugin_disabled)
		return -ENOTSUP;

	ret = cuda_gpu_inventory_restore_init();
	if (ret)
		return ret;

	return cuda_get_device_map(&cuda_restore_gpu_pairs, &cuda_restore_gpu_pairs_count);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_INIT, cuda_plugin_restore_init)

/**
 * Check if a CUDA device is available on the system
 */
static bool is_cuda_device_available(void)
{
	const char *gpu_path = "/proc/driver/nvidia/gpus/";
	struct stat sb;

	if (stat(gpu_path, &sb) != 0)
		return false;

	return S_ISDIR(sb.st_mode);
}

int cuda_plugin_init(int stage)
{
	cuda_restore_gpu_pairs = NULL;
	cuda_restore_gpu_pairs_count = 0;

	/* Disable CUDA checkpointing with pre-dump */
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

	if (!fault_injected(FI_PLUGIN_CUDA_FORCE_ENABLE) && !is_cuda_device_available()) {
		if (stage == CR_PLUGIN_STAGE__RESTORE) {
			pr_err("No GPU device found but the checkpoint requires the CUDA plugin\n");
			return -1;
		}
		pr_info("No GPU device found; CUDA plugin is disabled\n");
		plugin_disabled = true;
		return 0;
	}

	if (cuda_api_init()) {
		if (stage == CR_PLUGIN_STAGE__RESTORE) {
			pr_err("The checkpoint requires the CUDA checkpoint Driver API from an r570 or newer driver\n");
			return -1;
		}
		pr_warn("CUDA checkpoint Driver API unavailable; an r570 or higher "
			"NVIDIA driver is required. Disabling CUDA plugin\n");
		plugin_disabled = true;
		return 0;
	}

	pr_info("initialized: %s stage %d\n", CR_PLUGIN_DESC.name, stage);

	/* In the DUMP stage track all the PID's we've paused CUDA operations on to
	 * release them when we're done if the user requested the leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&cuda_pids);
	}

	set_compel_interrupt_only_mode();

	return 0;
}

void cuda_plugin_fini(int stage, int ret)
{
	cuda_free_device_map(cuda_restore_gpu_pairs);
	cuda_restore_gpu_pairs = NULL;
	cuda_restore_gpu_pairs_count = 0;
	cuda_gpu_inventory_fini();

	if (plugin_disabled) {
		cuda_api_fini();
		return;
	}

	pr_info("finished %s stage %d err %d\n", CR_PLUGIN_DESC.name, stage, ret);

	/* Release all the paused PID's at the end of the DUMP stage in case the
	 * user provides the -R (leave-running) flag or an error occurred
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && (opts.final_state == TASK_ALIVE || ret != 0)) {
		struct pid_info *info;
		list_for_each_entry(info, &cuda_pids, list) {
			if (resume_device(info->pid, info->current_task_state, info->initial_task_state))
				pr_err("Unable to restore CUDA state for pid %d during dump cleanup\n", info->pid);
		}
	}
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		free_cuda_pid_list();
	}

	cuda_api_fini();
}
CR_PLUGIN_REGISTER_VERSIONED("cuda", 2, cuda_plugin_init, cuda_plugin_fini)
