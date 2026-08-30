#include "criu-log.h"
#include "cuda_checkpoint.h"
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

#include <dlfcn.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static void *cuda_handle;
static bool cuda_driver_initialized;
static bool driver_failed;
static bool driver_call_aborted;

/* Only the tracing thread accesses the jump buffer and wait status. Other
 * threads can receive process-directed SIGCHLD and only notify this thread.
 * Keep this storage alive when a late handler outlives an operation.
 */
static struct {
	sigjmp_buf env;
	sigset_t blocked;
	int owner_tid;
	volatile sig_atomic_t restore_tid;
	int notified;
	volatile sig_atomic_t active;
	volatile sig_atomic_t in_call;
	volatile sig_atomic_t status;
	volatile sig_atomic_t error;
} cuda_guard;

_Static_assert(__atomic_always_lock_free(sizeof(int), 0), "CUDA signal routing needs lock-free integers");

static void cuda_call_begin(void);
static void cuda_call_end(void);

/* Keep CRIU's own logging and bookkeeping outside the jump interval. */
#define CUDA_CALL(member, ...) ({              \
	CUresult result;                       \
	cuda_call_begin();                     \
	result = cuda_api.member(__VA_ARGS__); \
	cuda_call_end();                       \
	result;                                \
})

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
		/* A nonlocal return may have left locks held inside libcuda. */
		if (!driver_call_aborted)
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

	if (CUDA_CALL(get_error_name, res, &name) != CUDA_SUCCESS || !name)
		return "CUDA_ERROR_UNKNOWN";

	return name;
}

static const char *cuda_result_string(CUresult res)
{
	const char *str = NULL;

	if (!cuda_api.get_error_string)
		return NULL;

	if (CUDA_CALL(get_error_string, res, &str) != CUDA_SUCCESS || !str)
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

	if (driver_call_aborted) {
		pr_err("Cannot reuse the CUDA Driver API after abandoning a call\n");
		return -1;
	}

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
	res = CUDA_CALL(driver_get_version, &driver_version);
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
	res = CUDA_CALL(init, 0);
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

	res = CUDA_CALL(get_restore_tid, root_pid, tid);
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

	res = CUDA_CALL(get_state, pid, &state);
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

	res = CUDA_CALL(unlock, pid, &args);
	if (res != CUDA_SUCCESS) {
		cuda_log_error("cuCheckpointProcessUnlock", pid, res);
		return -1;
	}

	return 0;
}

static int restore_thread_settings(int restore_tid, k_rtsigset_t *restore_sigset)
{
	const unsigned long ptrace_options = PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD;
	int ret = 0;

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

/* SIGCHLD is blocked here. Accept only the stop requested by this tracer. */
static int interrupt_restore_thread(int restore_tid)
{
	struct cuda_wait wait;
	int status, ret;
	pid_t pid;

	ret = cuda_wait_init(&wait, "stop CUDA restore thread", restore_tid, 0, NULL,
			     CUDA_RESTORE_THREAD_STOP_TIMEOUT);
	if (ret) {
		cuda_guard.error = -ret;
		return -1;
	}
	wait.ignore_criu_timeout = true;
	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, restore_tid, NULL, 0)) {
		cuda_guard.error = errno;
		return -1;
	}
	for (;;) {
		pid = waitpid(restore_tid, &status, __WALL | WNOHANG);
		if (pid == restore_tid)
			break;
		if (pid < 0) {
			if (errno == EINTR)
				continue;
			cuda_guard.error = errno;
			return -1;
		}
		ret = cuda_wait_signal(&wait, &cuda_guard.blocked);
		if (ret) {
			cuda_guard.error = -ret;
			return -1;
		}
		/* Re-notify CRIU after restoring its handler, including when this
		 * signal belongs to another child whose wait status is untouched.
		 */
		__atomic_store_n(&cuda_guard.notified, 1, __ATOMIC_RELAXED);
	}
	cuda_guard.status = status;
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
	    (unsigned int)status >> 16 != PTRACE_EVENT_STOP)
		return -1;
	return 0;
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

/* Called on the tracing thread, either from SIGCHLD or with it blocked. */
static bool cuda_restore_thread_failed(void)
{
	int status;
	pid_t pid;

	do {
		pid = waitpid(cuda_guard.restore_tid, &status, __WALL | WNOHANG);
	} while (pid < 0 && errno == EINTR);
	if (!pid)
		return false;
	if (pid < 0)
		cuda_guard.error = errno;
	else
		cuda_guard.status = status;
	return true;
}

static void cuda_sigchld(int signal)
{
	int saved_errno = errno;
	int owner = __atomic_load_n(&cuda_guard.owner_tid, __ATOMIC_ACQUIRE);

	(void)signal;
	__atomic_store_n(&cuda_guard.notified, 1, __ATOMIC_RELAXED);
	if (!owner)
		goto out;
	if (syscall(SYS_gettid) != owner) {
		/* SIGCHLD is process-directed. Never jump across thread stacks. */
		syscall(SYS_tgkill, getpid(), owner, SIGCHLD);
		goto out;
	}
	if (cuda_guard.in_call && cuda_restore_thread_failed())
		siglongjmp(cuda_guard.env, 1);
out:
	errno = saved_errno;
}

static void cuda_call_begin(void)
{
	if (!cuda_guard.active)
		return;
	cuda_guard.in_call = 1;
	if (sigprocmask(SIG_UNBLOCK, &cuda_guard.blocked, NULL)) {
		cuda_guard.error = errno;
		siglongjmp(cuda_guard.env, 1);
	}
}

static void cuda_call_end(void)
{
	if (!cuda_guard.active)
		return;
	if (sigprocmask(SIG_BLOCK, &cuda_guard.blocked, NULL)) {
		cuda_guard.error = errno;
		siglongjmp(cuda_guard.env, 1);
	}
	cuda_guard.in_call = 0;
	/* A notification may be pending, coalesced, or still being forwarded by
	 * another thread. Check the target before making any further CUDA call.
	 */
	if (cuda_restore_thread_failed())
		siglongjmp(cuda_guard.env, 1);
}

static int run_cuda_operation(int pid, int restore_tid, int (*run)(void *arg), void *arg)
{
	struct sigaction action = { .sa_handler = cuda_sigchld, .sa_flags = SA_RESTART };
	struct sigaction saved_action;
	k_rtsigset_t restore_sigset;
	sigset_t saved_mask;
	volatile int exit_code = -1;
	int owner = syscall(SYS_gettid);

	if (driver_failed)
		return -1;
	sigemptyset(&cuda_guard.blocked);
	sigaddset(&cuda_guard.blocked, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &cuda_guard.blocked, &saved_mask)) {
		pr_perror("Cannot block SIGCHLD for CUDA operation");
		return -1;
	}
	cuda_guard.restore_tid = restore_tid;
	cuda_guard.status = -1;
	cuda_guard.error = 0;
	__atomic_store_n(&cuda_guard.notified, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&cuda_guard.owner_tid, owner, __ATOMIC_RELEASE);
	sigemptyset(&action.sa_mask);
	/* Do not inherit SA_NOCLDSTOP: the guard needs ptrace stop notifications. */
	if (sigaction(SIGCHLD, &action, &saved_action)) {
		pr_perror("Cannot install CUDA SIGCHLD handler");
		goto restore_mask;
	}
	if (resume_restore_thread(restore_tid, &restore_sigset))
		goto restore_handler;

	/* Save the blocked mask so an escape also blocks SIGCHLD during cleanup.
	 * The target mask is saved before setjmp and is valid after the jump.
	 */
	if (sigsetjmp(cuda_guard.env, 1)) {
		driver_call_aborted |= cuda_guard.in_call;
		goto failed;
	}
	cuda_guard.active = 1;
	exit_code = run(arg);
	cuda_guard.active = 0;

	/* A fault may race with the last API reply or with PTRACE_INTERRUPT. */
	if (cuda_restore_thread_failed() || interrupt_restore_thread(restore_tid))
		goto failed;
	goto restore_settings;

failed:
	cuda_guard.active = 0;
	cuda_guard.in_call = 0;
	driver_failed = true;
	exit_code = -1;
	pr_err("CUDA restore thread %d failed during Driver API operation on pid %d: "
	       "wait status %#x, error %d\n",
	       restore_tid, pid,
	       (int)cuda_guard.status, (int)cuda_guard.error);
	if (cuda_guard.status != -1 && WIFSTOPPED(cuda_guard.status)) {
		pr_err("CUDA restore thread %d stopped by signal %d\n",
		       restore_tid, WSTOPSIG(cuda_guard.status));
		/* Checkpointing CUDA IPC without --launch-job can cause SIGSEGV.
		 * This should be fixed in driver 630 (CUDA 13.6). */
		if (WSTOPSIG(cuda_guard.status) == SIGSEGV)
			pr_err("For CUDA IPC, consider using: cuda-checkpoint --launch-job\n");
	}
restore_settings:
	/* A consumed fault stop must not be interrupted or waited for again. */
	if (cuda_guard.status != -1 && WIFSTOPPED(cuda_guard.status) &&
	    restore_thread_settings(restore_tid, &restore_sigset)) {
		driver_failed = true;
		exit_code = -1;
	}
restore_handler:
	/* Keep owner_tid valid: an already-entered handler on another thread
	 * must still forward its notification after the old action is restored.
	 */
	if (sigaction(SIGCHLD, &saved_action, NULL)) {
		pr_perror("Cannot restore SIGCHLD handler after CUDA operation");
		driver_failed = true;
		exit_code = -1;
	}
	/* Standard signals coalesce. Leave other children's wait statuses to
	 * the original handler, and notify it even if our event arrived too.
	 */
	if (__atomic_load_n(&cuda_guard.notified, __ATOMIC_RELAXED))
		syscall(SYS_tgkill, getpid(), owner, SIGCHLD);
restore_mask:
	if (sigprocmask(SIG_SETMASK, &saved_mask, NULL)) {
		pr_perror("Cannot restore signal mask after CUDA operation");
		driver_failed = true;
		exit_code = -1;
	}
	return exit_code;
}

static int checkpoint_device(void *arg)
{
	struct pid_info *task_info = arg;
	int pid = task_info->pid;
	CUcheckpointCheckpointArgs args = { 0 };
	cuda_task_state_t observed_task_state;
	CUresult res;
	int ret = 0;

	/* If the API fails before reporting its final state, CHECKPOINTED is the
	 * conservative rollback assumption. Replace it below whenever the driver
	 * can report the actual state while its restore thread is running.
	 */
	task_info->current_task_state = CUDA_TASK_CHECKPOINTED;
	res = CUDA_CALL(checkpoint, pid, &args);
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

	return ret;
}

static int cuda_driver_checkpoint_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	struct pid_info *task_info;
	int restore_tid;

	if (driver_failed)
		return -1;

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
	return run_cuda_operation(pid, restore_tid, checkpoint_device, task_info);
}

static int cuda_driver_pause_devices(int pid)
{
	enum cuda_restore_tid_result tid_result;
	CUcheckpointLockArgs args = { 0 };
	cuda_task_state_t task_state;
	int restore_tid;
	CUresult res;

	if (driver_failed)
		return -1;

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

	res = CUDA_CALL(lock, pid, &args);
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

struct cuda_resume_operation {
	int pid;
	cuda_task_state_t current;
	cuda_task_state_t initial;
	const struct cuda_device_map *map;
};

static int restore_device(void *arg)
{
	struct cuda_resume_operation *op = arg;
	int pid = op->pid;
	cuda_task_state_t current_task_state = op->current;
	cuda_task_state_t initial_task_state = op->initial;
	cuda_task_state_t observed_task_state;
	CUresult res;
	int ret = 0;

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
		goto out;
	}

	if (current_task_state == CUDA_TASK_FAILED) {
		pr_err("Cannot resume pid %d from failed CUDA state\n", pid);
		ret = -1;
		goto out;
	}
	if (current_task_state == initial_task_state)
		goto out;

	if (current_task_state == CUDA_TASK_CHECKPOINTED) {
		/* If the process was "locked" or "running" before checkpointing it, we need to restore it */
		CUcheckpointRestoreArgs args = { 0 };

		if (op->map) {
			args.gpuPairs = op->map->pairs;
			args.gpuPairsCount = op->map->count;
		}

		if (cuda_driver_init()) {
			ret = -1;
		} else {
			res = CUDA_CALL(restore, pid, &args);
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

out:
	return ret;
}

static int resume_device(int pid, cuda_task_state_t current_task_state,
			 cuda_task_state_t initial_task_state, const struct cuda_device_map *map)
{
	struct cuda_resume_operation op = {
		.pid = pid,
		.current = current_task_state,
		.initial = initial_task_state,
		.map = map,
	};
	enum cuda_restore_tid_result tid_result;
	int restore_tid;

	if (driver_failed)
		return -1;

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
	return run_cuda_operation(pid, restore_tid, restore_device, &op);
}

static int cuda_driver_resume_devices_late(int pid, const struct cuda_device_map *map)
{
	/* RESUME_DEVICES_LATE is used during `criu restore`.
	 * Here, we assume that users expect the target process
	 * to be in a "running" state after restore, even if it was
	 * in a "locked" or "checkpointed" state during `criu dump`.
	 */
	return resume_device(pid, CUDA_TASK_CHECKPOINTED, CUDA_TASK_RUNNING, map);
}

static int cuda_driver_backend_init(int stage)
{
	if (driver_call_aborted)
		return -1;
	driver_failed = false;
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
		if (resume_device(info->pid, info->current_task_state, info->initial_task_state, NULL)) {
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

	cuda_api_fini();
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
