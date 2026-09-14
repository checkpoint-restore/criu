#include "criu-log.h"
#include "cuda_driver_worker.h"
#include "cuda_wait.h"
#include "clone-noasan.h"
#include "util.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

extern unsigned int cuda_plugin_timeout;

struct cuda_driver_api {
	CUresult (*init)(unsigned int flags);
	CUresult (*driver_get_version)(int *version);
	CUresult (*get_error_name)(CUresult error, const char **name);
	CUresult (*get_error_string)(CUresult error, const char **text);
	CUresult (*lock)(int pid, CUcheckpointLockArgs *args);
	CUresult (*checkpoint)(int pid, CUcheckpointCheckpointArgs *args);
	CUresult (*restore)(int pid, CUcheckpointRestoreArgs *args);
	CUresult (*unlock)(int pid, CUcheckpointUnlockArgs *args);
	CUresult (*get_state)(int pid, CUprocessState *state);
	CUresult (*get_restore_tid)(int pid, int *tid);
};

struct cuda_worker_start {
	int sockets[2];
	pid_t parent;
};

static pid_t worker_pid = -1;
static int worker_socket = -1;
static bool worker_broken;

static const char *operation_name(enum cuda_driver_operation op)
{
	switch (op) {
	case CUDA_DRIVER_PROBE:
		return "cuDriverGetVersion";
	case CUDA_DRIVER_INIT:
		return "cuInit";
	case CUDA_DRIVER_LOCK:
		return "cuCheckpointProcessLock";
	case CUDA_DRIVER_CHECKPOINT:
		return "cuCheckpointProcessCheckpoint";
	case CUDA_DRIVER_RESTORE:
		return "cuCheckpointProcessRestore";
	case CUDA_DRIVER_UNLOCK:
		return "cuCheckpointProcessUnlock";
	case CUDA_DRIVER_GET_STATE:
		return "cuCheckpointProcessGetState";
	case CUDA_DRIVER_GET_TID:
		return "cuCheckpointProcessGetRestoreThreadId";
	}
	return "unknown CUDA operation";
}

static void log_cuda_error(const struct cuda_driver_api *api, const char *op, int pid, CUresult result)
{
	const char *name = NULL, *description = NULL;

	if (api->get_error_name && api->get_error_name(result, &name) != CUDA_SUCCESS)
		name = NULL;
	if (api->get_error_string && api->get_error_string(result, &description) != CUDA_SUCCESS)
		description = NULL;
	if (!name)
		name = "CUDA_ERROR_UNKNOWN";
	if (description)
		pr_err("%s(%d) failed: %s (%d): %s\n", op, pid, name, result, description);
	else
		pr_err("%s(%d) failed: %s (%d)\n", op, pid, name, result);
}

static void *cuda_get_symbol(void *handle, const char *name)
{
	const char *err;
	void *symbol;

	dlerror();
	symbol = dlsym(handle, name);
	err = dlerror();
	if (err) {
		pr_debug("Unable to resolve %s from libcuda.so.1: %s\n", name, err);
		return NULL;
	}

	return symbol;
}

static int load_driver(struct cuda_driver_api *api, int *version)
{
	void *handle;
	CUresult result;

	/* Only this disposable process loads libcuda and owns its internal state. */
	handle = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		pr_info("Cannot load libcuda.so.1: %s\n", dlerror());
		return -ENOTSUP;
	}

#define LOAD(member, symbol) api->member = (typeof(api->member))cuda_get_symbol(handle, symbol)
	LOAD(init, "cuInit");
	LOAD(driver_get_version, "cuDriverGetVersion");
	LOAD(get_error_name, "cuGetErrorName");
	LOAD(get_error_string, "cuGetErrorString");
	LOAD(lock, "cuCheckpointProcessLock");
	LOAD(checkpoint, "cuCheckpointProcessCheckpoint");
	LOAD(restore, "cuCheckpointProcessRestore");
	LOAD(unlock, "cuCheckpointProcessUnlock");
	LOAD(get_state, "cuCheckpointProcessGetState");
	LOAD(get_restore_tid, "cuCheckpointProcessGetRestoreThreadId");
#undef LOAD

	if (!api->init || !api->driver_get_version || !api->lock || !api->checkpoint || !api->restore ||
	    !api->unlock || !api->get_state || !api->get_restore_tid) {
		pr_warn("CUDA checkpoint Driver API not available in libcuda.so.1\n");
		return -ENOTSUP;
	}

	result = api->driver_get_version(version);
	if (result != CUDA_SUCCESS) {
		log_cuda_error(api, "cuDriverGetVersion", 0, result);
		return -1;
	}
	if (*version < CUDA_DIRECT_MIN_DRIVER_API_VERSION) {
		pr_info("CUDA Driver API version %d is older than the direct backend minimum %d\n",
			*version, CUDA_DIRECT_MIN_DRIVER_API_VERSION);
		return -ENOTSUP;
	}
	return 0;
}

static void execute_request(const struct cuda_driver_api *api, const struct cuda_driver_request *request,
			    int version, bool *initialized, struct cuda_driver_reply *reply)
{
	switch (request->op) {
	case CUDA_DRIVER_PROBE:
		reply->value = version;
		break;
	case CUDA_DRIVER_INIT:
		if (!*initialized) {
			reply->result = api->init(0);
			if (reply->result == CUDA_SUCCESS)
				*initialized = true;
		}
		break;
	case CUDA_DRIVER_LOCK: {
		CUcheckpointLockArgs args = { .timeoutMs = request->timeout_ms };

		reply->result = api->lock(request->pid, &args);
		break;
	}
	case CUDA_DRIVER_CHECKPOINT: {
		CUcheckpointCheckpointArgs args = { 0 };

		reply->result = api->checkpoint(request->pid, &args);
		break;
	}
	case CUDA_DRIVER_RESTORE: {
		CUcheckpointRestoreArgs args = { 0 };

		reply->result = api->restore(request->pid, &args);
		break;
	}
	case CUDA_DRIVER_UNLOCK: {
		CUcheckpointUnlockArgs args = { 0 };

		reply->result = api->unlock(request->pid, &args);
		break;
	}
	case CUDA_DRIVER_GET_STATE: {
		CUprocessState state = CU_PROCESS_STATE_FAILED;

		reply->result = api->get_state(request->pid, &state);
		reply->value = state;
		break;
	}
	case CUDA_DRIVER_GET_TID:
		reply->result = api->get_restore_tid(request->pid, &reply->value);
		break;
	default:
		reply->error = -EINVAL;
		break;
	}

	/* A PID without CUDA is an expected answer to the restore-TID query. */
	if (reply->result != CUDA_SUCCESS &&
	    !(request->op == CUDA_DRIVER_GET_TID &&
	      (reply->result == CUDA_ERROR_INVALID_VALUE || reply->result == CUDA_ERROR_NOT_INITIALIZED)))
		log_cuda_error(api, operation_name(request->op), request->pid, reply->result);
}

static int worker_main(void *arg)
{
	struct cuda_worker_start *start = arg;
	struct cuda_driver_api api = { 0 };
	struct sigaction action = { .sa_handler = SIG_DFL };
	struct cuda_driver_request request;
	sigset_t mask;
	int version = 0, error, sig, socket_fd;
	bool initialized = false;
	ssize_t size;

	close(start->sockets[0]);
	/* Do not run CRIU's signal handlers in a process that owns no tracees. */
	sigemptyset(&action.sa_mask);
	for (sig = 1; sig < NSIG; sig++) {
		if (sig != SIGKILL && sig != SIGSTOP)
			sigaction(sig, &action, NULL);
	}
	sigemptyset(&mask);
	if (sigprocmask(SIG_SETMASK, &mask, NULL)) {
		pr_perror("Cannot reset CUDA worker signal mask");
		return 1;
	}
	if (prctl(PR_SET_PDEATHSIG, SIGKILL)) {
		pr_perror("Cannot arrange CUDA worker exit with its parent");
		return 1;
	}
	if (getppid() != start->parent)
		return 1;

	/* Retain only the control socket and log, so the worker cannot keep
	 * unrelated CRIU RPC sockets, image pipes, or service descriptors alive.
	 */
	socket_fd = fcntl(start->sockets[1], F_DUPFD_CLOEXEC, 3);
	if (socket_fd < 0 || dup2(log_get_fd(), STDERR_FILENO) < 0) {
		pr_perror("Cannot preserve CUDA worker descriptors");
		return 1;
	}
	log_fini();
	if (dup2(socket_fd, 3) < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
		pr_perror("Cannot relocate CUDA worker descriptors");
		return 1;
	}
	socket_fd = 3;
	close(STDIN_FILENO);
	if (close_fds(4))
		return 1;

	error = load_driver(&api, &version);
	for (;;) {
		struct cuda_driver_reply reply = { .error = error };

		size = recv(socket_fd, &request, sizeof(request), MSG_TRUNC);
		if (size == 0)
			return 0;
		if (size != sizeof(request)) {
			pr_err("Invalid CUDA worker request size %zd\n", size);
			return 1;
		}
		if (!error)
			execute_request(&api, &request, version, &initialized, &reply);
		if (send(socket_fd, &reply, sizeof(reply), MSG_NOSIGNAL) != sizeof(reply)) {
			pr_perror("Cannot send CUDA worker reply");
			return 1;
		}
	}
}

static int stop_worker(void)
{
	struct cuda_wait wait;
	int status, ret = 0;

	if (worker_socket >= 0) {
		close(worker_socket);
		worker_socket = -1;
	}
	if (worker_pid > 0) {
		int wait_ret;

		if (kill(worker_pid, SIGKILL) && errno != ESRCH) {
			pr_perror("Cannot kill CUDA worker %d", worker_pid);
			ret = -1;
		}
		/* Do not turn a blocked driver ioctl into an unbounded wait here. */
		wait_ret = cuda_wait_init(&wait, "stop CUDA worker", worker_pid, 0, NULL, 1);
		if (!wait_ret) {
			wait.ignore_criu_timeout = true;
			wait_ret = cuda_wait_child(&wait, worker_pid, __WCLONE, &status);
		}
		if (wait_ret) {
			pr_err("CUDA worker %d did not exit after SIGKILL; driver may be stuck in the kernel\n",
			       worker_pid);
			ret = -1;
		} else if (worker_broken) {
			if (WIFEXITED(status) && WEXITSTATUS(status))
				pr_err("CUDA worker %d exited with status %d\n", worker_pid, WEXITSTATUS(status));
			else if (WIFSIGNALED(status) && WTERMSIG(status) != SIGKILL)
				pr_err("CUDA worker %d terminated by signal %d\n", worker_pid, WTERMSIG(status));
		}
		worker_pid = -1;
	}
	return ret;
}

static int start_worker(void)
{
	struct cuda_worker_start start = { .parent = getpid() };
	int saved_errno;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, start.sockets)) {
		saved_errno = errno;
		pr_perror("Cannot create CUDA worker socket");
		stop_worker();
		return -saved_errno;
	}
	worker_socket = start.sockets[0];
	/* No SIGCHLD: the restore master's handler only understands restored
	 * tasks, and its foreground wait must not include this private worker.
	 */
	worker_pid = clone_noasan(worker_main, 0, &start);
	saved_errno = errno;
	close(start.sockets[1]);
	if (worker_pid < 0) {
		errno = saved_errno;
		pr_perror("Cannot create CUDA Driver API worker");
		stop_worker();
		return -saved_errno;
	}
	return 0;
}

int cuda_driver_worker_call(const struct cuda_driver_request *request, struct cuda_driver_reply *reply,
			    int monitored_tid, int *thread_status)
{
	sigset_t blocked, saved;
	struct cuda_wait wait;
	ssize_t size;
	int ret, unused_thread_status;

	if (!thread_status)
		thread_status = &unused_thread_status;
	*thread_status = -1;
	memset(reply, 0, sizeof(*reply));
	if (worker_broken) {
		pr_err("CUDA worker is unavailable after an earlier failure; cannot run %s(%d)\n",
		       operation_name(request->op), request->pid);
		return -EIO;
	}
	/* The restore SIGCHLD handler must not consume the event we monitor. */
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blocked, &saved)) {
		pr_perror("Cannot block SIGCHLD during CUDA operation");
		return -errno;
	}
	ret = cuda_wait_init(&wait, operation_name(request->op), request->pid, monitored_tid,
			     thread_status, cuda_plugin_timeout);
	if (ret)
		goto failed;
	if (worker_pid < 0) {
		ret = start_worker();
		if (ret)
			goto failed;
	}
	size = send(worker_socket, request, sizeof(*request), MSG_NOSIGNAL | MSG_DONTWAIT);
	if (size != sizeof(*request)) {
		ret = size < 0 ? -errno : -EIO;
		pr_perror("Cannot send %s(%d) to CUDA worker", operation_name(request->op), request->pid);
		goto failed;
	}
	ret = cuda_wait_fd(&wait, worker_socket);
	if (ret)
		goto failed;
	size = recv(worker_socket, reply, sizeof(*reply), MSG_DONTWAIT | MSG_TRUNC);
	if (size != sizeof(*reply)) {
		pr_err("CUDA worker stopped or returned an invalid reply during %s(%d): %zd bytes\n",
		       operation_name(request->op), request->pid, size);
		ret = -EIO;
		goto failed;
	}
	ret = cuda_wait_check_thread(&wait);
	if (!ret)
		goto out;
failed:
	worker_broken = true;
	stop_worker();
out:
	if (sigprocmask(SIG_SETMASK, &saved, NULL)) {
		int saved_errno = errno;

		pr_perror("Cannot restore signal mask after CUDA operation");
		worker_broken = true;
		stop_worker();
		if (!ret)
			ret = -saved_errno;
	}
	return ret;
}

int cuda_driver_worker_fini(void)
{
	int ret = stop_worker();

	worker_broken = false;
	return ret;
}
