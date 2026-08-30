#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Mock implementation of the CUDA checkpoint Driver API used by CRIU tests.
 *
 * This library does not access a GPU or maintain real CUDA state. By default,
 * it reports every PID as CUDA and keeps a synthetic process state so
 * tests can verify the plugin's API calls, ptrace coordination, state
 * transitions, and rollback handling without NVIDIA hardware.
 */

#define MOCK_CUDA_SUCCESS	      0
#define MOCK_CUDA_ERROR_INVALID_VALUE 1
#define MOCK_PROCESS_MAX	      64
#define MOCK_GPU_COUNT		      4

#ifndef MOCK_CUDA_DRIVER_VERSION
#define MOCK_CUDA_DRIVER_VERSION 13000
#endif

/* Keep these test-local declarations ABI-compatible with the plugin. */
typedef int mock_cuda_result_t;

typedef enum {
	MOCK_CUDA_PROCESS_STATE_RUNNING = 0,
	MOCK_CUDA_PROCESS_STATE_LOCKED,
	MOCK_CUDA_PROCESS_STATE_CHECKPOINTED,
	MOCK_CUDA_PROCESS_STATE_FAILED,
} mock_cuda_process_state_t;

struct mock_process {
	int pid;
	mock_cuda_process_state_t state;
};

static struct mock_process processes[MOCK_PROCESS_MAX];
static unsigned int nr_processes;

static void record_api(const char *operation, int pid)
{
	const char *path = getenv("CRIU_CUDA_MOCK_API_MARKER");
	FILE *file;

	if (!path)
		return;
	file = fopen(path, "a");
	if (!file)
		_exit(1);
	fprintf(file, "%s %d %ld\n", operation, pid, (long)syscall(SYS_gettid));
	if (fclose(file))
		_exit(1);
}

static mock_cuda_process_state_t initial_process_state(void)
{
	const char *state = getenv("CRIU_CUDA_MOCK_INITIAL_STATE");

	if (!state || !strcmp(state, "running"))
		return MOCK_CUDA_PROCESS_STATE_RUNNING;
	if (!strcmp(state, "locked"))
		return MOCK_CUDA_PROCESS_STATE_LOCKED;
	if (!strcmp(state, "checkpointed"))
		return MOCK_CUDA_PROCESS_STATE_CHECKPOINTED;
	if (!strcmp(state, "failed"))
		return MOCK_CUDA_PROCESS_STATE_FAILED;
	return MOCK_CUDA_PROCESS_STATE_RUNNING;
}

static struct mock_process *get_process(int pid)
{
	unsigned int i;

	for (i = 0; i < nr_processes; i++) {
		if (processes[i].pid == pid)
			return &processes[i];
	}

	if (nr_processes == MOCK_PROCESS_MAX)
		return NULL;

	processes[nr_processes].pid = pid;
	processes[nr_processes].state = initial_process_state();
	return &processes[nr_processes++];
}

static void checkpoint_behavior(int pid, const char *behavior);

mock_cuda_result_t cuInit(unsigned int flags)
{
	record_api("init", 0);
	(void)flags;
	if (getenv("CRIU_CUDA_MOCK_INIT_FAULT"))
		checkpoint_behavior(atoi(getenv("CRIU_CUDA_MOCK_TARGET_PID")), "fault");
	if (getenv("CRIU_CUDA_MOCK_INIT_HANG")) {
		for (;;)
			pause();
	}
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDeviceGetCount(int *count)
{
	if (!count)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	*count = MOCK_GPU_COUNT;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDeviceGetUuid(void *uuid, int device)
{
	unsigned char *bytes = uuid;
	unsigned int i;

	if (!uuid || device < 0 || device >= MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	for (i = 0; i < 16; i++)
		bytes[i] = (unsigned char)((unsigned int)device * 16 + i);
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDriverGetVersion(int *driver_version)
{
	const char *marker = getenv("CRIU_CUDA_MOCK_DRIVER_MARKER");

	if (marker) {
		FILE *marker_file = fopen(marker, "a");

		if (!marker_file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fputs("invoked\n", marker_file);
		fclose(marker_file);
	}

	if (getenv("CRIU_CUDA_MOCK_DRIVER_VERSION_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (!driver_version)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	*driver_version = MOCK_CUDA_DRIVER_VERSION;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuGetErrorName(mock_cuda_result_t error, const char **pstr)
{
	*pstr = error == MOCK_CUDA_SUCCESS ? "CUDA_SUCCESS" : "CUDA_ERROR_MOCK";
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuGetErrorString(mock_cuda_result_t error, const char **pstr)
{
	*pstr = error == MOCK_CUDA_SUCCESS ? "success" : "mock CUDA error";
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessGetRestoreThreadId(int pid, int *tid)
{
	const char *error = getenv("CRIU_CUDA_MOCK_TID_ERROR");
	const char *cuda_pid = getenv("CRIU_CUDA_MOCK_CUDA_PID");

	record_api("get-tid", pid);
	/* A selected PID can remain CUDA while the rest of a process tree is not. */
	if (error && (!cuda_pid || atoi(cuda_pid) != pid))
		return atoi(error);

	*tid = getenv("CRIU_CUDA_MOCK_RESTORE_TID") ? atoi(getenv("CRIU_CUDA_MOCK_RESTORE_TID")) : pid;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessGetState(int pid, mock_cuda_process_state_t *state)
{
	struct mock_process *process = get_process(pid);

	record_api("get-state", pid);
	if (!process)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	*state = process->state;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessLock(int pid, void *args)
{
	struct mock_process *process = get_process(pid);
	const char *marker = getenv("CRIU_CUDA_MOCK_LOCK_MARKER");

	(void)args;
	record_api("lock", pid);
	if (getenv("CRIU_CUDA_MOCK_LOCK_HANG")) {
		for (;;)
			pause();
	}

	if (marker) {
		FILE *file = fopen(marker, "a");

		if (!file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fputs("lock\n", file);
		fclose(file);
	}

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_RUNNING)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

/* Faults deliberately never return, even if the target dies. This checks
 * that the tracer escapes the API instead of waiting for libcuda to unblock.
 */
static void checkpoint_behavior(int pid, const char *behavior)
{
	const char *tid_value = getenv("CRIU_CUDA_MOCK_RESTORE_TID");
	int tid = tid_value ? atoi(tid_value) : pid;
	bool foreign, unrelated, fault;
	sigset_t blocked, saved;
	siginfo_t info;

	if (!behavior)
		return;
	if (!strcmp(behavior, "exit"))
		_exit(77); /* CLI helper failure, not a target exit. */
	foreign = !strcmp(behavior, "foreign-sigchld");
	unrelated = !strcmp(behavior, "unrelated") || !strcmp(behavior, "coalesced");
	fault = !strcmp(behavior, "fault") || foreign || !strcmp(behavior, "coalesced") ||
		!strcmp(behavior, "target-exit");
	if (foreign || unrelated) {
		sigemptyset(&blocked);
		sigaddset(&blocked, SIGCHLD);
		if (sigprocmask(SIG_BLOCK, &blocked, &saved))
			_exit(1);
	}
	if (unrelated) {
		pid_t child = atoi(getenv("CRIU_CUDA_MOCK_OTHER_PID"));
		int fd = atoi(getenv("CRIU_CUDA_MOCK_OTHER_FD"));

		if (write(fd, "x", 1) != 1 || waitid(P_PID, child, &info, WEXITED | WNOWAIT))
			_exit(1);
	}
	if (fault) {
		const char *path = getenv("CRIU_CUDA_MOCK_FAULT_TRIGGER");
		FILE *file = path ? fopen(path, "w") : NULL;

		if (!file || fclose(file))
			_exit(1);
	}
	if (!strcmp(behavior, "trap") && syscall(SYS_tgkill, pid, tid, SIGTRAP))
		_exit(1);
	if (!strcmp(behavior, "target-kill") && kill(pid, SIGKILL))
		_exit(1);
	if (foreign || !strcmp(behavior, "coalesced")) {
		if (waitid(P_PID, tid, &info, WSTOPPED | WNOWAIT | __WALL))
			_exit(1);
	}
	if (foreign) {
		const struct timespec timeout = { .tv_sec = 3 };
		int other_tid = atoi(getenv("CRIU_CUDA_MOCK_SIGNAL_TID"));

		/* Force the plugin handler to execute on another tracer thread.
		 * Wait for its thread-directed notification before unblocking ours.
		 */
		if (syscall(SYS_tgkill, getpid(), other_tid, SIGCHLD))
			_exit(1);
		do {
			if (sigtimedwait(&blocked, &info, &timeout) < 0)
				_exit(1);
		} while (info.si_pid != getpid());
		if (syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGCHLD))
			_exit(1);
	}
	if ((foreign || unrelated) && sigprocmask(SIG_SETMASK, &saved, NULL))
		_exit(1);
	if (fault || !strcmp(behavior, "trap") || !strcmp(behavior, "target-kill") ||
	    !strcmp(behavior, "hang")) {
		for (;;)
			pause();
	}
}

mock_cuda_result_t cuCheckpointProcessCheckpoint(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;
	record_api("checkpoint", pid);
	checkpoint_behavior(pid, getenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR"));

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_CHECKPOINTED;
	/* Test rollback when the mock changes state before reporting an error. */
	if (getenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessRestore(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;
	record_api("restore", pid);
	checkpoint_behavior(pid, getenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR"));

	if (getenv("CRIU_CUDA_MOCK_RESTORE_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_CHECKPOINTED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessUnlock(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;
	record_api("unlock", pid);

	if (getenv("CRIU_CUDA_MOCK_UNLOCK_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_RUNNING;
	return MOCK_CUDA_SUCCESS;
}
