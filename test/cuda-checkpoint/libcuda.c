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
#define MOCK_DEVICE_HANDLE_BASE	      100

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

/* Report a misconfigured test case instead of crashing inside CRIU. */
static int required_env_int(const char *name)
{
	const char *value = getenv(name);

	if (!value) {
		fprintf(stderr, "mock libcuda: %s is not set\n", name);
		_exit(1);
	}
	return atoi(value);
}

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

static bool checkpoint_behavior(int pid, const char *behavior);

mock_cuda_result_t cuInit(unsigned int flags)
{
	record_api("init", 0);
	(void)flags;
	if (getenv("CRIU_CUDA_MOCK_INIT_FAULT") &&
	    checkpoint_behavior(required_env_int("CRIU_CUDA_MOCK_TARGET_PID"), "fault"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
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

mock_cuda_result_t cuDeviceGet(int *device, int ordinal)
{
	if (!device || ordinal < 0 || ordinal >= MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	/* Device handles differ from ordinals so callers must use cuDeviceGet(). */
	*device = MOCK_DEVICE_HANDLE_BASE + ordinal;
	return MOCK_CUDA_SUCCESS;
}

/* Like a MIG instance, the original symbol reports only a parent GPU UUID. */
mock_cuda_result_t cuDeviceGetUuid(void *uuid, int device)
{
	if (!uuid || device < MOCK_DEVICE_HANDLE_BASE || device >= MOCK_DEVICE_HANDLE_BASE + MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	memset(uuid, 0xee, 16);
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDeviceGetUuid_v2(void *uuid, int device)
{
	unsigned char *bytes = uuid;
	unsigned int i;

	if (!uuid || device < MOCK_DEVICE_HANDLE_BASE || device >= MOCK_DEVICE_HANDLE_BASE + MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	device -= MOCK_DEVICE_HANDLE_BASE;

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

/* Model a blocking driver request with a pipe held open by the target.
 * Killing the target closes the pipe and lets the worker return normally.
 */
static bool checkpoint_behavior(int pid, const char *behavior)
{
	const char *tid_value = getenv("CRIU_CUDA_MOCK_RESTORE_TID");
	int tid = tid_value ? atoi(tid_value) : pid;
	bool fault;

	if (!behavior)
		return false;
	if (!strcmp(behavior, "exit"))
		_exit(77);
	if (!strcmp(behavior, "unrelated")) {
		int fd = required_env_int("CRIU_CUDA_MOCK_OTHER_FD");

		if (write(fd, "x", 1) != 1)
			_exit(1);
	}
	fault = !strcmp(behavior, "fault") || !strcmp(behavior, "target-exit");
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
	if (fault || !strcmp(behavior, "trap") || !strcmp(behavior, "target-kill")) {
		int fd = required_env_int("CRIU_CUDA_MOCK_TARGET_PIPE");
		char byte;
		ssize_t ret;

		do {
			ret = read(fd, &byte, 1);
		} while (ret < 0 && errno == EINTR);
		if (ret != 0)
			_exit(1);
		return true;
	}
	if (!strcmp(behavior, "hang")) {
		for (;;)
			pause();
	}
	return false;
}

mock_cuda_result_t cuCheckpointProcessCheckpoint(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;
	record_api("checkpoint", pid);
	if (checkpoint_behavior(pid, getenv("CRIU_CUDA_MOCK_CHECKPOINT_BEHAVIOR")))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

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
	if (checkpoint_behavior(pid, getenv("CRIU_CUDA_MOCK_RESTORE_BEHAVIOR")))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

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
