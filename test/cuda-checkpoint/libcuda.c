#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

mock_cuda_result_t cuInit(unsigned int flags)
{
	(void)flags;
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

	/* A selected PID can remain CUDA while the rest of a process tree is not. */
	if (error && (!cuda_pid || atoi(cuda_pid) != pid))
		return atoi(error);

	*tid = pid;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessGetState(int pid, mock_cuda_process_state_t *state)
{
	struct mock_process *process = get_process(pid);

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

mock_cuda_result_t cuCheckpointProcessCheckpoint(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;

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

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_CHECKPOINTED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessUnlock(int pid, void *args)
{
	struct mock_process *process = get_process(pid);

	(void)args;

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_RUNNING;
	return MOCK_CUDA_SUCCESS;
}
