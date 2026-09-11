#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

struct mock_cuda_gpu_pair {
	unsigned char old_uuid[16];
	unsigned char new_uuid[16];
};

struct mock_cuda_restore_args {
	struct mock_cuda_gpu_pair *gpu_pairs;
	unsigned int gpu_pairs_count;
};

struct mock_process {
	int pid;
	mock_cuda_process_state_t state;
};

static struct mock_process processes[MOCK_PROCESS_MAX];
static unsigned int nr_processes;

static int environment_matches(const char *name, const char *expected_name);

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

static void format_uuid(FILE *file, const unsigned char uuid[16])
{
	unsigned int i;

	fputs("GPU-", file);
	for (i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			fputc('-', file);
		fprintf(file, "%02x", uuid[i]);
	}
}

static int record_device_map(const struct mock_cuda_restore_args *args)
{
	const char *path = getenv("CRIU_CUDA_MOCK_DEVICE_MAP_MARKER");
	FILE *file;
	unsigned int i;

	if (!path)
		return 0;
	if (!args || !args->gpu_pairs || !args->gpu_pairs_count)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	file = fopen(path, "a");
	if (!file)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	for (i = 0; i < args->gpu_pairs_count; i++) {
		if (i)
			fputc(',', file);
		format_uuid(file, args->gpu_pairs[i].old_uuid);
		fputc('=', file);
		format_uuid(file, args->gpu_pairs[i].new_uuid);
	}
	fputc('\n', file);
	fclose(file);
	return 0;
}

mock_cuda_result_t cuInit(unsigned int flags)
{
	const char *marker = getenv("CRIU_CUDA_MOCK_INIT_MARKER");

	(void)flags;
	if (marker) {
		FILE *file = fopen(marker, "a");

		if (!file)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
		fprintf(file, "%ld\n", (long)getpid());
		if (fclose(file))
			return MOCK_CUDA_ERROR_INVALID_VALUE;
	}
	if (getenv("CRIU_CUDA_MOCK_INIT_EXIT"))
		_exit(EXIT_FAILURE);
	if (getenv("CRIU_CUDA_MOCK_INIT_ERROR"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (!environment_matches("CUDA_VISIBLE_DEVICES", "CRIU_CUDA_MOCK_EXPECT_VISIBLE_DEVICES") ||
	    !environment_matches("CUDA_DEVICE_ORDER", "CRIU_CUDA_MOCK_EXPECT_DEVICE_ORDER"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return MOCK_CUDA_SUCCESS;
}

static int environment_matches(const char *name, const char *expected_name)
{
	const char *expected = getenv(expected_name);
	const char *value;

	if (!expected)
		return 1;
	value = getenv(name);
	return value && !strcmp(value, expected);
}

mock_cuda_result_t cuDeviceGetCount(int *count)
{
	if (!count ||
	    !environment_matches("CUDA_VISIBLE_DEVICES", "CRIU_CUDA_MOCK_EXPECT_VISIBLE_DEVICES") ||
	    !environment_matches("CUDA_DEVICE_ORDER", "CRIU_CUDA_MOCK_EXPECT_DEVICE_ORDER"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	*count = MOCK_GPU_COUNT;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuDeviceGetUuid(void *uuid, int device)
{
	const char *offset_value = getenv("CRIU_CUDA_MOCK_UUID_OFFSET");
	unsigned char *bytes = uuid;
	unsigned long offset = 0;
	char *end = NULL;
	unsigned int i;

	if (!uuid || device < 0 || device >= MOCK_GPU_COUNT)
		return MOCK_CUDA_ERROR_INVALID_VALUE;

	if (offset_value) {
		errno = 0;
		offset = strtoul(offset_value, &end, 0);
		if (errno || end == offset_value || *end || offset > 0xff)
			return MOCK_CUDA_ERROR_INVALID_VALUE;
	}

	for (i = 0; i < 16; i++)
		bytes[i] = (unsigned char)(offset + (unsigned int)device * 16 + i);
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

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_CHECKPOINTED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	if (record_device_map(args))
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
