#include <stdlib.h>

/*
 * Mock implementation of the CUDA checkpoint Driver API used by CRIU tests.
 *
 * This library does not access a GPU or maintain real CUDA state. It reports
 * every tested PID as a CUDA process and keeps a synthetic process state so
 * tests can verify the plugin's API calls, ptrace coordination, state
 * transitions, and rollback handling without NVIDIA hardware.
 */

#define MOCK_CUDA_SUCCESS 0
#define MOCK_CUDA_ERROR_INVALID_VALUE 1
#define MOCK_PROCESS_MAX 64

/* Keep these test-local declarations ABI-compatible with the plugin. */
typedef int mock_cuda_result_t;

typedef enum {
	MOCK_CUDA_PROCESS_STATE_RUNNING = 0,
	MOCK_CUDA_PROCESS_STATE_LOCKED,
	MOCK_CUDA_PROCESS_STATE_CHECKPOINTED,
	MOCK_CUDA_PROCESS_STATE_FAILED,
} mock_cuda_process_state_t;

typedef struct {
	unsigned int timeout_ms;
	unsigned int reserved0;
	unsigned long long reserved1[7];
} mock_cuda_lock_args_t;

typedef struct {
	unsigned long long reserved[8];
} mock_cuda_checkpoint_args_t;

typedef struct {
	unsigned char old_uuid[16];
	unsigned char new_uuid[16];
} mock_cuda_gpu_pair_t;

typedef struct {
	mock_cuda_gpu_pair_t *gpu_pairs;
	unsigned int gpu_pairs_count;
	char reserved[52 - sizeof(mock_cuda_gpu_pair_t *)];
	unsigned long long reserved1;
} mock_cuda_restore_args_t;

typedef struct {
	unsigned long long reserved[8];
} mock_cuda_unlock_args_t;

_Static_assert(sizeof(mock_cuda_lock_args_t) == 64,
	       "mock_cuda_lock_args_t must be 64 bytes");
_Static_assert(sizeof(mock_cuda_checkpoint_args_t) == 64,
	       "mock_cuda_checkpoint_args_t must be 64 bytes");
_Static_assert(sizeof(mock_cuda_restore_args_t) == 64,
	       "mock_cuda_restore_args_t must be 64 bytes");
_Static_assert(sizeof(mock_cuda_unlock_args_t) == 64,
	       "mock_cuda_unlock_args_t must be 64 bytes");

struct mock_process {
	int pid;
	mock_cuda_process_state_t state;
};

static struct mock_process processes[MOCK_PROCESS_MAX];
static unsigned int nr_processes;

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
	processes[nr_processes].state = MOCK_CUDA_PROCESS_STATE_RUNNING;
	return &processes[nr_processes++];
}

mock_cuda_result_t cuInit(unsigned int flags)
{
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

mock_cuda_result_t cuCheckpointProcessLock(int pid, mock_cuda_lock_args_t *args)
{
	struct mock_process *process = get_process(pid);

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_RUNNING)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessCheckpoint(int pid, mock_cuda_checkpoint_args_t *args)
{
	struct mock_process *process = get_process(pid);

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_CHECKPOINTED;
	/* Test rollback when the mock changes state before reporting an error. */
	if (getenv("CRIU_CUDA_MOCK_CHECKPOINT_ERROR_AFTER_TRANSITION"))
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessRestore(int pid, mock_cuda_restore_args_t *args)
{
	struct mock_process *process = get_process(pid);

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_CHECKPOINTED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_LOCKED;
	return MOCK_CUDA_SUCCESS;
}

mock_cuda_result_t cuCheckpointProcessUnlock(int pid, mock_cuda_unlock_args_t *args)
{
	struct mock_process *process = get_process(pid);

	if (!process || process->state != MOCK_CUDA_PROCESS_STATE_LOCKED)
		return MOCK_CUDA_ERROR_INVALID_VALUE;
	process->state = MOCK_CUDA_PROCESS_STATE_RUNNING;
	return MOCK_CUDA_SUCCESS;
}
