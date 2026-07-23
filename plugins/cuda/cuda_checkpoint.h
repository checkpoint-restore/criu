#ifndef CUDA_CHECKPOINT_H
#define CUDA_CHECKPOINT_H

#include <stddef.h>

/*
 * Independently authored ABI declarations for the CUDA checkpoint Driver API,
 * based on NVIDIA's public API documentation. The NVIDIA driver does not
 * require CUDA toolkit headers for these calls. Keep these definitions local to
 * the plugin rather than depending on CUDA toolkit headers.
 *
 * This header describes the currently supported CUDA checkpoint ABI. Reserved
 * fields are part of the ABI and must remain zero. A future CUDA release that
 * assigns a meaning to one of them requires an explicit driver-version check
 * and updated declarations after its structure layout has been verified.
 */

typedef int CUresult;

#define CUDA_SUCCESS 0
#define CUDA_ERROR_INVALID_VALUE 1

typedef enum {
	CU_PROCESS_STATE_RUNNING = 0,
	CU_PROCESS_STATE_LOCKED,
	CU_PROCESS_STATE_CHECKPOINTED,
	CU_PROCESS_STATE_FAILED,
} CUprocessState;

typedef struct {
	unsigned int timeoutMs;
	unsigned int reserved0;
	unsigned long long reserved1[7];
} CUcheckpointLockArgs;

typedef struct {
	unsigned long long reserved[8];
} CUcheckpointCheckpointArgs;

typedef struct {
	unsigned char oldUuid[16];
	unsigned char newUuid[16];
} CUcheckpointGpuPair;

typedef struct {
	CUcheckpointGpuPair *gpuPairs;
	unsigned int gpuPairsCount;
	char reserved[52 - sizeof(CUcheckpointGpuPair *)];
	unsigned long long reserved1;
} CUcheckpointRestoreArgs;

typedef struct {
	unsigned long long reserved[8];
} CUcheckpointUnlockArgs;

/*
 * These structures mirror the currently supported CUDA Driver API checkpoint
 * ABI. Keep each structure 64 bytes so libcuda.so.1 receives the expected
 * structure layout from the plugin.
 */
_Static_assert(sizeof(CUcheckpointLockArgs) == 64,
	       "CUcheckpointLockArgs must be 64 bytes");
_Static_assert(sizeof(CUcheckpointCheckpointArgs) == 64,
	       "CUcheckpointCheckpointArgs must be 64 bytes");
_Static_assert(sizeof(CUcheckpointRestoreArgs) == 64,
	       "CUcheckpointRestoreArgs must be 64 bytes");
_Static_assert(sizeof(CUcheckpointUnlockArgs) == 64,
	       "CUcheckpointUnlockArgs must be 64 bytes");

_Static_assert(offsetof(CUcheckpointLockArgs, timeoutMs) == 0,
	       "CUcheckpointLockArgs.timeoutMs has an unexpected offset");
_Static_assert(offsetof(CUcheckpointLockArgs, reserved0) == 4,
	       "CUcheckpointLockArgs.reserved0 has an unexpected offset");
_Static_assert(offsetof(CUcheckpointRestoreArgs, gpuPairs) == 0,
	       "CUcheckpointRestoreArgs.gpuPairs has an unexpected offset");
_Static_assert(offsetof(CUcheckpointRestoreArgs, gpuPairsCount) == sizeof(void *),
	       "CUcheckpointRestoreArgs.gpuPairsCount has an unexpected offset");

#endif /* CUDA_CHECKPOINT_H */
