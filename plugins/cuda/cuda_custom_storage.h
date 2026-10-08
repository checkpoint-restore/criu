#ifndef CUDA_CUSTOM_STORAGE_H
#define CUDA_CUSTOM_STORAGE_H

#include <stdbool.h>
#include <stddef.h>

#include "cuda_checkpoint.h"

#define CUDA_CS_MAXDEV 32 /* GPUs of one task */

/*
 * CUDA 13.4 (driver >= R615) custom-storage checkpoint/restore: the driver maps the target
 * process's GPU memory into the calling process (one contiguous region per GPU) and the caller
 * moves the bytes itself, then calls cuCheckpointOperationComplete().  No VRAM-sized host
 * staging in the target, and the copies run at whatever rate the storage and PCIe allow.
 */
typedef struct CUIcheckpointOperation_st *CUcheckpointOperationHandle;

typedef struct {
	unsigned long long devPtr; /* CUdeviceptr: zero-copy mapped device memory */
	size_t size;
	void *stream; /* CUstream in the primary context of that GPU */
} CUcheckpointCustomStoragePerDeviceData;

struct CUcheckpointCustomStorageInfo_st {
	CUcheckpointOperationHandle handle;
	CUcheckpointCustomStoragePerDeviceData *perDeviceData;
	unsigned int deviceCount;
};
typedef struct CUcheckpointCustomStorageInfo_st CUcheckpointCustomStorageInfo;

enum cuda_cs_mode {
	CUDA_CS_AUTO = 0, /* use it when the driver exposes the API */
	CUDA_CS_ON,	  /* require it */
	CUDA_CS_OFF,	  /* never */
};
extern enum cuda_cs_mode cuda_cs_mode;

/* Resolve the extra driver symbols from an already dlopen()ed libcuda; -ENOTSUP if the API is absent. */
int cuda_cs_init(void *libcuda_handle);
/* True when the API is available and the mode allows it: the dump uses custom storage. */
bool cuda_cs_active(void);
/* Fail unless a task checkpointed to custom storage can be restored from it. */
int cuda_cs_check_restore(int pid);
/* 1 if gpu-cs-<nspid>.img exists in img_dir_fd, 0 if not, -1 on error. */
int cuda_cs_image_exists(int pid, int img_dir_fd);
/* Remove a gpu-cs-<nspid>.img left by an earlier dump. */
int cuda_cs_image_remove(int pid, int img_dir_fd);
/*
 * The driver needs CRIU to retain the primary contexts of the GPUs the task
 * uses, and CRIU must not create any on the others, which can be other
 * tenants'. At checkpoint, those holding its memory, from NVML: 0 and *n = 0
 * if it has none, -1 if NVML cannot tell.
 */
int cuda_cs_task_gpus(int pid, unsigned char (*gpus)[16], unsigned int *n);
/* At restore, those its image restores onto, as cuda_cs_transfer() pairs them. */
int cuda_cs_restore_gpus(int pid, int img_dir_fd, const CUcheckpointGpuPair *pairs, unsigned int npairs,
			 unsigned char (*gpus)[16], unsigned int *n);
/* Retain the primary contexts of these GPUs (after cuInit()), until cuda_cs_fini(). */
int cuda_cs_retain(const unsigned char (*gpus)[16], unsigned int n);
void cuda_cs_fini(void);
/*
 * Copy the mapped regions to (restore=false) or from (restore=true) gpu-cs-<nspid>.img in img_dir_fd.
 * On restore, each region gets the memory of the GPU that pairs (the device map, old to new UUID) maps
 * to its GPU, or of its own GPU without a pair; without a map, a single GPU that changed takes the
 * memory of the single checkpointed GPU left.
 */
int cuda_cs_transfer(int pid, CUcheckpointCustomStorageInfo *info, int img_dir_fd, bool restore,
		     const CUcheckpointGpuPair *pairs, unsigned int npairs);
/* Tell the driver the copies are done (synchronises its streams, unmaps). */
int cuda_cs_complete(CUcheckpointOperationHandle handle);

#endif /* CUDA_CUSTOM_STORAGE_H */
