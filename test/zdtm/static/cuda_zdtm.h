#ifndef __CUDA_ZDTM_H__
#define __CUDA_ZDTM_H__

#include <stdint.h>

#include <cuda_runtime.h>

extern "C" {
#include "zdtmtst.h"
}

#define CUDA_ZDTM_THREADS 256

static inline unsigned int cuda_zdtm_grid(unsigned int nr)
{
	return (nr + CUDA_ZDTM_THREADS - 1) / CUDA_ZDTM_THREADS;
}

static inline int cuda_zdtm_check(cudaError_t err, const char *op)
{
	if (err == cudaSuccess)
		return 0;

	fail("%s failed: %s", op, cudaGetErrorString(err));
	return -1;
}

static inline int cuda_zdtm_select_device(int device)
{
	int count;

	if (cuda_zdtm_check(cudaGetDeviceCount(&count), "cudaGetDeviceCount"))
		return -1;
	if (device >= count) {
		fail("CUDA device %d not available, device count %d", device, count);
		return -1;
	}
	if (cuda_zdtm_check(cudaSetDevice(device), "cudaSetDevice"))
		return -1;

	return 0;
}

#endif /* __CUDA_ZDTM_H__ */
