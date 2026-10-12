#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Mock NVML for the custom-storage tests: the CUDA plugin uses it to find the
 * GPUs holding the memory of the task it checkpoints. GPU i has the UUID that
 * the mock libcuda gives it (CRIU_CUDA_MOCK_UUID_OFFSET). The task
 * CRIU_CUDA_MOCK_NVML_PID runs on the GPUs listed in CRIU_CUDA_MOCK_NVML_GPUS
 * ("0,1"), by default on the first CRIU_CUDA_MOCK_CS_DEVICES ones.
 * CRIU_CUDA_MOCK_NVML_INIT_ERROR makes nvmlInit fail.
 */

#define MOCK_GPU_COUNT 4

typedef struct {
	unsigned int pid;
	unsigned long long usedGpuMemory;
	unsigned int gpuInstanceId;
	unsigned int computeInstanceId;
} mock_nvml_process_info;

int nvmlInit_v2(void)
{
	return getenv("CRIU_CUDA_MOCK_NVML_INIT_ERROR") ? 999 : 0;
}

int nvmlShutdown(void)
{
	return 0;
}

int nvmlDeviceGetCount_v2(unsigned int *count)
{
	*count = MOCK_GPU_COUNT;
	return 0;
}

int nvmlDeviceGetHandleByIndex_v2(unsigned int index, void **dev)
{
	if (index >= MOCK_GPU_COUNT)
		return 2;
	*dev = (void *)(uintptr_t)(index + 1);
	return 0;
}

int nvmlDeviceGetUUID(void *dev, char *uuid, unsigned int len)
{
	unsigned int ordinal = (uintptr_t)dev - 1, offset = strtoul(getenv("CRIU_CUDA_MOCK_UUID_OFFSET") ?: "0", NULL, 0);
	unsigned char b[16];
	int i;

	for (i = 0; i < 16; i++)
		b[i] = (unsigned char)(offset + ordinal * 16 + i);
	snprintf(uuid, len, "GPU-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
		 b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
	return 0;
}

static int uses_gpu(unsigned int ordinal)
{
	const char *gpus = getenv("CRIU_CUDA_MOCK_NVML_GPUS");
	char *list, *tok, *save;
	int found = 0;

	if (!gpus)
		return ordinal < (unsigned int)atoi(getenv("CRIU_CUDA_MOCK_CS_DEVICES") ?: "2");
	list = strdup(gpus);
	for (tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
		if ((unsigned int)atoi(tok) == ordinal)
			found = 1;
	free(list);
	return found;
}

int nvmlDeviceGetComputeRunningProcesses_v3(void *dev, unsigned int *count, mock_nvml_process_info *infos)
{
	const char *pid = getenv("CRIU_CUDA_MOCK_NVML_PID");
	unsigned int n = pid && *pid && uses_gpu((uintptr_t)dev - 1);

	if (*count < n) {
		*count = n;
		return 7; /* NVML_ERROR_INSUFFICIENT_SIZE */
	}
	*count = n;
	if (n)
		infos[0] = (mock_nvml_process_info){ .pid = atoi(pid), .usedGpuMemory = 1 << 20 };
	return 0;
}
