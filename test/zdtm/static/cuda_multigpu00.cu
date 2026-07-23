#include "cuda_zdtm.h"

const char *test_doc = "Check CUDA state on multiple GPUs survives checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define MAX_GPUS 32
#define NR_ELEMS 4096

struct cuda_gpu {
	uint32_t *host_data;
	uint32_t *cuda_data;
	cudaStream_t stream;
};

static struct cuda_gpu gpus[MAX_GPUS];
static int nr_gpus;

__global__ static void cuda_multigpu_step(uint32_t *data, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		data[i] += addend;
}

static void cuda_cleanup(void)
{
	for (int dev = 0; dev < nr_gpus; dev++) {
		cudaSetDevice(dev);
		if (gpus[dev].stream) {
			cudaStreamDestroy(gpus[dev].stream);
			gpus[dev].stream = NULL;
		}
		if (gpus[dev].cuda_data) {
			cudaFree(gpus[dev].cuda_data);
			gpus[dev].cuda_data = NULL;
		}
		if (gpus[dev].host_data) {
			cudaFreeHost(gpus[dev].host_data);
			gpus[dev].host_data = NULL;
		}
	}
}

static uint32_t cuda_base_value(int dev, unsigned int index)
{
	return (uint32_t)(dev * 100000 + index);
}

static int cuda_verify(int dev, uint32_t expected_addend)
{
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		uint32_t expected = cuda_base_value(dev, i) + expected_addend;

		if (gpus[dev].host_data[i] != expected) {
			fail("CUDA multi-GPU mismatch on device %d at %u: got %u expected %u",
			     dev, i, gpus[dev].host_data[i], expected);
			return -1;
		}
	}

	return 0;
}

static int cuda_run_step(uint32_t addend, uint32_t expected_addend)
{
	unsigned int grid = cuda_zdtm_grid(NR_ELEMS);

	for (int dev = 0; dev < nr_gpus; dev++) {
		if (cuda_zdtm_check(cudaSetDevice(dev), "cudaSetDevice"))
			return -1;
		cuda_multigpu_step<<<grid, CUDA_ZDTM_THREADS, 0, gpus[dev].stream>>>(gpus[dev].cuda_data,
										      NR_ELEMS, addend);
		if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_multigpu_step launch"))
			return -1;
		if (cuda_zdtm_check(cudaMemcpyAsync(gpus[dev].host_data, gpus[dev].cuda_data,
						   NR_ELEMS * sizeof(*gpus[dev].host_data),
						   cudaMemcpyDeviceToHost, gpus[dev].stream),
				    "cudaMemcpyAsync device to host"))
			return -1;
	}

	for (int dev = 0; dev < nr_gpus; dev++) {
		if (cuda_zdtm_check(cudaSetDevice(dev), "cudaSetDevice"))
			return -1;
		if (cuda_zdtm_check(cudaStreamSynchronize(gpus[dev].stream), "cudaStreamSynchronize"))
			return -1;
		if (cuda_verify(dev, expected_addend))
			return -1;
	}

	return 0;
}

static int cuda_prepare(void)
{
	if (cuda_zdtm_check(cudaGetDeviceCount(&nr_gpus), "cudaGetDeviceCount"))
		return -1;
	if (nr_gpus < 2) {
		fail("need at least two CUDA devices, found %d", nr_gpus);
		return -1;
	}
	if (nr_gpus > MAX_GPUS) {
		fail("too many CUDA devices: %d > %d", nr_gpus, MAX_GPUS);
		return -1;
	}

	for (int dev = 0; dev < nr_gpus; dev++) {
		if (cuda_zdtm_check(cudaSetDevice(dev), "cudaSetDevice"))
			return -1;
		if (cuda_zdtm_check(cudaMallocHost((void **)&gpus[dev].host_data,
						  NR_ELEMS * sizeof(*gpus[dev].host_data)),
				    "cudaMallocHost"))
			return -1;
		for (unsigned int i = 0; i < NR_ELEMS; i++)
			gpus[dev].host_data[i] = cuda_base_value(dev, i);
		if (cuda_zdtm_check(cudaMalloc((void **)&gpus[dev].cuda_data,
					      NR_ELEMS * sizeof(*gpus[dev].cuda_data)),
				    "cudaMalloc"))
			return -1;
		if (cuda_zdtm_check(cudaStreamCreateWithFlags(&gpus[dev].stream, cudaStreamNonBlocking),
				    "cudaStreamCreateWithFlags"))
			return -1;
		if (cuda_zdtm_check(cudaMemcpyAsync(gpus[dev].cuda_data, gpus[dev].host_data,
						   NR_ELEMS * sizeof(*gpus[dev].host_data),
						   cudaMemcpyHostToDevice, gpus[dev].stream),
				    "cudaMemcpyAsync host to device"))
			return -1;
		if (cuda_zdtm_check(cudaStreamSynchronize(gpus[dev].stream), "cudaStreamSynchronize"))
			return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_step(17, 17))
		goto err;

	test_msg("CUDA multi-GPU workload ready on pid %d with %d devices\n", getpid(), nr_gpus);
	test_daemon();
	test_waitsig();

	if (cuda_run_step(23, 40))
		goto err;

	cuda_cleanup();
	pass();
	return 0;

err:
	cuda_cleanup();
	return 1;
}
