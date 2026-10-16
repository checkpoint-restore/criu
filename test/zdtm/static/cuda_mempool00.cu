#include <stdint.h>

#include "cuda_zdtm.h"

const char *test_doc = "Check CUDA stream-ordered memory allocation survives checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define NR_ELEMS 8192

static uint32_t *host_data;
static uint32_t *cuda_data;
static cudaStream_t stream;

__global__ static void cuda_mempool_step(uint32_t *data, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		data[i] += addend;
}

static void cuda_cleanup(void)
{
	if (cuda_data && stream) {
		cudaFreeAsync(cuda_data, stream);
		cudaStreamSynchronize(stream);
		cuda_data = NULL;
	}
	if (stream) {
		cudaStreamDestroy(stream);
		stream = NULL;
	}
	if (host_data) {
		cudaFreeHost(host_data);
		host_data = NULL;
	}
}

static int cuda_verify(uint32_t expected_addend)
{
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		uint32_t expected = i + expected_addend;

		if (host_data[i] != expected) {
			fail("CUDA mempool data mismatch at %u: got %u expected %u", i, host_data[i], expected);
			return -1;
		}
	}

	return 0;
}

static int cuda_run_step(uint32_t addend, uint32_t expected_addend)
{
	unsigned int grid = cuda_zdtm_grid(NR_ELEMS);

	cuda_mempool_step<<<grid, CUDA_ZDTM_THREADS, 0, stream>>>(cuda_data, NR_ELEMS, addend);
	if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_mempool_step launch"))
		return -1;
	if (cuda_zdtm_check(cudaMemcpyAsync(host_data, cuda_data, NR_ELEMS * sizeof(*host_data),
					   cudaMemcpyDeviceToHost, stream),
			    "cudaMemcpyAsync device to host"))
		return -1;
	if (cuda_zdtm_check(cudaStreamSynchronize(stream), "cudaStreamSynchronize"))
		return -1;

	return cuda_verify(expected_addend);
}

static int cuda_prepare(void)
{
	cudaMemPool_t mem_pool;
	uint64_t threshold = UINT64_MAX;
	int supported;

	if (cuda_zdtm_select_device(0))
		return -1;
	if (cuda_zdtm_check(cudaDeviceGetAttribute(&supported, cudaDevAttrMemoryPoolsSupported, 0),
			    "cudaDeviceGetAttribute cudaDevAttrMemoryPoolsSupported"))
		return -1;
	if (!supported) {
		fail("CUDA device does not support memory pools");
		return -1;
	}

	if (cuda_zdtm_check(cudaMallocHost((void **)&host_data, NR_ELEMS * sizeof(*host_data)), "cudaMallocHost"))
		return -1;
	for (unsigned int i = 0; i < NR_ELEMS; i++)
		host_data[i] = i;

	if (cuda_zdtm_check(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreateWithFlags"))
		return -1;
	if (cuda_zdtm_check(cudaDeviceGetDefaultMemPool(&mem_pool, 0), "cudaDeviceGetDefaultMemPool"))
		return -1;
	if (cuda_zdtm_check(cudaMemPoolSetAttribute(mem_pool, cudaMemPoolAttrReleaseThreshold, &threshold),
			    "cudaMemPoolSetAttribute cudaMemPoolAttrReleaseThreshold"))
		return -1;
	if (cuda_zdtm_check(cudaMallocAsync((void **)&cuda_data, NR_ELEMS * sizeof(*cuda_data), stream),
			    "cudaMallocAsync"))
		return -1;
	if (cuda_zdtm_check(cudaMemcpyAsync(cuda_data, host_data, NR_ELEMS * sizeof(*host_data),
					   cudaMemcpyHostToDevice, stream),
			    "cudaMemcpyAsync host to device"))
		return -1;
	if (cuda_zdtm_check(cudaStreamSynchronize(stream), "cudaStreamSynchronize"))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_step(17, 17))
		goto err;

	test_msg("CUDA mempool workload ready on pid %d\n", getpid());
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
