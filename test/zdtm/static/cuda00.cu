#include "cuda_zdtm.h"

const char *test_doc = "Check CUDA device memory survives checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define NR_ELEMS 4096

static uint32_t *cuda_data;

__global__ static void cuda_step(uint32_t *data, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		data[i] += addend;
}

static void cuda_cleanup(void)
{
	if (cuda_data) {
		cudaFree(cuda_data);
		cuda_data = NULL;
	}
}

static int cuda_run_step(uint32_t addend)
{
	unsigned int grid = cuda_zdtm_grid(NR_ELEMS);

	cuda_step<<<grid, CUDA_ZDTM_THREADS>>>(cuda_data, NR_ELEMS, addend);
	if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_step launch"))
		return -1;
	if (cuda_zdtm_check(cudaDeviceSynchronize(), "cudaDeviceSynchronize"))
		return -1;

	return 0;
}

static int cuda_verify(uint32_t expected_addend)
{
	uint32_t host[NR_ELEMS];
	cudaError_t err;

	err = cudaMemcpy(host, cuda_data, sizeof(host), cudaMemcpyDeviceToHost);
	if (cuda_zdtm_check(err, "cudaMemcpy device to host"))
		return -1;

	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		uint32_t expected = i + expected_addend;

		if (host[i] != expected) {
			fail("CUDA data mismatch at %u: got %u expected %u", i, host[i], expected);
			return -1;
		}
	}

	return 0;
}

static int cuda_prepare(void)
{
	uint32_t host[NR_ELEMS];
	cudaError_t err;
	int count;

	if (cuda_zdtm_check(cudaGetDeviceCount(&count), "cudaGetDeviceCount"))
		return -1;
	if (count <= 0) {
		fail("no CUDA devices found");
		return -1;
	}

	if (cuda_zdtm_check(cudaSetDevice(0), "cudaSetDevice"))
		return -1;

	for (unsigned int i = 0; i < NR_ELEMS; i++)
		host[i] = i;

	if (cuda_zdtm_check(cudaMalloc((void **)&cuda_data, sizeof(host)), "cudaMalloc"))
		return -1;
	err = cudaMemcpy(cuda_data, host, sizeof(host), cudaMemcpyHostToDevice);
	if (cuda_zdtm_check(err, "cudaMemcpy host to device"))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_step(17))
		goto err;
	if (cuda_verify(17))
		goto err;

	test_msg("CUDA workload ready on pid %d\n", getpid());
	test_daemon();
	test_waitsig();

	if (cuda_run_step(23))
		goto err;
	if (cuda_verify(40))
		goto err;

	cuda_cleanup();
	pass();
	return 0;

err:
	cuda_cleanup();
	return 1;
}
