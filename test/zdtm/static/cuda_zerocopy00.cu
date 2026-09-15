#include "cuda_zdtm.h"

const char *test_doc = "Check CUDA mapped host memory survives checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define NR_ELEMS 8192

static uint32_t *host_a;
static uint32_t *host_b;
static uint32_t *host_c;
static uint32_t *cuda_a;
static uint32_t *cuda_b;
static uint32_t *cuda_c;

__global__ static void cuda_zerocopy_step(uint32_t *a, uint32_t *b, uint32_t *c, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		c[i] = a[i] + b[i] + addend;
}

static void cuda_cleanup(void)
{
	if (host_c) {
		cudaFreeHost(host_c);
		host_c = NULL;
	}
	if (host_b) {
		cudaFreeHost(host_b);
		host_b = NULL;
	}
	if (host_a) {
		cudaFreeHost(host_a);
		host_a = NULL;
	}
}

static void cuda_init_input(uint32_t bias)
{
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		host_a[i] = i;
		host_b[i] = bias + i * 3;
		host_c[i] = 0;
	}
}

static int cuda_verify(uint32_t bias, uint32_t addend)
{
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		uint32_t expected = i + bias + i * 3 + addend;

		if (host_c[i] != expected) {
			fail("CUDA zero-copy mismatch at %u: got %u expected %u", i, host_c[i], expected);
			return -1;
		}
	}

	return 0;
}

static int cuda_run_step(uint32_t bias, uint32_t addend)
{
	unsigned int grid = cuda_zdtm_grid(NR_ELEMS);

	cuda_init_input(bias);
	cuda_zerocopy_step<<<grid, CUDA_ZDTM_THREADS>>>(cuda_a, cuda_b, cuda_c, NR_ELEMS, addend);
	if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_zerocopy_step launch"))
		return -1;
	if (cuda_zdtm_check(cudaDeviceSynchronize(), "cudaDeviceSynchronize"))
		return -1;

	return cuda_verify(bias, addend);
}

static int cuda_prepare(void)
{
	cudaDeviceProp prop;

	if (cuda_zdtm_check(cudaSetDeviceFlags(cudaDeviceMapHost), "cudaSetDeviceFlags"))
		return -1;
	if (cuda_zdtm_select_device(0))
		return -1;
	if (cuda_zdtm_check(cudaGetDeviceProperties(&prop, 0), "cudaGetDeviceProperties"))
		return -1;
	if (!prop.canMapHostMemory) {
		fail("CUDA device cannot map host memory");
		return -1;
	}

	if (cuda_zdtm_check(cudaHostAlloc((void **)&host_a, NR_ELEMS * sizeof(*host_a), cudaHostAllocMapped),
			    "cudaHostAlloc host_a"))
		return -1;
	if (cuda_zdtm_check(cudaHostAlloc((void **)&host_b, NR_ELEMS * sizeof(*host_b), cudaHostAllocMapped),
			    "cudaHostAlloc host_b"))
		return -1;
	if (cuda_zdtm_check(cudaHostAlloc((void **)&host_c, NR_ELEMS * sizeof(*host_c), cudaHostAllocMapped),
			    "cudaHostAlloc host_c"))
		return -1;

	if (cuda_zdtm_check(cudaHostGetDevicePointer((void **)&cuda_a, host_a, 0), "cudaHostGetDevicePointer host_a"))
		return -1;
	if (cuda_zdtm_check(cudaHostGetDevicePointer((void **)&cuda_b, host_b, 0), "cudaHostGetDevicePointer host_b"))
		return -1;
	if (cuda_zdtm_check(cudaHostGetDevicePointer((void **)&cuda_c, host_c, 0), "cudaHostGetDevicePointer host_c"))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_step(5, 17))
		goto err;

	test_msg("CUDA zero-copy workload ready on pid %d\n", getpid());
	test_daemon();
	test_waitsig();

	if (cuda_run_step(11, 23))
		goto err;

	cuda_cleanup();
	pass();
	return 0;

err:
	cuda_cleanup();
	return 1;
}
