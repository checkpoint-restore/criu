#include <math.h>
#include <stdlib.h>

#include <cublas_v2.h>

#include "cuda_zdtm.h"

const char *test_doc = "Check CUBLAS handles and device memory survive checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define MATRIX_N 32
#define MATRIX_ELEMS (MATRIX_N * MATRIX_N)

static float *host_a;
static float *host_b;
static float *host_c;
static float *host_ref;
static float *cuda_a;
static float *cuda_b;
static float *cuda_c;
static cublasHandle_t handle;

static const char *cublas_status_string(cublasStatus_t status)
{
	switch (status) {
	case CUBLAS_STATUS_SUCCESS:
		return "CUBLAS_STATUS_SUCCESS";
	case CUBLAS_STATUS_NOT_INITIALIZED:
		return "CUBLAS_STATUS_NOT_INITIALIZED";
	case CUBLAS_STATUS_ALLOC_FAILED:
		return "CUBLAS_STATUS_ALLOC_FAILED";
	case CUBLAS_STATUS_INVALID_VALUE:
		return "CUBLAS_STATUS_INVALID_VALUE";
	case CUBLAS_STATUS_ARCH_MISMATCH:
		return "CUBLAS_STATUS_ARCH_MISMATCH";
	case CUBLAS_STATUS_MAPPING_ERROR:
		return "CUBLAS_STATUS_MAPPING_ERROR";
	case CUBLAS_STATUS_EXECUTION_FAILED:
		return "CUBLAS_STATUS_EXECUTION_FAILED";
	case CUBLAS_STATUS_INTERNAL_ERROR:
		return "CUBLAS_STATUS_INTERNAL_ERROR";
	case CUBLAS_STATUS_NOT_SUPPORTED:
		return "CUBLAS_STATUS_NOT_SUPPORTED";
	case CUBLAS_STATUS_LICENSE_ERROR:
		return "CUBLAS_STATUS_LICENSE_ERROR";
	default:
		return "unknown CUBLAS status";
	}
}

static int cublas_check(cublasStatus_t status, const char *op)
{
	if (status == CUBLAS_STATUS_SUCCESS)
		return 0;

	fail("%s failed: %s", op, cublas_status_string(status));
	return -1;
}

static void simple_sgemm(float alpha, const float *a, const float *b, float beta, float *c)
{
	for (int row = 0; row < MATRIX_N; row++) {
		for (int col = 0; col < MATRIX_N; col++) {
			float prod = 0.0f;

			for (int k = 0; k < MATRIX_N; k++)
				prod += a[k * MATRIX_N + row] * b[col * MATRIX_N + k];
			c[col * MATRIX_N + row] = alpha * prod + beta * c[col * MATRIX_N + row];
		}
	}
}

static void cuda_cleanup(void)
{
	if (handle) {
		cublasDestroy(handle);
		handle = NULL;
	}
	if (cuda_c) {
		cudaFree(cuda_c);
		cuda_c = NULL;
	}
	if (cuda_b) {
		cudaFree(cuda_b);
		cuda_b = NULL;
	}
	if (cuda_a) {
		cudaFree(cuda_a);
		cuda_a = NULL;
	}
	free(host_ref);
	host_ref = NULL;
	free(host_c);
	host_c = NULL;
	free(host_b);
	host_b = NULL;
	free(host_a);
	host_a = NULL;
}

static int cuda_verify(void)
{
	double err_norm = 0.0;
	double ref_norm = 0.0;

	for (int i = 0; i < MATRIX_ELEMS; i++) {
		double diff = host_ref[i] - host_c[i];

		err_norm += diff * diff;
		ref_norm += host_ref[i] * host_ref[i];
	}

	if (ref_norm == 0.0) {
		fail("CUBLAS reference norm is zero");
		return -1;
	}
	if (sqrt(err_norm) / sqrt(ref_norm) > 1.0e-5) {
		fail("CUBLAS result mismatch: err_norm=%f ref_norm=%f", sqrt(err_norm), sqrt(ref_norm));
		return -1;
	}

	return 0;
}

static int cuda_run_sgemm(float beta)
{
	const float alpha = 1.0f;

	simple_sgemm(alpha, host_a, host_b, beta, host_ref);

	if (cublas_check(cublasSgemm(handle, CUBLAS_OP_N, CUBLAS_OP_N, MATRIX_N, MATRIX_N, MATRIX_N,
				    &alpha, cuda_a, MATRIX_N, cuda_b, MATRIX_N, &beta, cuda_c, MATRIX_N),
			 "cublasSgemm"))
		return -1;
	if (cublas_check(cublasGetVector(MATRIX_ELEMS, sizeof(host_c[0]), cuda_c, 1, host_c, 1),
			 "cublasGetVector cuda_c"))
		return -1;

	return cuda_verify();
}

static int cuda_prepare(void)
{
	size_t bytes = MATRIX_ELEMS * sizeof(float);

	if (cuda_zdtm_select_device(0))
		return -1;

	host_a = (float *)malloc(bytes);
	host_b = (float *)malloc(bytes);
	host_c = (float *)malloc(bytes);
	host_ref = (float *)malloc(bytes);
	if (!host_a || !host_b || !host_c || !host_ref) {
		fail("failed to allocate CUBLAS host matrices");
		return -1;
	}

	for (int i = 0; i < MATRIX_ELEMS; i++) {
		host_a[i] = (float)((i % 17) + 1) / 17.0f;
		host_b[i] = (float)((i % 13) + 1) / 13.0f;
		host_c[i] = 0.0f;
		host_ref[i] = 0.0f;
	}

	if (cuda_zdtm_check(cudaMalloc((void **)&cuda_a, bytes), "cudaMalloc cuda_a"))
		return -1;
	if (cuda_zdtm_check(cudaMalloc((void **)&cuda_b, bytes), "cudaMalloc cuda_b"))
		return -1;
	if (cuda_zdtm_check(cudaMalloc((void **)&cuda_c, bytes), "cudaMalloc cuda_c"))
		return -1;
	if (cublas_check(cublasCreate(&handle), "cublasCreate"))
		return -1;
	if (cublas_check(cublasSetVector(MATRIX_ELEMS, sizeof(host_a[0]), host_a, 1, cuda_a, 1),
			 "cublasSetVector cuda_a"))
		return -1;
	if (cublas_check(cublasSetVector(MATRIX_ELEMS, sizeof(host_b[0]), host_b, 1, cuda_b, 1),
			 "cublasSetVector cuda_b"))
		return -1;
	if (cublas_check(cublasSetVector(MATRIX_ELEMS, sizeof(host_c[0]), host_c, 1, cuda_c, 1),
			 "cublasSetVector cuda_c"))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_sgemm(0.0f))
		goto err;

	test_msg("CUDA CUBLAS workload ready on pid %d\n", getpid());
	test_daemon();
	test_waitsig();

	if (cuda_run_sgemm(1.0f))
		goto err;

	cuda_cleanup();
	pass();
	return 0;

err:
	cuda_cleanup();
	return 1;
}
