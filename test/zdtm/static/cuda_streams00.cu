#include "cuda_zdtm.h"

#include <atomic>
#include <thread>

const char *test_doc =
	"Check CUDA work on a secondary host thread, streams, events, and pinned host memory survive checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define NR_ELEMS 8192
#define WORKER_ELEMS 1024

static uint32_t *host_data;
static uint32_t *cuda_data;
static cudaStream_t stream;
static cudaEvent_t event;
static uint32_t *worker_data;
static cudaStream_t worker_stream;
static std::atomic<bool> worker_stop(false);
static std::atomic<int> worker_error(cudaSuccess);
static std::atomic<unsigned long> worker_requests(1);
static std::atomic<unsigned long> worker_iterations(0);
static std::thread worker;

__global__ static void cuda_stream_step(uint32_t *data, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		data[i] += addend;
}

static void cuda_cleanup(void)
{
	worker_stop.store(true, std::memory_order_relaxed);
	if (worker.joinable())
		worker.join();
	if (worker_stream) {
		cudaStreamDestroy(worker_stream);
		worker_stream = NULL;
	}
	if (worker_data) {
		cudaFree(worker_data);
		worker_data = NULL;
	}
	if (event) {
		cudaEventDestroy(event);
		event = NULL;
	}
	if (stream) {
		cudaStreamDestroy(stream);
		stream = NULL;
	}
	if (cuda_data) {
		cudaFree(cuda_data);
		cuda_data = NULL;
	}
	if (host_data) {
		cudaFreeHost(host_data);
		host_data = NULL;
	}
}

static void cuda_worker(void)
{
	cudaError_t err;
	uint32_t value = 0;

	err = cudaSetDevice(0);
	while (err == cudaSuccess && !worker_stop.load(std::memory_order_relaxed)) {
		if (worker_iterations.load(std::memory_order_relaxed) >=
		    worker_requests.load(std::memory_order_relaxed)) {
			usleep(1000);
			continue;
		}

		err = cudaMemsetAsync(worker_data, value++, WORKER_ELEMS * sizeof(*worker_data), worker_stream);
		if (err == cudaSuccess)
			err = cudaStreamSynchronize(worker_stream);
		if (err == cudaSuccess)
			worker_iterations.fetch_add(1, std::memory_order_relaxed);
	}

	worker_error.store(err, std::memory_order_relaxed);
}

static int cuda_wait_for_worker(unsigned long previous_iterations)
{
	for (unsigned int i = 0; i < 10000; i++) {
		cudaError_t err = (cudaError_t)worker_error.load(std::memory_order_relaxed);

		if (err != cudaSuccess) {
			fail("concurrent CUDA worker failed: %s", cudaGetErrorString(err));
			return -1;
		}
		if (worker_iterations.load(std::memory_order_relaxed) > previous_iterations)
			return 0;
		usleep(1000);
	}

	fail("concurrent CUDA worker made no progress");
	return -1;
}

static int cuda_verify(uint32_t expected_addend)
{
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		uint32_t expected = i + expected_addend;

		if (host_data[i] != expected) {
			fail("CUDA stream data mismatch at %u: got %u expected %u", i, host_data[i], expected);
			return -1;
		}
	}

	return 0;
}

static int cuda_run_step(uint32_t addend, uint32_t expected_addend)
{
	unsigned int grid = cuda_zdtm_grid(NR_ELEMS);

	cuda_stream_step<<<grid, CUDA_ZDTM_THREADS, 0, stream>>>(cuda_data, NR_ELEMS, addend);
	if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_stream_step launch"))
		return -1;
	if (cuda_zdtm_check(cudaMemcpyAsync(host_data, cuda_data, NR_ELEMS * sizeof(*host_data),
					   cudaMemcpyDeviceToHost, stream),
			    "cudaMemcpyAsync device to host"))
		return -1;
	if (cuda_zdtm_check(cudaEventRecord(event, stream), "cudaEventRecord"))
		return -1;
	if (cuda_zdtm_check(cudaEventSynchronize(event), "cudaEventSynchronize"))
		return -1;

	return cuda_verify(expected_addend);
}

static int cuda_prepare(void)
{
	if (cuda_zdtm_select_device(0))
		return -1;

	if (cuda_zdtm_check(cudaMallocHost((void **)&host_data, NR_ELEMS * sizeof(*host_data)), "cudaMallocHost"))
		return -1;
	for (unsigned int i = 0; i < NR_ELEMS; i++)
		host_data[i] = i;

	if (cuda_zdtm_check(cudaMalloc((void **)&cuda_data, NR_ELEMS * sizeof(*cuda_data)), "cudaMalloc"))
		return -1;
	if (cuda_zdtm_check(cudaMalloc((void **)&worker_data, WORKER_ELEMS * sizeof(*worker_data)), "cudaMalloc"))
		return -1;
	if (cuda_zdtm_check(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreateWithFlags"))
		return -1;
	if (cuda_zdtm_check(cudaStreamCreateWithFlags(&worker_stream, cudaStreamNonBlocking),
			    "cudaStreamCreateWithFlags"))
		return -1;
	if (cuda_zdtm_check(cudaEventCreateWithFlags(&event, cudaEventDisableTiming), "cudaEventCreateWithFlags"))
		return -1;
	if (cuda_zdtm_check(cudaMemcpyAsync(cuda_data, host_data, NR_ELEMS * sizeof(*host_data),
					   cudaMemcpyHostToDevice, stream),
			    "cudaMemcpyAsync host to device"))
		return -1;
	if (cuda_zdtm_check(cudaStreamSynchronize(stream), "cudaStreamSynchronize"))
		return -1;

	worker = std::thread(cuda_worker);
	if (cuda_wait_for_worker(0))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	unsigned long previous_iterations;

	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_step(17, 17))
		goto err;

	test_msg("CUDA stream workload ready on pid %d\n", getpid());
	test_daemon();
	test_waitsig();

	previous_iterations = worker_iterations.load(std::memory_order_relaxed);
	worker_requests.fetch_add(1, std::memory_order_relaxed);
	if (cuda_wait_for_worker(previous_iterations))
		goto err;

	if (cuda_run_step(23, 40))
		goto err;

	cuda_cleanup();
	pass();
	return 0;

err:
	cuda_cleanup();
	return 1;
}
