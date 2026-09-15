#include "cuda_zdtm.h"

const char *test_doc = "Check CUDA graph execution state survives checkpoint/restore";
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define NR_ELEMS 8192
#define GRAPH_ADDEND 17

static uint32_t *host_data;
static uint32_t *cuda_data;
static cudaStream_t stream;
static cudaGraph_t graph;
static cudaGraphExec_t graph_exec;

__global__ static void cuda_graph_step(uint32_t *data, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		data[i] += addend;
}

static void cuda_cleanup(void)
{
	if (graph_exec) {
		cudaGraphExecDestroy(graph_exec);
		graph_exec = NULL;
	}
	if (graph) {
		cudaGraphDestroy(graph);
		graph = NULL;
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

static int cuda_verify(uint32_t expected_addend)
{
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		uint32_t expected = i + expected_addend;

		if (host_data[i] != expected) {
			fail("CUDA graph data mismatch at %u: got %u expected %u", i, host_data[i], expected);
			return -1;
		}
	}

	return 0;
}

static int cuda_build_graph(void)
{
	unsigned int grid = cuda_zdtm_grid(NR_ELEMS);

	if (cuda_zdtm_check(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal), "cudaStreamBeginCapture"))
		return -1;

	cuda_graph_step<<<grid, CUDA_ZDTM_THREADS, 0, stream>>>(cuda_data, NR_ELEMS, GRAPH_ADDEND);
	if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_graph_step launch"))
		return -1;
	if (cuda_zdtm_check(cudaMemcpyAsync(host_data, cuda_data, NR_ELEMS * sizeof(*host_data),
					   cudaMemcpyDeviceToHost, stream),
			    "cudaMemcpyAsync device to host"))
		return -1;
	if (cuda_zdtm_check(cudaStreamEndCapture(stream, &graph), "cudaStreamEndCapture"))
		return -1;
	if (cuda_zdtm_check(cudaGraphInstantiate(&graph_exec, graph, NULL, NULL, 0), "cudaGraphInstantiate"))
		return -1;

	return 0;
}

static int cuda_run_graph(uint32_t expected_addend)
{
	if (cuda_zdtm_check(cudaGraphLaunch(graph_exec, stream), "cudaGraphLaunch"))
		return -1;
	if (cuda_zdtm_check(cudaStreamSynchronize(stream), "cudaStreamSynchronize"))
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
	if (cuda_zdtm_check(cudaMemcpy(cuda_data, host_data, NR_ELEMS * sizeof(*host_data), cudaMemcpyHostToDevice),
			    "cudaMemcpy host to device"))
		return -1;
	if (cuda_zdtm_check(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), "cudaStreamCreateWithFlags"))
		return -1;

	return cuda_build_graph();
}

int main(int argc, char **argv)
{
	test_init(argc, argv);

	if (cuda_prepare())
		goto err;

	if (cuda_run_graph(GRAPH_ADDEND))
		goto err;

	test_msg("CUDA graph workload ready on pid %d\n", getpid());
	test_daemon();
	test_waitsig();

	if (cuda_run_graph(GRAPH_ADDEND * 2))
		goto err;

	cuda_cleanup();
	pass();
	return 0;

err:
	cuda_cleanup();
	return 1;
}
