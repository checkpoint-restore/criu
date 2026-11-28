#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>

#include <vector>

#include "cuda_zdtm.h"

#ifdef CUDA_FORK_OWN_DEVICE
const char *test_doc = "Check that a forked process holding NVIDIA state it did not inherit is refused";
#else
const char *test_doc = "Check a process forked after CUDA started survives checkpoint/restore without its parent's GPU state";
#endif
const char *test_author = "Radostin Stoyanov <rstoyanov@fedoraproject.org>";

#define NR_ELEMS 4096

static uint32_t *cuda_data;

__global__ static void cuda_step(uint32_t *data, unsigned int n, uint32_t addend)
{
	unsigned int i = blockDim.x * blockIdx.x + threadIdx.x;

	if (i < n)
		data[i] += addend;
}

static int cuda_run_step(uint32_t addend)
{
	cuda_step<<<cuda_zdtm_grid(NR_ELEMS), CUDA_ZDTM_THREADS>>>(cuda_data, NR_ELEMS, addend);
	if (cuda_zdtm_check(cudaPeekAtLastError(), "cuda_step launch"))
		return -1;
	return cuda_zdtm_check(cudaDeviceSynchronize(), "cudaDeviceSynchronize");
}

static int cuda_verify(uint32_t expected_addend)
{
	uint32_t host[NR_ELEMS];

	if (cuda_zdtm_check(cudaMemcpy(host, cuda_data, sizeof(host), cudaMemcpyDeviceToHost), "cudaMemcpy"))
		return -1;
	for (unsigned int i = 0; i < NR_ELEMS; i++) {
		if (host[i] != i + expected_addend) {
			fail("CUDA data mismatch at %u: got %u expected %u", i, host[i], i + expected_addend);
			return -1;
		}
	}
	return 0;
}

static int cuda_prepare(void)
{
	uint32_t host[NR_ELEMS];

	if (cuda_zdtm_select_device(0))
		return -1;
	for (unsigned int i = 0; i < NR_ELEMS; i++)
		host[i] = i;
	if (cuda_zdtm_check(cudaMalloc((void **)&cuda_data, sizeof(host)), "cudaMalloc"))
		return -1;
	return cuda_zdtm_check(cudaMemcpy(cuda_data, host, sizeof(host), cudaMemcpyHostToDevice), "cudaMemcpy");
}

/* The number of mappings of NVIDIA device files in this process. */
static int nvidia_mappings(void)
{
	char line[4096];
	int nr = 0;
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		pr_perror("Can't open /proc/self/maps");
		return -1;
	}
	while (fgets(line, sizeof(line), maps))
		if (strstr(line, " /dev/nvidia"))
			nr++;
	if (ferror(maps)) {
		pr_perror("Can't read /proc/self/maps");
		nr = -1;
	}
	fclose(maps);
	return nr;
}

/* The descriptors of this process open on NVIDIA device files. */
static int nvidia_fds(std::vector<int> &fds)
{
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *de;
	int ret = -1;

	if (!dir) {
		pr_perror("Can't open /proc/self/fd");
		return -1;
	}
	for (;;) {
		char target[PATH_MAX];
		char *end;

		errno = 0;
		de = readdir(dir);
		if (!de) {
			if (errno) {
				pr_perror("Can't enumerate /proc/self/fd");
				goto out;
			}
			break;
		}
		long fd = strtol(de->d_name, &end, 10);

		if (end == de->d_name || *end || fd < 0 || fd > INT_MAX)
			continue;
		ssize_t len = readlinkat(dirfd(dir), de->d_name, target, sizeof(target) - 1);
		if (len < 0) {
			pr_perror("Can't read /proc/self/fd/%ld", fd);
			goto out;
		}
		target[len] = '\0';
		if (!strncmp(target, "/dev/nvidia", strlen("/dev/nvidia")))
			fds.push_back(fd);
	}
	ret = 0;
out:
	closedir(dir);
	return ret;
}

/*
 * The forked process inherits the parent's CUDA mappings and descriptors but
 * not its CUDA state, so it never calls CUDA. After restore it must have no
 * NVIDIA mapping, and each inherited descriptor must still be open, on
 * /dev/null.
 *
 * With CUDA_FORK_OWN_DEVICE the forked process also opens an NVIDIA device
 * itself. That descriptor is not its parent's, so the dump must fail
 * (cuda_fork01).
 */
static int forked_process(int wait_fd)
{
	std::vector<int> fds;
	int nr_maps = nvidia_mappings();
	char c;

	if (nvidia_fds(fds) || fds.empty() || nr_maps <= 0) {
		pr_err("Expected the forked process to inherit both NVIDIA mappings and descriptors\n");
		return 1;
	}
	test_msg("Forked process %d inherited %d NVIDIA mappings and %zu descriptors\n", getpid(), nr_maps, fds.size());

#ifdef CUDA_FORK_OWN_DEVICE
	if (open("/dev/nvidiactl", O_RDWR) < 0) {
		pr_perror("Can't open /dev/nvidiactl");
		return 1;
	}
#endif
	if (write(wait_fd, "r", 1) != 1) {
		pr_perror("Can't signal readiness");
		return 1;
	}
	if (read(wait_fd, &c, 1) != 1) {
		pr_perror("Can't wait for the parent");
		return 1;
	}
#ifdef CUDA_FORK_OWN_DEVICE
	/* The dump failed and the tasks resumed, so nothing was restored. */
	return 0;
#endif

	nr_maps = nvidia_mappings();
	if (nr_maps != 0) {
		pr_err("The forked process still has %d NVIDIA mappings after restore\n", nr_maps);
		return 1;
	}
	for (int fd : fds) {
		struct stat st;

		if (fstat(fd, &st)) {
			pr_perror("Inherited descriptor %d is closed after restore", fd);
			return 1;
		}
		if (!S_ISCHR(st.st_mode) || major(st.st_rdev) != 1 || minor(st.st_rdev) != 3) {
			pr_err("Inherited descriptor %d is %u:%u, not /dev/null\n", fd, major(st.st_rdev),
			       minor(st.st_rdev));
			return 1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	int sock[2], status;
	char ready;
	pid_t pid;

	test_init(argc, argv);

	if (cuda_prepare() || cuda_run_step(17) || cuda_verify(17))
		return 1;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sock)) {
		pr_perror("socketpair");
		return 1;
	}
	pid = fork();
	if (pid < 0) {
		pr_perror("fork");
		return 1;
	}
	if (pid == 0) {
		close(sock[1]);
		_exit(forked_process(sock[0]));
	}
	close(sock[0]);
	if (read(sock[1], &ready, 1) != 1) {
		fail("The forked process did not finish setting up its NVIDIA state");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (cuda_run_step(23) || cuda_verify(40))
		return 1;

	if (write(sock[1], "x", 1) != 1) {
		pr_perror("Can't release the forked process");
		return 1;
	}
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("waitpid");
		return 1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		fail("The forked process failed after restore (status %#x)", status);
		return 1;
	}

	cudaFree(cuda_data);
	pass();
	return 0;
}
