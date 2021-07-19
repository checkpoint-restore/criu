#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

#include <pthread.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <syscall.h>

#define min(x, y)                              \
	({                                     \
		typeof(x) _min1 = (x);         \
		typeof(y) _min2 = (y);         \
		(void)(&_min1 == &_min2);      \
		_min1 < _min2 ? _min1 : _min2; \
	})

#define max(x, y)                              \
	({                                     \
		typeof(x) _max1 = (x);         \
		typeof(y) _max2 = (y);         \
		(void)(&_max1 == &_max2);      \
		_max1 > _max2 ? _max1 : _max2; \
	})

#define MAX_CHUNK 4096
#define PAGE_SIZE 4096

#define pr_info(fmt, ...) printf("%8d: " fmt, sys_gettid(), ##__VA_ARGS__)

#define pr_err(fmt, ...) printf("%8d: Error (%s:%d): " fmt, sys_gettid(), __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_perror(fmt, ...) pr_err(fmt ": %m\n", ##__VA_ARGS__)

#define pr_msg(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define pr_trace(fmt, ...) printf("%8d: %s: " fmt, sys_gettid(), __func__, ##__VA_ARGS__)

enum {
	MEM_FILL_MODE_NONE = 0,
	MEM_FILL_MODE_ALL = 1,
	MEM_FILL_MODE_LIGHT = 2,
	MEM_FILL_MODE_DIRTIFY = 3,
};

typedef struct {
	pthread_mutex_t mutex;
	pthread_mutexattr_t mutex_attr;

	size_t opt_tasks;

	size_t opt_files;
	size_t opt_file_size;
	int prev_fd[MAX_CHUNK];

	size_t opt_mem;
	size_t opt_mem_chunks;
	size_t opt_mem_chunk_size;
	int opt_mem_fill_mode;
	int opt_mem_cycle_mode;
	unsigned int opt_refresh_time;

	char *opt_work_dir;
	int work_dir_fd;
	DIR *work_dir;

	pid_t err_pid;
	int err_no;

	unsigned long prev_map[MAX_CHUNK];
} shared_data_t;

static shared_data_t *shared;

static int sys_gettid(void)
{
	return syscall(__NR_gettid);
}

static void dirtify_memory(unsigned long *chunks, size_t nr_chunks, size_t chunk_size, int mode, const size_t nr_pages)
{
	size_t i;

	pr_trace("filling memory\n");
	switch (mode) {
	case MEM_FILL_MODE_LIGHT:
		*((unsigned long *)chunks[0]) = -1ul;
		break;
	case MEM_FILL_MODE_ALL:
		for (i = 0; i < nr_chunks; i++)
			memset((void *)chunks[i], (char)i, chunk_size);
		break;
	case MEM_FILL_MODE_DIRTIFY:
		for (i = 0; i < nr_chunks; i++)
			*((unsigned long *)chunks[i]) = -1ul;
		break;
	}
}

static void dirtify_files(int *fd, size_t nr_files, size_t size)
{
	size_t buf[8192];
	size_t i;

	/*
	 * Note we don't write any _sane_ data here, the only
	 * important thing is I/O activity by self.
	 */

	for (i = 0; i < nr_files; i++) {
		size_t c = min(size, sizeof(buf));
		size_t left = size;

		while (left > 0) {
			write(fd[i], buf, c);
			left -= c;
			c = min(left, sizeof(buf));
		}
	}
}

static int create_files(shared_data_t *shared, int *fd, size_t nr_files)
{
	char path[PATH_MAX];
	size_t i;

	memset(fd, 0xff, sizeof(*fd) * MAX_CHUNK);

	pr_info("\tCreating %lu files\n", shared->opt_files);

	for (i = 0; i < shared->opt_files; i++) {
		if (shared->prev_fd[i] != -1) {
			close(shared->prev_fd[i]);
			shared->prev_fd[i] = -1;
		}
		snprintf(path, sizeof(path), "%08d-%04d-temp", sys_gettid(), i);
		fd[i] = openat(shared->work_dir_fd, path, O_RDWR | O_CREAT | O_TRUNC, 0666);
		if (fd[i] < 0) {
			pr_perror("Can't open %s/%s", shared->opt_work_dir, path);
			shared->err_pid = sys_gettid();
			shared->err_no = -errno;
			return -1;
		}
		shared->prev_fd[i] = fd[i];
	}

	return 0;
}

static void work_on_fork(shared_data_t *shared)
{
	const size_t nr_pages = shared->opt_mem_chunk_size / PAGE_SIZE;
	unsigned long chunks[MAX_CHUNK] = {};
	int fd[MAX_CHUNK];
	size_t i;
	void *mem;

	pr_trace("locking\n");
	pthread_mutex_lock(&shared->mutex);
	pr_trace("init\n");

	pr_info("\tCreating %lu mmaps each %lu K\n", shared->opt_mem_chunks, shared->opt_mem_chunk_size >> 10);

	for (i = 0; i < shared->opt_mem_chunks; i++) {
		if (shared->prev_map[i]) {
			munmap((void *)shared->prev_map[i], shared->opt_mem_chunk_size);
			shared->prev_map[i] = 0;
		}

		/* If we won't change proto here, the kernel might merge close areas */
		mem = mmap(NULL, shared->opt_mem_chunk_size, PROT_READ | PROT_WRITE | ((i % 2) ? PROT_EXEC : 0),
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

		if (mem != (void *)MAP_FAILED) {
			shared->prev_map[i] = (unsigned long)mem;
			chunks[i] = (unsigned long)mem;

			pr_info("\t\tMap at %lx\n", (unsigned long)mem);
		} else {
			pr_info("\t\tCan't map\n");

			shared->err_pid = sys_gettid();
			shared->err_no = -errno;
			exit(1);
		}
	}

	if (shared->opt_mem_fill_mode)
		dirtify_memory(chunks, shared->opt_mem_chunks, shared->opt_mem_chunk_size, shared->opt_mem_fill_mode,
			       nr_pages);

	if (create_files(shared, fd, shared->opt_files))
		exit(1);

	if (shared->opt_file_size)
		dirtify_files(fd, shared->opt_files, shared->opt_file_size);

	pr_trace("releasing\n");
	pthread_mutex_unlock(&shared->mutex);

	while (1) {
		sleep(shared->opt_refresh_time);
		if (shared->opt_mem_cycle_mode)
			dirtify_memory(chunks, shared->opt_mem_chunks, shared->opt_mem_chunk_size,
				       shared->opt_mem_cycle_mode, nr_pages);
		if (shared->opt_file_size)
			dirtify_files(fd, shared->opt_files, shared->opt_file_size);
	}
}

static int parse_mem_mode(int *mode, char *opt)
{
	if (!strcmp(opt, "all")) {
		*mode = MEM_FILL_MODE_ALL;
	} else if (!strcmp(opt, "light")) {
		*mode = MEM_FILL_MODE_LIGHT;
	} else if (!strcmp(opt, "dirtify")) {
		*mode = MEM_FILL_MODE_DIRTIFY;
	} else {
		pr_err("Unrecognized option %s\n", opt);
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	/* a - 97, z - 122, A - 65, 90 */
	static const char short_opts[] = "t:d:f:m:c:h";
	static struct option long_opts[] = {
		{ "tasks", required_argument, 0, 't' },
		{ "dir", required_argument, 0, 'd' },
		{ "files", required_argument, 0, 'f' },
		{ "memory", required_argument, 0, 'm' },
		{ "mem-chunks", required_argument, 0, 'c' },
		{ "help", no_argument, 0, 'h' },
		{ "mem-fill", required_argument, 0, 10 },
		{ "mem-cycle", required_argument, 0, 11 },
		{ "refresh", required_argument, 0, 12 },
		{ "file-size", required_argument, 0, 13 },
		{},
	};

	char workdir[PATH_MAX];
	int opt, idx, pidfd;
	char pidbuf[32];
	pid_t pid;
	size_t i;

	shared = (void *)mmap(NULL, sizeof(*shared), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if ((void *)shared == MAP_FAILED) {
		pr_err("Failed to setup shared data\n");
		exit(1);
	}

	pthread_mutexattr_init(&shared->mutex_attr);
	pthread_mutexattr_setpshared(&shared->mutex_attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&shared->mutex, &shared->mutex_attr);

	/*
	 * Default options.
	 */
	shared->opt_mem_chunks = 1;
	shared->opt_refresh_time = 1;
	shared->opt_tasks = 1;
	shared->opt_mem = 1 << 20ul;
	memset(shared->prev_fd, 0xff, sizeof(shared->prev_fd));

	while (1) {
		idx = -1;
		opt = getopt_long(argc, argv, short_opts, long_opts, &idx);
		if (opt == -1)
			break;

		switch (opt) {
		case 't':
			shared->opt_tasks = (size_t)atol(optarg);
			break;
		case 'f':
			shared->opt_files = (size_t)atol(optarg);
			break;
		case 'm':
			/* In megabytes */
			shared->opt_mem = (size_t)atol(optarg) << 20ul;
			break;
		case 'c':
			shared->opt_mem_chunks = (size_t)atol(optarg);
			break;
		case 'd':
			shared->opt_work_dir = optarg;
			break;
		case 'h':
			goto usage;
			break;
		case 10:
			if (parse_mem_mode(&shared->opt_mem_fill_mode, optarg))
				goto usage;
		case 11:
			if (parse_mem_mode(&shared->opt_mem_cycle_mode, optarg))
				goto usage;
			break;
		case 12:
			shared->opt_refresh_time = (unsigned int)atoi(optarg);
			break;
		case 13:
			shared->opt_file_size = (size_t)atol(optarg);
		}
	}

	if (!shared->opt_work_dir) {
		shared->opt_work_dir = getcwd(workdir, sizeof(workdir));
		if (!shared->opt_work_dir) {
			pr_perror("Can't fetch current working dir");
			exit(1);
		}
		shared->opt_work_dir = workdir;
	}

	if (shared->opt_mem_chunks > MAX_CHUNK)
		shared->opt_mem_chunks = MAX_CHUNK;

	if (shared->opt_files > MAX_CHUNK)
		shared->opt_files = MAX_CHUNK;

	shared->work_dir = opendir(shared->opt_work_dir);
	if (!shared->work_dir) {
		pr_perror("Can't open working dir `%s'", shared->opt_work_dir);
		exit(1);
	}
	shared->work_dir_fd = dirfd(shared->work_dir);

	shared->opt_mem_chunk_size = shared->opt_mem / shared->opt_mem_chunks;

	if (shared->opt_mem_chunk_size && shared->opt_mem_chunk_size < PAGE_SIZE) {
		pr_err("Memory chunk size is too small, provide at least %lu M of memory\n",
		       (shared->opt_mem_chunks * PAGE_SIZE) >> 20ul);
		exit(1);
	}

	for (i = 0; i < shared->opt_tasks; i++) {
		if (shared->err_no)
			goto err_child;

		pid = fork();
		if (pid < 0) {
			pr_perror("Can't fork");
			exit(1);
		} else if (pid == 0) {
			work_on_fork(shared);
		}
	}

	/*
	 * Once everything is done and we're in cycle,
	 * create pidfile and go to sleep...
	 */
	pid = sys_gettid();
	pidfd = openat(shared->work_dir_fd, "bers.pid", O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (pidfd < 0) {
		pr_perror("Can't open pidfile");
		exit(1);
	}
	snprintf(pidbuf, sizeof(pidbuf), "%d", sys_gettid());
	write(pidfd, pidbuf, strlen(pidbuf));
	close(pidfd);
	pidfd = -1;

	/*
	 * Endless!
	 */
	while (!shared->err_no)
		sleep(1);

err_child:
	pr_err("Child %d exited with %d\n", shared->err_pid, shared->err_no);
	return shared->err_no;

usage:
	pr_msg("bers [options]\n");
	pr_msg("    -t|--tasks <num>         create <num> of tasks\n");
	pr_msg("    -d|--dir <dir>           use directory <dir> for temporary files\n");
	pr_msg("    -f|--files <num>         create <num> files for each task\n");
	pr_msg("    -m|--memory <num>        allocate <num> megabytes for each task\n");
	pr_msg("    --memory-chunks <num>    split memory to <num> equal parts\n");
	pr_msg("    --mem-fill <mode>        fill memory with data dependin on <mode>:\n");
	pr_msg("                all          fill every byte of memory\n");
	pr_msg("                light        fill first bytes of every page\n");
	pr_msg("                dirtify      fill every page\n");
	pr_msg("    --mem-cycle <mode>       same as --mem-fill but for cycling\n");
	pr_msg("    --refresh <second>       refresh loading of every task each <second>\n");
	pr_msg("    --file-size <bytes>      write <bytes> of data into each file on every refresh cycle\n");

	return 1;
}
