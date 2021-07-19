#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include "zdtmtst.h"
#include "lock.h"

const char *test_doc = "ps tree with anon shared vmas for dedup";

/*
 * 1. ps tree with non triavial anon shmem vmas is created first.
 * 2. Each process gets its portion of shmem vmas.
 * 3. Each process continuously datagens its portion until
 *    criu dump is finished.
 * 4. Each process datachecks all its shmem portions after restore.
 * 5. Contents of anon shmem vmas are checked for equality in
 *    different processes.
 */

typedef int (*proc_func_t)(task_waiter_t *setup_waiter);

static pid_t fork_and_setup(proc_func_t pfunc)
{
	task_waiter_t setup_waiter;
	pid_t pid;

	task_waiter_init(&setup_waiter);
	pid = test_fork();
	if (pid < 0) {
		pr_perror("fork failed");
		exit(1);
	}

	if (pid == 0)
		exit(pfunc(&setup_waiter));

	task_waiter_wait4(&setup_waiter, pid);
	task_waiter_fini(&setup_waiter);
	return pid;
}

static void cont_and_wait_child(pid_t pid)
{
	int status;

	kill(pid, SIGTERM);
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status))
			exit(WEXITSTATUS(status));
	} else
		exit(1);
}

static void *mmap_ashmem(size_t size)
{
	void *mem = mmap(NULL, size, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't map shmem %zx", size);
		exit(1);
	}
	return mem;
}

static void *mmap_proc_mem(pid_t pid, unsigned long addr, unsigned long size)
{
	int fd;
	void *mem;
	char path[PATH_MAX];

	snprintf(path, PATH_MAX, "/proc/%d/map_files/%lx-%lx", (int)pid, addr, addr + size);
	fd = open(path, O_RDWR);
	if (fd == -1) {
		pr_perror("Can't open file %s", path);
		exit(1);
	}

	mem = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (mem == MAP_FAILED) {
		pr_perror("Can't map file %s", path);
		exit(1);
	}
	return mem;
}

static void check_mem_eq(void *addr1, size_t size1, void *addr2, size_t size2)
{
	unsigned long min_size = size1 < size2 ? size1 : size2;

	if (memcmp(addr1, addr2, min_size)) {
		pr_err("Mem differs %lx %lx %lx\n", (unsigned long)addr1, (unsigned long)addr2, min_size);
		exit(1);
	}
}

static void xmunmap(void *map, size_t size)
{
	if (munmap(map, size)) {
		pr_perror("xmunmap");
		exit(1);
	}
}

static void chk_proc_mem_eq(pid_t pid1, void *addr1, unsigned long size1, pid_t pid2, void *addr2, unsigned long size2)
{
	void *map1, *map2;

	map1 = mmap_proc_mem(pid1, (unsigned long)addr1, size1);
	map2 = mmap_proc_mem(pid2, (unsigned long)addr2, size2);
	check_mem_eq(map1, size1, map2, size2);
	xmunmap(map1, size1);
	xmunmap(map2, size2);
}

/*
 * ps tree:
 * proc1_______________
 * |          |       |
 * proc11___  proc12  proc13
 * |       |          |
 * proc111 proc112    proc131
 */
#define PROC_CNT 7

#define PROC1_PGIX   0
#define PROC11_PGIX  1
#define PROC12_PGIX  2
#define PROC13_PGIX  3
#define PROC111_PGIX 4
#define PROC112_PGIX 5
#define PROC131_PGIX 6
#define ZERO_PGIX    7
/* unused pgix: 8 */
#define MEM_PERIOD (9 * PAGE_SIZE)

struct pstree {
	pid_t proc1;
	pid_t proc11;
	pid_t proc12;
	pid_t proc13;
	pid_t proc111;
	pid_t proc112;
	pid_t proc131;
};
struct pstree *pstree;

struct test_sync {
	futex_t datagen;
	futex_t datagen_exit_cnt;
};
struct test_sync *test_sync;

size_t mem1_size, mem2_size, mem3_size;
uint8_t *mem1, *mem2, *mem3;

#define CRC_EPOCH_OFFSET (PAGE_SIZE - sizeof(uint32_t))

static void read_each_pg(volatile uint8_t *mem, size_t size, size_t off)
{
	if (!mem)
		return;

	while (off < size) {
		(mem + off)[0];
		off += MEM_PERIOD;
	}
}

void datagen_each_pg(uint8_t *mem, size_t size, size_t off, uint32_t crc_epoch)
{
	if (!mem)
		return;

	while (futex_get(&test_sync->datagen) && (off < size)) {
		uint32_t crc = crc_epoch;

		datagen(mem + off, CRC_EPOCH_OFFSET, &crc);
		*(uint32_t *)(mem + off + CRC_EPOCH_OFFSET) = crc_epoch;
		off += MEM_PERIOD;
	}
}

void datachck_each_pg(uint8_t *mem, size_t size, size_t off)
{
	if (!mem)
		return;

	while (off < size) {
		uint32_t crc = *(uint32_t *)(mem + off + CRC_EPOCH_OFFSET);

		if (datachk(mem + off, CRC_EPOCH_OFFSET, &crc))
			exit(1);
		off += MEM_PERIOD;
	}
}

static void mems_read_each_pgix(size_t pgix)
{
	const size_t off = pgix * PAGE_SIZE;

	read_each_pg(mem1, mem1_size, off);
	read_each_pg(mem2, mem2_size, off);
	read_each_pg(mem3, mem3_size, off);
}

static void mems_datagen_each_pgix(size_t pgix, uint32_t *crc_epoch)
{
	const size_t off = pgix * PAGE_SIZE;

	++(*crc_epoch);
	datagen_each_pg(mem1, mem1_size, off, *crc_epoch);
	datagen_each_pg(mem2, mem2_size, off, *crc_epoch);
	datagen_each_pg(mem3, mem3_size, off, *crc_epoch);
}

static void mems_datachck_each_pgix(size_t pgix)
{
	const size_t off = pgix * PAGE_SIZE;

	datachck_each_pg(mem1, mem1_size, off);
	datachck_each_pg(mem2, mem2_size, off);
	datachck_each_pg(mem3, mem3_size, off);
}

static int proc131_func(task_waiter_t *setup_waiter)
{
	uint32_t crc_epoch = 0;

	pstree->proc131 = getpid();
	mems_datagen_each_pgix(PROC131_PGIX, &crc_epoch);
	task_waiter_complete_current(setup_waiter);

	while (futex_get(&test_sync->datagen))
		mems_datagen_each_pgix(PROC131_PGIX, &crc_epoch);
	futex_inc_and_wake(&test_sync->datagen_exit_cnt);
	test_waitsig();

	mems_datachck_each_pgix(PROC131_PGIX);
	return 0;
}

static int proc13_func(task_waiter_t *setup_waiter)
{
	size_t MEM1_HOLE_START = 2 * MEM_PERIOD;
	size_t MEM1_HOLE_SIZE = 1 * MEM_PERIOD;
	uint32_t crc_epoch = 0;

	pstree->proc13 = getpid();
	xmunmap(mem1 + MEM1_HOLE_START, MEM1_HOLE_SIZE);
	xmunmap(mem2, mem2_size);
	xmunmap(mem3, mem3_size);
	mem2 = mem1 + MEM1_HOLE_START + MEM1_HOLE_SIZE;
	mem2_size = mem1_size - (mem2 - mem1);
	mem1_size = MEM1_HOLE_START;
	mem3 = mmap_ashmem(mem3_size);
	mems_datagen_each_pgix(PROC13_PGIX, &crc_epoch);
	fork_and_setup(proc131_func);
	task_waiter_complete_current(setup_waiter);

	while (futex_get(&test_sync->datagen))
		mems_datagen_each_pgix(PROC13_PGIX, &crc_epoch);
	futex_inc_and_wake(&test_sync->datagen_exit_cnt);
	test_waitsig();

	mems_datachck_each_pgix(PROC13_PGIX);

	chk_proc_mem_eq(pstree->proc13, mem1, mem1_size, pstree->proc131, mem1, mem1_size);
	chk_proc_mem_eq(pstree->proc13, mem2, mem2_size, pstree->proc131, mem2, mem2_size);
	chk_proc_mem_eq(pstree->proc13, mem3, mem3_size, pstree->proc131, mem3, mem3_size);

	cont_and_wait_child(pstree->proc131);
	return 0;
}

static int proc12_func(task_waiter_t *setup_waiter)
{
	uint32_t crc_epoch = 0;

	pstree->proc12 = getpid();
	mems_datagen_each_pgix(PROC12_PGIX, &crc_epoch);
	task_waiter_complete_current(setup_waiter);

	while (futex_get(&test_sync->datagen))
		mems_datagen_each_pgix(PROC12_PGIX, &crc_epoch);
	futex_inc_and_wake(&test_sync->datagen_exit_cnt);
	test_waitsig();

	mems_datachck_each_pgix(PROC12_PGIX);

	return 0;
}

static int proc111_func(task_waiter_t *setup_waiter)
{
	uint32_t crc_epoch = 0;

	pstree->proc111 = getpid();
	mems_datagen_each_pgix(PROC111_PGIX, &crc_epoch);
	task_waiter_complete_current(setup_waiter);

	while (futex_get(&test_sync->datagen))
		mems_datagen_each_pgix(PROC111_PGIX, &crc_epoch);
	futex_inc_and_wake(&test_sync->datagen_exit_cnt);
	test_waitsig();

	mems_datachck_each_pgix(PROC111_PGIX);
	return 0;
}

static int proc112_func(task_waiter_t *setup_waiter)
{
	uint32_t crc_epoch = 0;

	pstree->proc112 = getpid();
	mems_datagen_each_pgix(PROC112_PGIX, &crc_epoch);
	task_waiter_complete_current(setup_waiter);

	while (futex_get(&test_sync->datagen))
		mems_datagen_each_pgix(PROC112_PGIX, &crc_epoch);
	futex_inc_and_wake(&test_sync->datagen_exit_cnt);
	test_waitsig();

	mems_datachck_each_pgix(PROC112_PGIX);
	return 0;
}

static int proc11_func(task_waiter_t *setup_waiter)
{
	const size_t MEM3_START_CUT = 1 * MEM_PERIOD;
	const size_t MEM3_END_CUT = 2 * MEM_PERIOD;
	void *mem3_old = mem3;
	size_t mem3_size_old = mem3_size;
	uint32_t crc_epoch = 0;
	uint8_t *proc1_mem3;

	pstree->proc11 = getpid();
	xmunmap(mem3, MEM3_START_CUT);
	mem3 += MEM3_START_CUT;
	mem3_size -= MEM3_START_CUT;
	fork_and_setup(proc111_func);
	fork_and_setup(proc112_func);
	xmunmap(mem3 + mem3_size - MEM3_END_CUT, MEM3_END_CUT);
	mem3_size -= MEM3_END_CUT;
	mems_datagen_each_pgix(PROC11_PGIX, &crc_epoch);
	task_waiter_complete_current(setup_waiter);

	while (futex_get(&test_sync->datagen))
		mems_datagen_each_pgix(PROC11_PGIX, &crc_epoch);
	futex_inc_and_wake(&test_sync->datagen_exit_cnt);
	test_waitsig();

	mems_datachck_each_pgix(PROC11_PGIX);

	chk_proc_mem_eq(pstree->proc11, mem1, mem1_size, pstree->proc111, mem1, mem1_size);
	chk_proc_mem_eq(pstree->proc11, mem1, mem1_size, pstree->proc112, mem1, mem1_size);

	chk_proc_mem_eq(pstree->proc11, mem2, mem2_size, pstree->proc111, mem2, mem2_size);
	chk_proc_mem_eq(pstree->proc11, mem2, mem2_size, pstree->proc112, mem2, mem2_size);

	chk_proc_mem_eq(pstree->proc11, mem3, mem3_size, pstree->proc111, mem3, mem3_size + MEM3_END_CUT);
	chk_proc_mem_eq(pstree->proc11, mem3, mem3_size, pstree->proc112, mem3, mem3_size + MEM3_END_CUT);

	proc1_mem3 = mmap_proc_mem(pstree->proc1, (unsigned long)mem3_old, mem3_size_old);
	check_mem_eq(mem3, mem3_size, proc1_mem3 + MEM3_START_CUT, mem3_size);
	xmunmap(proc1_mem3, mem3_size_old);

	cont_and_wait_child(pstree->proc111);
	cont_and_wait_child(pstree->proc112);
	return 0;
}

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MB(n)	  ((n) * (1UL << 20))

static int proc1_func(void)
{
	uint32_t crc_epoch = 0;
	uint8_t *mem2_old = NULL;

	/*
	 * Min mem size:
	 * At least 5 mem periods for mem pages and vma holes.
	 * At least 1 MB mem size not to test on tiny working set.
	 */
	mem1_size = MEM_PERIOD * MAX(5, MB(1) / MEM_PERIOD + 1);
	mem2_size = mem1_size * 2;
	mem3_size = mem2_size * 3;

	futex_set(&test_sync->datagen, 1);
	pstree->proc1 = getpid();
	mem1 = mmap_ashmem(mem1_size);
	mem2 = mmap_ashmem(mem2_size);
	mem3 = mmap_ashmem(mem3_size);
	mems_datagen_each_pgix(PROC1_PGIX, &crc_epoch);
	mems_read_each_pgix(ZERO_PGIX);

	fork_and_setup(proc11_func);
	fork_and_setup(proc12_func);
	fork_and_setup(proc13_func);

	xmunmap(mem1, mem1_size);
	if (mremap(mem2, mem2_size, mem1_size, MREMAP_MAYMOVE | MREMAP_FIXED, mem1) != mem1) {
		pr_perror("proc1 mem2 remap");
		exit(1);
	}
	mem2_old = mem2;
	mem2 = NULL;

	test_daemon();
	while (test_go())
		mems_datagen_each_pgix(PROC1_PGIX, &crc_epoch);
	test_waitsig();
	futex_set(&test_sync->datagen_exit_cnt, 0);
	futex_set(&test_sync->datagen, 0);
	futex_wait_while(&test_sync->datagen_exit_cnt, PROC_CNT);

	mems_datachck_each_pgix(PROC1_PGIX);

	chk_proc_mem_eq(pstree->proc1, mem1, mem1_size, pstree->proc11, mem2_old, mem2_size);
	chk_proc_mem_eq(pstree->proc1, mem1, mem1_size, pstree->proc12, mem2_old, mem2_size);

	chk_proc_mem_eq(pstree->proc1, mem3, mem3_size, pstree->proc12, mem3, mem3_size);

	cont_and_wait_child(pstree->proc11);
	cont_and_wait_child(pstree->proc12);
	cont_and_wait_child(pstree->proc13);

	pass();
	return 0;
}

static void kill_pstree_from_root(void)
{
	if (getpid() != pstree->proc1)
		return;

	kill(pstree->proc11, SIGKILL);
	kill(pstree->proc12, SIGKILL);
	kill(pstree->proc13, SIGKILL);
	kill(pstree->proc111, SIGKILL);
	kill(pstree->proc112, SIGKILL);
	kill(pstree->proc131, SIGKILL);
}

static void sigchld_hand(int signo, siginfo_t *info, void *ucontext)
{
	if (info->si_code != CLD_EXITED)
		return;
	if (!info->si_status)
		return;

	/*
	 * If we are not ps tree root then propagate child error to parent.
	 * If we are ps tree root then also call all
	 * atexit handlers set up by zdtm test framework and this test.
	 * exit() is not async signal safe but it's ok for testing purposes.
	 * exit() usage allows us to use very simple error handling
	 * and pstree killing logic.
	 */
	exit(info->si_status);
}

int main(int argc, char **argv)
{
	struct sigaction sa = { .sa_sigaction = sigchld_hand, .sa_flags = SA_RESTART | SA_SIGINFO | SA_NOCLDSTOP };
	sigemptyset(&sa.sa_mask);

	test_init(argc, argv);

	pstree = (struct pstree *)mmap_ashmem(PAGE_SIZE);
	test_sync = (struct test_sync *)mmap_ashmem(sizeof(*test_sync));

	if (sigaction(SIGCHLD, &sa, NULL)) {
		pr_perror("SIGCHLD handler setup");
		exit(1);
	};

	if (atexit(kill_pstree_from_root)) {
		pr_err("Can't setup atexit cleanup func\n");
		exit(1);
	}
	return proc1_func();
}
