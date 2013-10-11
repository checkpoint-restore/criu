#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include "log.h"
#include "kerndat.h"
#include "mem.h"
#include "compiler.h"
#include "sysctl.h"
#include "asm/types.h"

dev_t kerndat_shmem_dev;

/*
 * Anonymous shared mappings are backed by hidden tmpfs
 * mount. Find out its dev to distinguish such mappings
 * from real tmpfs files maps.
 */

static int kerndat_get_shmemdev(void)
{
	void *map;
	char maps[128];
	struct stat buf;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED) {
		pr_perror("Can't mmap memory for shmemdev test");
		return -1;
	}

	sprintf(maps, "/proc/self/map_files/%lx-%lx",
			(unsigned long)map, (unsigned long)map + PAGE_SIZE);
	if (stat(maps, &buf) < 0) {
		munmap(map, PAGE_SIZE);
		pr_perror("Can't stat self map_files");
		return -1;
	}

	munmap(map, PAGE_SIZE);

	kerndat_shmem_dev = buf.st_dev;
	pr_info("Found anon-shmem device at %"PRIx64"\n", kerndat_shmem_dev);
	return 0;
}

/*
 * Check whether pagemap reports soft dirty bit. Kernel has
 * this functionality under CONFIG_MEM_SOFT_DIRTY option.
 */

bool kerndat_has_dirty_track = false;

int kerndat_get_dirty_track(void)
{
	char *map;
	int pm2;
	u64 pmap = 0;
	int ret = -1;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED) {
		pr_perror("Can't mmap memory for pagemap test");
		return ret;
	}

	/*
	 * Kernel shows soft-dirty bits only if this soft-dirty
	 * was at least once re-set. (this is to be removed in
	 * a couple of kernel releases)
	 */
	do_task_reset_dirty_track(getpid());
	pm2 = open("/proc/self/pagemap", O_RDONLY);
	if (pm2 < 0) {
		pr_perror("Can't open pagemap file");
		munmap(map, PAGE_SIZE);
		return ret;
	}

	map[0] = '\0';

	lseek(pm2, (unsigned long)map / PAGE_SIZE * sizeof(u64), SEEK_SET);
	ret = read(pm2, &pmap, sizeof(pmap));
	if (ret < 0)
		pr_perror("Read pmap err!");

	close(pm2);
	munmap(map, PAGE_SIZE);

	if (pmap & PME_SOFT_DIRTY) {
		pr_info("Dirty track supported on kernel\n");
		kerndat_has_dirty_track = true;
	} else
		pr_info("Dirty tracking support is OFF\n");

	return 0;
}

/*
 * Strictly speaking, if there is a machine with huge amount
 * of memory, we're allowed to send up to 4M and read up to
 * 6M of tcp data at once. But we will figure out precise size
 * of a limit a bit later when restore starts.
 *
 * Meanwhile set it up to 2M and 3M, which is safe enough to
 * proceed without errors.
 */
int tcp_max_wshare = 2U << 20;
int tcp_max_rshare = 3U << 20;

static int tcp_read_sysctl_limits(void)
{
	u32 vect[2][3] = { };
	int ret;

	struct sysctl_req req[] = {
		{ "net/ipv4/tcp_wmem", &vect[0], CTL_U32A(ARRAY_SIZE(vect[0])) },
		{ "net/ipv4/tcp_rmem", &vect[1], CTL_U32A(ARRAY_SIZE(vect[1])) },
		{ },
	};

	/*
	 * Lets figure out which exactly amount of memory is
	 * availabe for send/read queues on restore.
	 */
	ret = sysctl_op(req, CTL_READ);
	if (ret) {
		pr_warn("TCP mem sysctls are not available. Using defaults.\n");
		goto out;
	}

	tcp_max_wshare = min(tcp_max_wshare, (int)vect[0][2]);
	tcp_max_rshare = min(tcp_max_rshare, (int)vect[1][2]);

	if (tcp_max_wshare < 128 || tcp_max_rshare < 128)
		pr_warn("The memory limits for TCP queues are suspiciously small\n");
out:
	pr_debug("TCP queue memory limits are %d:%d\n", tcp_max_wshare, tcp_max_rshare);
	return 0;
}

int kerndat_init(void)
{
	int ret;

	ret = kerndat_get_shmemdev();
	if (!ret)
		ret = kerndat_get_dirty_track();

	return ret;
}

int kern_last_cap;

int get_last_cap(void)
{
	struct sysctl_req req[] = {
		{ "kernel/cap_last_cap", &kern_last_cap, CTL_U32 },
		{ },
	};

	return sysctl_op(req, CTL_READ);
}

int kerndat_init_rst(void)
{
	int ret;

	/*
	 * Read TCP sysctls before anything else,
	 * since the limits we're interested in are
	 * not available inside namespaces.
	 */

	ret = tcp_read_sysctl_limits();
	if (!ret)
		ret = get_last_cap();

	return ret;
}
