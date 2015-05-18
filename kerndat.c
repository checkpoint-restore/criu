#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>

#include "log.h"
#include "bug.h"
#include "kerndat.h"
#include "fs-magic.h"
#include "mem.h"
#include "compiler.h"
#include "sysctl.h"
#include "syscall.h"
#include "asm/types.h"
#include "cr_options.h"
#include "util.h"
#include "lsm.h"

struct kerndat_s kdat = {
	.tcp_max_rshare = 3U << 20,
};

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
			(unsigned long)map, (unsigned long)map + page_size());
	if (stat(maps, &buf) < 0) {
		munmap(map, PAGE_SIZE);
		pr_perror("Can't stat self map_files");
		return -1;
	}

	munmap(map, PAGE_SIZE);

	kdat.shmem_dev = buf.st_dev;
	pr_info("Found anon-shmem device at %"PRIx64"\n", kdat.shmem_dev);
	return 0;
}

static dev_t get_host_dev(unsigned int which)
{
	static struct kst {
		const char	*name;
		const char	*path;
		unsigned int	magic;
		dev_t		fs_dev;
	} kstat[KERNDAT_FS_STAT_MAX] = {
		[KERNDAT_FS_STAT_DEVPTS] = {
			.name	= "devpts",
			.path	= "/dev/pts",
			.magic	= DEVPTS_SUPER_MAGIC,
		},
		[KERNDAT_FS_STAT_DEVTMPFS] = {
			.name	= "devtmpfs",
			.path	= "/dev",
			.magic	= TMPFS_MAGIC,
		},
	};

	if (which >= KERNDAT_FS_STAT_MAX) {
		pr_err("Wrong fs type %u passed\n", which);
		return 0;
	}

	if (kstat[which].fs_dev == 0) {
		struct statfs fst;
		struct stat st;

		if (statfs(kstat[which].path, &fst)) {
			pr_perror("Unable to statefs %s", kstat[which].path);
			return 0;
		}

		/*
		 * XXX: If the fs we need is not there, it still
		 * may mean that it's virtualized, but just not
		 * mounted on the host.
		 */

		if (fst.f_type != kstat[which].magic) {
			pr_err("%s isn't mount on the host\n", kstat[which].name);
			return 0;
		}

		if (stat(kstat[which].path, &st)) {
			pr_perror("Unable to stat %s", kstat[which].path);
			return 0;
		}

		BUG_ON(st.st_dev == 0);
		kstat[which].fs_dev = st.st_dev;
	}

	return kstat[which].fs_dev;
}

int kerndat_fs_virtualized(unsigned int which, u32 kdev)
{
	dev_t host_fs_dev;

	host_fs_dev = get_host_dev(which);
	if (host_fs_dev == 0)
		return -1;

	return (kdev_to_odev(kdev) == host_fs_dev) ? 0 : 1;
}

/*
 * Check whether pagemap reports soft dirty bit. Kernel has
 * this functionality under CONFIG_MEM_SOFT_DIRTY option.
 */

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
		kdat.has_dirty_track = true;
	} else {
		pr_info("Dirty tracking support is OFF\n");
		if (opts.track_mem) {
			pr_err("Tracking memory is not available\n");
			return -1;
		}
	}

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

static int tcp_read_sysctl_limits(void)
{
	u32 vect[2][3] = { };
	int ret;

	struct sysctl_req req[] = {
		{ "net/ipv4/tcp_rmem", &vect[1], CTL_U32A(ARRAY_SIZE(vect[1])) },
	};

	/*
	 * Lets figure out which exactly amount of memory is
	 * availabe for send/read queues on restore.
	 */
	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_READ);
	if (ret) {
		pr_warn("TCP mem sysctls are not available. Using defaults.\n");
		goto out;
	}

	kdat.tcp_max_rshare = min(kdat.tcp_max_rshare, (int)vect[1][2]);

	if (kdat.tcp_max_rshare < 128)
		pr_warn("The memory limits for TCP queues are suspiciously small\n");
out:
	pr_debug("TCP recv queue memory limit is %d\n", kdat.tcp_max_rshare);
	return 0;
}

/* The page frame number (PFN) is constant for the zero page */
static int init_zero_page_pfn()
{
	void *addr;
	int ret;

	addr = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Unable to map zero page");
		return 0;
	}

	if (*((int *) addr) != 0) {
		BUG();
		return -1;
	}

	ret = vaddr_to_pfn((unsigned long)addr, &kdat.zero_page_pfn);
	munmap(addr, PAGE_SIZE);

	if (kdat.zero_page_pfn == 0)
		ret = -1;

	return ret;
}

static int get_last_cap(void)
{
	struct sysctl_req req[] = {
		{ "kernel/cap_last_cap", &kdat.last_cap, CTL_U32 },
	};

	return sysctl_op(req, ARRAY_SIZE(req), CTL_READ);
}

static bool kerndat_has_memfd_create(void)
{
	int ret;

	ret = sys_memfd_create(NULL, 0);

	if (ret == -ENOSYS)
		kdat.has_memfd = false;
	else if (ret == -EFAULT)
		kdat.has_memfd = true;
	else {
		pr_err("Unexpected error %d from memfd_create(NULL, 0)\n", ret);
		return -1;
	}

	return 0;
}

int kerndat_fdinfo_has_lock()
{
	int fd, pfd = -1, exit_code = -1, len;
	char buf[PAGE_SIZE];

	fd = open("/proc/locks", O_RDONLY);
	if (fd < 0) {
		pr_perror("Unable to open /proc/locks");
		return -1;
	}

	if (flock(fd, LOCK_SH)) {
		pr_perror("Can't take a lock");
		goto out;
	}

	pfd = open_proc(PROC_SELF, "fdinfo/%d", fd);
	if (pfd < 0)
		goto out;

	len = read(pfd, buf, sizeof(buf) - 1);
	if (len < 0) {
		pr_perror("Unable to read");
		goto out;
	}
	buf[len] = 0;

	kdat.has_fdinfo_lock = (strstr(buf, "lock:") != NULL);

	exit_code = 0;
out:
	close(pfd);
	close(fd);

	return exit_code;
}

int kerndat_init(void)
{
	int ret;

	ret = kerndat_get_shmemdev();
	if (!ret)
		ret = kerndat_get_dirty_track();
	if (!ret)
		ret = init_zero_page_pfn();
	if (!ret)
		ret = get_last_cap();
	if (!ret)
		ret = kerndat_fdinfo_has_lock();

	kerndat_lsm();

	return ret;
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
	if (!ret)
		ret = kerndat_has_memfd_create();

	kerndat_lsm();

	return ret;
}
