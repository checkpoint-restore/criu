#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>

#include "log.h"
#include "bug.h"
#include "kerndat.h"
#include "fs-magic.h"
#include "mem.h"
#include "compiler.h"
#include "sysctl.h"
#include "asm/types.h"
#include "cr_options.h"
#include "util.h"
#include "lsm.h"
#include "proc_parse.h"
#include "config.h"
#include "syscall-codes.h"

struct kerndat_s kdat = {
};

static int check_pagemap(void)
{
	int ret, fd;
	u64 pfn = 0;

	fd = __open_proc(PROC_SELF, EPERM, O_RDONLY, "pagemap");
	if (fd < 0) {
		if (errno == EPERM) {
			pr_info("Pagemap disabled");
			kdat.pmap = PM_DISABLED;
			return 0;
		}

		return -1;
	}

	/* Get the PFN of some present page. Stack is here, so try it :) */
	ret = pread(fd, &pfn, sizeof(pfn), (((unsigned long)&ret) / page_size()) * sizeof(pfn));
	if (ret != sizeof(pfn)) {
		pr_perror("Can't read pagemap");
		return -1;
	}

	close(fd);

	if ((pfn & PME_PFRAME_MASK) == 0) {
		pr_info("Pagemap provides flags only\n");
		kdat.pmap = PM_FLAGS_ONLY;
	} else {
		pr_info("Pagemap is fully functional\n");
		kdat.pmap = PM_FULL;
	}

	return 0;
}

/*
 * Anonymous shared mappings are backed by hidden tmpfs
 * mount. Find out its dev to distinguish such mappings
 * from real tmpfs files maps.
 */

static int parse_self_maps(unsigned long vm_start, dev_t *device)
{
	FILE *maps;
	char buf[1024];

	maps = fopen_proc(PROC_SELF, "maps");
	if (maps == NULL) {
		pr_perror("Can't open self maps");
		return -1;
	}

	while (fgets(buf, sizeof(buf), maps) != NULL) {
		char *end, *aux;
		unsigned long start;
		int maj, min;

		start = strtoul(buf, &end, 16);
		if (vm_start > start)
			continue;
		if (vm_start < start)
			break;

		/* It's ours */
		aux = strchr(end + 1, ' '); /* end prot */
		aux = strchr(aux + 1, ' '); /* prot pgoff */
		aux = strchr(aux + 1, ' '); /* pgoff dev */

		maj = strtoul(aux + 1, &end, 16);
		min = strtoul(end + 1, NULL, 16);

		*device = makedev(maj, min);
		fclose(maps);
		return 0;
	}

	fclose(maps);
	return -1;
}

static int kerndat_get_shmemdev(void)
{
	void *map;
	char maps[128];
	struct stat buf;
	dev_t dev;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED) {
		pr_perror("Can't mmap memory for shmemdev test");
		return -1;
	}

	sprintf(maps, "/proc/self/map_files/%lx-%lx",
			(unsigned long)map, (unsigned long)map + page_size());
	if (stat(maps, &buf) < 0) {
		int e = errno;
		if (errno == EPERM) {
			/*
			 * Kernel disables messing with map_files.
			 * OK, let's go the slower route.
			 */

			if (parse_self_maps((unsigned long)map, &dev) < 0) {
				pr_err("Can't read self maps\n");
				goto err;
			}
		} else {
			pr_perror("Can't stat self map_files %d", e);
			goto err;
		}
	} else
		dev = buf.st_dev;

	munmap(map, PAGE_SIZE);
	kdat.shmem_dev = dev;
	pr_info("Found anon-shmem device at %"PRIx64"\n", kdat.shmem_dev);
	return 0;

err:
	munmap(map, PAGE_SIZE);
	return -1;
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
		[KERNDAT_FS_STAT_BINFMT_MISC] = {
			.name	= "binfmt_misc",
			.path	= "/proc/sys/fs/binfmt_misc",
			.magic	= BINFMTFS_MAGIC,
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
	ret = do_task_reset_dirty_track(getpid());
	if (ret < 0)
		return ret;
	if (ret == 1)
		goto no_dt;

	ret = -1;
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
no_dt:
		pr_info("Dirty tracking support is OFF\n");
		if (opts.track_mem) {
			pr_err("Tracking memory is not available\n");
			return -1;
		}
	}

	return 0;
}

/* The page frame number (PFN) is constant for the zero page */
static int init_zero_page_pfn()
{
	void *addr;
	int ret = 0;

	kdat.zero_page_pfn = -1;
	if (kdat.pmap != PM_FULL) {
		pr_info("Zero page detection failed, optimization turns off.\n");
		return 0;
	}

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

	return sysctl_op(req, ARRAY_SIZE(req), CTL_READ, 0);
}

#ifdef CONFIG_HAS_MEMFD
static bool kerndat_has_memfd_create(void)
{
	int ret;

	ret = syscall(SYS_memfd_create, NULL, 0);

	if (ret == -1 && errno == ENOSYS)
		kdat.has_memfd = false;
	else if (ret == -1 && errno == EFAULT)
		kdat.has_memfd = true;
	else {
		pr_err("Unexpected error from memfd_create(NULL, 0): %m\n");
		return -1;
	}

	return 0;
}
#else
static bool kerndat_has_memfd_create(void)
{
	kdat.has_memfd = false;
	return 0;
}
#endif

static int get_task_size(void)
{
	kdat.task_size = task_size();
	pr_debug("Found task size of %lx\n", kdat.task_size);
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

static int get_ipv6()
{
	if (access("/proc/sys/net/ipv6", F_OK) < 0) {
		if (errno == ENOENT) {
			pr_debug("ipv6 is disabled\n");
			kdat.ipv6 = false;
			return 0;
		}
		pr_perror("Unable to access /proc/sys/net/ipv6");
		return -1;
	}
	kdat.ipv6 = true;
	return 0;
}

int kerndat_loginuid(bool only_dump)
{
	unsigned int saved_loginuid;
	int ret;

	kdat.has_loginuid = false;

	/* No such file: CONFIG_AUDITSYSCALL disabled */
	saved_loginuid = parse_pid_loginuid(PROC_SELF, &ret, true);
	if (ret < 0)
		return 0;

	if (only_dump) {
		kdat.has_loginuid = true;
		return 0;
	}

	/*
	 * From kernel v3.13-rc2 it's possible to unset loginuid value,
	 * on that rely dump/restore code.
	 * See also: marc.info/?l=git-commits-head&m=138509506407067
	 */
	if (prepare_loginuid(INVALID_UID, LOG_WARN) < 0)
		return 0;
	/* Cleaning value back as it was */
	if (prepare_loginuid(saved_loginuid, LOG_WARN) < 0)
		return 0;

	kdat.has_loginuid = true;
	return 0;
}

int kerndat_init(void)
{
	int ret;

	ret = check_pagemap();
	if (!ret)
		ret = kerndat_get_shmemdev();
	if (!ret)
		ret = kerndat_get_dirty_track();
	if (!ret)
		ret = init_zero_page_pfn();
	if (!ret)
		ret = get_last_cap();
	if (!ret)
		ret = kerndat_fdinfo_has_lock();
	if (!ret)
		ret = get_task_size();
	if (!ret)
		ret = get_ipv6();
	if (!ret)
		ret = kerndat_loginuid(true);

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

	ret = check_pagemap();
	if (!ret)
		ret = get_last_cap();
	if (!ret)
		ret = kerndat_has_memfd_create();
	if (!ret)
		ret = get_task_size();
	if (!ret)
		ret = get_ipv6();
	if (!ret)
		ret = kerndat_loginuid(false);

	kerndat_lsm();

	return ret;
}
