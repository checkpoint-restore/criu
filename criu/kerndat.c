#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/inotify.h>
#include <sched.h>
#include <sys/mount.h>
#include <linux/membarrier.h>

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
#include <nftables/libnftables.h>
#endif
#include <sys/utsname.h>

#include "common/config.h"
#include "int.h"
#include "log.h"
#include "restorer.h"
#include "kerndat.h"
#include "fs-magic.h"
#include "mem.h"
#include "mman.h"
#include "common/compiler.h"
#include "sysctl.h"
#include "cr_options.h"
#include "util.h"
#include "lsm.h"
#include "proc_parse.h"
#include "sk-inet.h"
#include "sockets.h"
#include "net.h"
#include "tun.h"
#include <compel/ptrace.h>
#include <compel/plugins/std/syscall-codes.h>
#include "netfilter.h"
#include "fsnotify.h"
#include "linux/userfaultfd.h"
#include "prctl.h"
#include "uffd.h"
#include "vdso.h"
#include "kcmp.h"
#include "sched.h"
#include "memfd.h"
#include "mount-v2.h"
#include "util-caps.h"
#include "pagemap_scan.h"

struct kerndat_s kdat = {};
volatile int dummy_var;

static int check_pagemap(void)
{
	int ret, fd, retry;
	u64 pfn = 0;
	struct pm_scan_arg args = {
		.size = sizeof(struct pm_scan_arg),
		.flags = 0,
		.category_inverted = PAGE_IS_PFNZERO | PAGE_IS_FILE,
		.category_mask = PAGE_IS_PFNZERO | PAGE_IS_FILE,
		.category_anyof_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
		.return_mask = PAGE_IS_PRESENT | PAGE_IS_SWAPPED | PAGE_IS_SOFT_DIRTY,
	};

	fd = __open_proc(PROC_SELF, EPERM, O_RDONLY, "pagemap");
	if (fd < 0) {
		if (errno == EPERM) {
			pr_info("Pagemap disabled\n");
			kdat.pmap = PM_DISABLED;
			return 0;
		}

		return -1;
	}

	if (ioctl(fd, PAGEMAP_SCAN, &args) == 0) {
		pr_debug("PAGEMAP_SCAN is supported\n");
		kdat.has_pagemap_scan = true;

		args.return_mask |= PAGE_IS_GUARD;
		if (ioctl(fd, PAGEMAP_SCAN, &args) == 0)
			kdat.has_pagemap_scan_guard_pages = true;
	} else {
		switch (errno) {
		case EINVAL:
		case ENOTTY:
			pr_debug("PAGEMAP_SCAN isn't supported\n");
			break;
		default:
			pr_perror("PAGEMAP_SCAN failed with unexpected errno");
			return -1;
		}
	}

	retry = 3;
	while (retry--) {
		++dummy_var;
		/* Get the PFN of a page likely to be present. */
		ret = pread(fd, &pfn, sizeof(pfn), PAGE_PFN((uintptr_t)&dummy_var) * sizeof(pfn));
		if (ret != sizeof(pfn)) {
			pr_perror("Can't read pagemap");
			close(fd);
			return -1;
		}
		/* The page can be swapped out by the time the read occurs,
		 * in which case the rest of the bits are a swap type + offset
		 * (which could be zero even if not hidden).
		 * Retry if this happens. */
		if (pfn & PME_PRESENT)
			break;
		pr_warn("got non-present PFN %#lx for the dummy data page; %s\n", (unsigned long)pfn,
			retry ? "retrying" : "giving up");
		pfn = 0;
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
	if (maps == NULL)
		return -1;

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

static void kerndat_mmap_min_addr(void)
{
	/* From kernel's default CONFIG_LSM_MMAP_MIN_ADDR */
	static const unsigned long default_mmap_min_addr = 65536;
	uint64_t value;

	struct sysctl_req req[] = {
		{
			.name = "vm/mmap_min_addr",
			.arg = &value,
			.type = CTL_U64,
		},
	};

	if (sysctl_op(req, ARRAY_SIZE(req), CTL_READ, 0)) {
		pr_warn("Can't fetch %s value, use default %#lx\n", req[0].name, (unsigned long)default_mmap_min_addr);
		kdat.mmap_min_addr = default_mmap_min_addr;
		return;
	}

	if (value < default_mmap_min_addr) {
		pr_debug("Adjust mmap_min_addr %#lx -> %#lx\n", (unsigned long)value,
			 (unsigned long)default_mmap_min_addr);
		kdat.mmap_min_addr = default_mmap_min_addr;
	} else
		kdat.mmap_min_addr = value;

	pr_debug("Found mmap_min_addr %#lx\n", (unsigned long)kdat.mmap_min_addr);
}

static int kerndat_files_stat(void)
{
	static const uint32_t NR_OPEN_DEFAULT = 1024 * 1024;
	uint32_t nr_open;

	struct sysctl_req req[] = {
		{
			.name = "fs/nr_open",
			.arg = &nr_open,
			.type = CTL_U32,
		},
	};

	if (sysctl_op(req, ARRAY_SIZE(req), CTL_READ, 0)) {
		pr_warn("Can't fetch file_stat, using kernel defaults\n");
		nr_open = NR_OPEN_DEFAULT;
	}

	kdat.sysctl_nr_open = nr_open;

	pr_debug("files stat: %s %u\n", req[0].name, kdat.sysctl_nr_open);

	return 0;
}

static int kerndat_get_dev(dev_t *dev, char *map, size_t size)
{
	char maps[128];
	struct stat buf;

	sprintf(maps, "/proc/self/map_files/%lx-%lx", (unsigned long)map, (unsigned long)map + size);
	if (stat(maps, &buf) < 0) {
		int e = errno;
		if (errno == EPERM) {
			/*
			 * Kernel disables messing with map_files.
			 * OK, let's go the slower route.
			 */

			if (parse_self_maps((unsigned long)map, dev) < 0) {
				pr_err("Can't read self maps\n");
				return -1;
			}
		} else {
			pr_perror("Can't stat self map_files %d", e);
			return -1;
		}
	} else {
		*dev = buf.st_dev;
	}

	return 0;
}

static int kerndat_get_shmemdev(void)
{
	void *map;
	dev_t dev;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED) {
		pr_perror("Can't mmap memory for shmemdev test");
		return -1;
	}

	if (kerndat_get_dev(&dev, map, PAGE_SIZE))
		goto err;

	munmap(map, PAGE_SIZE);
	kdat.shmem_dev = dev;
	pr_info("Found anon-shmem device at %" PRIx64 "\n", kdat.shmem_dev);
	return 0;

err:
	munmap(map, PAGE_SIZE);
	return -1;
}

/* Return -1 -- error
 * Return 0 -- successful but can't get any new device's numbers
 * Return 1 -- successful and get new device's numbers
 *
 * At first, all kdat.hugetlb_dev elements are initialized to 0.
 * When the function finishes,
 * kdat.hugetlb_dev[i] == -1 -- this hugetlb page size is not supported
 * kdat.hugetlb_dev[i] == 0  -- this hugetlb page size is supported but can't collect device's number
 * Otherwise, kdat.hugetlb_dev[i] contains the corresponding device's number
 *
 * Next time the function is called, it only tries to collect the device's number of hugetlb page size
 * that is supported but can't be collected in the previous call (kdat.hugetlb_dev[i] == 0)
 */
static int kerndat_get_hugetlb_dev(void)
{
	void *map;
	int i, flag, ret = 0;
	unsigned long long size;
	dev_t dev;

	for (i = 0; i < HUGETLB_MAX; i++) {
		/* Skip if this hugetlb size is not supported or the device's number has been collected */
		if (kdat.hugetlb_dev[i])
			continue;

		size = hugetlb_info[i].size;
		flag = hugetlb_info[i].flag;
		map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | flag, 0, 0);
		if (map == MAP_FAILED) {
			if (errno == EINVAL) {
				kdat.hugetlb_dev[i] = (dev_t)-1;
				continue;
			} else if (errno == ENOMEM) {
				pr_info("Hugetlb size %llu Mb is supported but cannot get dev's number\n", size >> 20);
				continue;
			} else {
				pr_perror("Unexpected result when get hugetlb dev");
				return -1;
			}
		}

		if (kerndat_get_dev(&dev, map, size)) {
			munmap(map, size);
			return -1;
		}

		munmap(map, size);
		kdat.hugetlb_dev[i] = dev;
		ret = 1;
		pr_info("Found hugetlb device at %" PRIx64 "\n", kdat.hugetlb_dev[i]);
	}
	return ret;
}

static dev_t get_host_dev(unsigned int which)
{
	static struct kst {
		const char *name;
		const char *path;
		unsigned int magic;
		dev_t fs_dev;
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

static int kerndat_get_dirty_track(void)
{
	char *map;
	int pm2;
	u64 pmap = 0;
	int ret = -1;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
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
	pm2 = open_proc(PROC_SELF, "pagemap");
	if (pm2 < 0) {
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
	}

	return 0;
}

/* The page frame number (PFN) is constant for the zero page */
static int init_zero_page_pfn(void)
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

	if (*((int *)addr) != 0) {
		BUG();
		return -1;
	}

	ret = vaddr_to_pfn(-1, (unsigned long)addr, &kdat.zero_page_pfn);
	munmap(addr, PAGE_SIZE);

	if (kdat.zero_page_pfn == 0) {
		pr_err("vaddr_to_pfn succeeded but kdat.zero_page_pfn is invalid.\n");
		ret = -1;
	}
	return ret;
}

static int get_last_cap(void)
{
	struct sysctl_req req[] = {
		{ "kernel/cap_last_cap", &kdat.last_cap, CTL_U32 },
	};
	int ret;

	ret = sysctl_op(req, ARRAY_SIZE(req), CTL_READ, 0);
	if (ret || kdat.last_cap < 32 * CR_CAP_SIZE)
		return ret;

	pr_err("Kernel reports more capabilities than this CRIU supports: %u > %u\n",
	       kdat.last_cap, 32 * CR_CAP_SIZE - 1);
	return -1;
}

static bool kerndat_has_memfd_create(void)
{
	int ret;

	ret = memfd_create(NULL, 0);

	if (ret == -1 && errno == ENOSYS)
		kdat.has_memfd = false;
	else if (ret == -1 && errno == EFAULT)
		kdat.has_memfd = true;
	else {
		pr_perror("Unexpected error from memfd_create(NULL, 0)");
		return -1;
	}

	return 0;
}

static bool kerndat_has_memfd_hugetlb(void)
{
	int ret;

	if (!kdat.has_memfd) {
		kdat.has_memfd_hugetlb = false;
		return 0;
	}

	ret = memfd_create("", MFD_HUGETLB);
	if (ret >= 0) {
		kdat.has_memfd_hugetlb = true;
		close(ret);
	} else if (ret == -1 && (errno == EINVAL || errno == ENOENT || errno == ENOSYS)) {
		kdat.has_memfd_hugetlb = false;
	} else {
		pr_perror("Unexpected error from memfd_create(\"\", MFD_HUGETLB)");
		return -1;
	}

	return 0;
}

static int get_task_size(void)
{
	kdat.task_size = compel_task_size();
	pr_debug("Found task size of %lx\n", kdat.task_size);
	return 0;
}

static int kerndat_fdinfo_has_lock(void)
{
	int fd, pfd = -1, exit_code = -1, len;
	char buf[PAGE_SIZE];

	fd = open_proc(PROC_GEN, "locks");
	if (fd < 0)
		return -1;

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
	close_safe(&pfd);
	close(fd);

	return exit_code;
}

static int get_ipv6(void)
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

static int kerndat_loginuid(void)
{
	unsigned int saved_loginuid;
	int ret;

	kdat.luid = LUID_NONE;

	/* No such file: CONFIG_AUDITSYSCALL disabled */
	saved_loginuid = parse_pid_loginuid(PROC_SELF, &ret, true);
	if (ret < 0)
		return 0;

	kdat.luid = LUID_READ;

	/*
	 * From kernel v3.13-rc2 it's possible to unset loginuid value,
	 * on that rely dump/restore code.
	 * See also: marc.info/?l=git-commits-head&m=138509506407067
	 */
	if (prepare_loginuid(INVALID_UID) < 0)
		return 0;
	/* Cleaning value back as it was */
	if (prepare_loginuid(saved_loginuid) < 0)
		return 0;

	kdat.luid = LUID_FULL;
	return 0;
}

static int kerndat_iptables_has_xtlocks(void)
{
	int fd;
	char *argv[4] = { "sh", "-c", "iptables -n -w -L", NULL };

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		fd = -1;
		pr_perror("failed to open /dev/null, using log fd for xtlocks check");
	}

	kdat.has_xtlocks = 1;
	if (cr_system(fd, fd, fd, "sh", argv, CRS_CAN_FAIL) == -1)
		kdat.has_xtlocks = 0;

	close_safe(&fd);
	return 0;
}

/*
 * Unfortunately in C htonl() is not constexpr and cannot be used in a static
 * initialization below.
 */
#define constant_htonl(x) \
	(__BYTE_ORDER == __BIG_ENDIAN ? (x) : \
		(((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
		(((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

static int kerndat_tcp_repair(void)
{
	static const struct sockaddr_in loopback_ip4 = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr = { constant_htonl(INADDR_LOOPBACK) },
	};
	static const struct sockaddr_in6 loopback_ip6 = {
		.sin6_family = AF_INET6,
		.sin6_port = 0,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
	};
	int sock, clnt = -1, yes = 1, exit_code = -1;
	const struct sockaddr *addr;
	struct sockaddr_storage listener_addr;
	socklen_t addrlen;

	addr = (const struct sockaddr *)&loopback_ip4;
	addrlen = sizeof(loopback_ip4);
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0 && errno == EAFNOSUPPORT) {
		addr = (const struct sockaddr *)&loopback_ip6;
		addrlen = sizeof(loopback_ip6);
		sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	if (sock < 0) {
		pr_perror("Unable to create a socket");
		return -1;
	}

	if (bind(sock, addr, addrlen)) {
		pr_perror("Unable to bind a socket");
		goto err;
	}

	addrlen = sizeof(listener_addr);
	if (getsockname(sock, (struct sockaddr *)&listener_addr, &addrlen)) {
		pr_perror("Unable to get a socket name");
		goto err;
	}

	if (listen(sock, 1)) {
		pr_perror("Unable to listen a socket");
		goto err;
	}

	clnt = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (clnt < 0) {
		pr_perror("Unable to create a socket");
		goto err;
	}

	if (connect(clnt, (const struct sockaddr *)&listener_addr, addrlen)) {
		pr_perror("Unable to connect a socket");
		goto err;
	}

	if (shutdown(clnt, SHUT_WR)) {
		pr_perror("Unable to shutdown a socket");
		goto err;
	}

	if (setsockopt(clnt, SOL_TCP, TCP_REPAIR, &yes, sizeof(yes))) {
		if (errno != EPERM) {
			pr_perror("Unable to set TCP_REPAIR with setsockopt");
			goto err;
		}
		kdat.has_tcp_half_closed = false;
	} else
		kdat.has_tcp_half_closed = true;

	exit_code = 0;
err:
	close_safe(&clnt);
	close(sock);

	return exit_code;
}

static int kerndat_nsid(void)
{
	int nsid, sk;

	kdat.has_nsid = false;

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_pwarn("Unable to create a netlink socket: NSID can't be used.");
		return 0;
	}

	if (net_get_nsid(sk, getpid(), &nsid) < 0) {
		pr_warn("NSID is not supported\n");
		close(sk);
		return 0;
	}

	kdat.has_nsid = true;
	close(sk);
	return 0;
}

static int kerndat_compat_restore(void)
{
	int ret;

	ret = kdat_can_map_vdso();
	if (ret < 0) {
		pr_err("kdat_can_map_vdso failed\n");
		return ret;
	}
	kdat.can_map_vdso = !!ret;

	/* depends on kdat.can_map_vdso result */
	kdat.compat_cr = kdat_compatible_cr();

	return 0;
}

static int kerndat_detect_stack_guard_gap(void)
{
	int num, ret = -1, detected = 0;
	unsigned long start, end;
	char r, w, x, s;
	char buf[1024];
	FILE *maps;
	void *mem;

	mem = mmap(NULL, (3ul << 20), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap stack area");
		return -1;
	}
	munmap(mem, (3ul << 20));

	mem = mmap(mem + (2ul << 20), (1ul << 20), PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_GROWSDOWN, -1, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap stack area");
		return -1;
	}

	maps = fopen("/proc/self/maps", "r");
	if (maps == NULL) {
		pr_perror("Could not open /proc/self/maps");
		munmap(mem, 4096);
		return -1;
	}

	while (fgets(buf, sizeof(buf), maps)) {
		num = sscanf(buf, "%lx-%lx %c%c%c%c", &start, &end, &r, &w, &x, &s);
		if (num < 6) {
			pr_err("Can't parse: %s\n", buf);
			goto err;
		}

		/*
		 * When reading /proc/$pid/[s]maps the
		 * start/end addresses might be cut off
		 * with PAGE_SIZE on kernels prior 4.12
		 * (see kernel commit 1be7107fbe18ee).
		 *
		 * Same time there was semi-complete
		 * patch released which hit a number
		 * of repos (Ubuntu, Fedora) where instead
		 * of PAGE_SIZE the 1M gap is cut off.
		 */
		if (start == (unsigned long)mem) {
			kdat.stack_guard_gap_hidden = false;
			detected = 1;
			break;
		} else if (start == ((unsigned long)mem + (1ul << 20))) {
			pr_warn("Unsupported stack guard detected, confused but continue\n");
			kdat.stack_guard_gap_hidden = true;
			detected = 1;
			break;
		} else if (start == ((unsigned long)mem + PAGE_SIZE)) {
			kdat.stack_guard_gap_hidden = true;
			detected = 1;
			break;
		}
	}

	if (detected)
		ret = 0;

err:
	munmap(mem, (1ul << 20));
	fclose(maps);
	return ret;
}

static int kerndat_has_inotify_setnextwd(void)
{
	int ret = 0;
	int fd;

	fd = inotify_init();
	if (fd < 0) {
		pr_perror("Can't create inotify");
		return -1;
	}

	if (ioctl(fd, INOTIFY_IOC_SETNEXTWD, 0x10)) {
		if (errno != ENOTTY) {
			pr_perror("Can't call ioctl");
			ret = -1;
		}
	} else
		kdat.has_inotify_setnextwd = true;

	close(fd);
	return ret;
}

static int kerndat_has_fsopen(void)
{
	if (syscall(__NR_fsopen, NULL, -1) != -1) {
		pr_err("fsopen should fail\n");
		return -1;
	}
	if (errno == ENOSYS)
		pr_info("The new mount API (fsopen, fsmount) isn't supported\n");
	else
		kdat.has_fsopen = true;

	return 0;
}

static int has_kcmp_epoll_tfd(void)
{
	kcmp_epoll_slot_t slot = {};
	int ret = -1, efd, tfd;
	pid_t pid = getpid();
	struct epoll_event ev;
	int pipefd[2];

	efd = epoll_create(1);
	if (efd < 0) {
		pr_perror("Can't create epoll");
		return -1;
	}

	memset(&ev, 0xff, sizeof(ev));
	ev.events = EPOLLIN | EPOLLOUT;

	if (pipe(pipefd)) {
		pr_perror("Can't create pipe");
		close(efd);
		return -1;
	}

	tfd = pipefd[0];
	if (epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &ev)) {
		pr_perror("Can't add event");
		goto out;
	}

	slot.efd = efd;
	slot.tfd = tfd;

	if (syscall(SYS_kcmp, pid, pid, KCMP_EPOLL_TFD, tfd, &slot) == 0)
		kdat.has_kcmp_epoll_tfd = true;
	else
		kdat.has_kcmp_epoll_tfd = false;
	ret = 0;

out:
	close(pipefd[0]);
	close(pipefd[1]);
	close(efd);
	return ret;
}

static int has_time_namespace(void)
{
	if (access("/proc/self/timens_offsets", F_OK) < 0) {
		if (errno == ENOENT) {
			pr_debug("Time namespaces are not supported.\n");
			kdat.has_timens = false;
			return 0;
		}
		pr_perror("Unable to access /proc/self/timens_offsets");
		return -1;
	}
	kdat.has_timens = true;
	return 0;
}

int __attribute__((weak)) kdat_x86_has_ptrace_fpu_xsave_bug(void)
{
	return 0;
}

static int kerndat_x86_has_ptrace_fpu_xsave_bug(void)
{
	int ret = kdat_x86_has_ptrace_fpu_xsave_bug();

	if (ret < 0) {
		pr_err("kdat_x86_has_ptrace_fpu_xsave_bug failed\n");
		return ret;
	}

	kdat.x86_has_ptrace_fpu_xsave_bug = !!ret;
	return 0;
}

static int kerndat_has_rseq(void)
{
	if (syscall(__NR_rseq, NULL, 0, 0, 0) != -1) {
		pr_err("rseq should fail\n");
		return -1;
	}
	if (errno == ENOSYS)
		pr_info("rseq syscall isn't supported\n");
	else
		kdat.has_rseq = true;

	return 0;
}

static int kerndat_has_ptrace_get_rseq_conf(void)
{
	pid_t pid;
	int len;
	struct __ptrace_rseq_configuration rseq;
	int ret = 0;

	pid = fork_and_ptrace_attach(NULL);
	if (pid < 0)
		return -1;

	len = ptrace(PTRACE_GET_RSEQ_CONFIGURATION, pid, sizeof(rseq), &rseq);
	if (len != sizeof(rseq)) {
		if (kdat.has_ptrace_get_rseq_conf)
			ret = 1; /* we should update kdat */

		kdat.has_ptrace_get_rseq_conf = false;
		pr_info("ptrace(PTRACE_GET_RSEQ_CONFIGURATION) is not supported\n");
		goto out;
	}

	/*
	 * flags is always zero from the kernel side, if it will be changed
	 * we need to pay attention to that and, possibly, make changes on the CRIU side.
	 */
	if (rseq.flags != 0) {
		if (kdat.has_ptrace_get_rseq_conf)
			ret = 1; /* we should update kdat */

		kdat.has_ptrace_get_rseq_conf = false;
		pr_err("ptrace(PTRACE_GET_RSEQ_CONFIGURATION): rseq.flags != 0\n");
	} else {
		if (!kdat.has_ptrace_get_rseq_conf)
			ret = 1; /* we should update kdat */

		kdat.has_ptrace_get_rseq_conf = true;

		if (memcmp(&kdat.libc_rseq_conf, &rseq, sizeof(rseq)))
			ret = 1; /* we should update kdat */

		kdat.libc_rseq_conf = rseq;
	}

out:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return ret;
}

int kerndat_sockopt_buf_lock(void)
{
	int exit_code = -1;
	socklen_t len;
	u32 buf_lock;
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0 && errno == EAFNOSUPPORT)
		sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		pr_perror("Unable to create a socket");
		return -1;
	}

	len = sizeof(buf_lock);
	if (getsockopt(sock, SOL_SOCKET, SO_BUF_LOCK, &buf_lock, &len)) {
		if (errno != ENOPROTOOPT) {
			pr_perror("Unable to get SO_BUF_LOCK with getsockopt");
			goto err;
		}
		kdat.has_sockopt_buf_lock = false;
	} else
		kdat.has_sockopt_buf_lock = true;

	exit_code = 0;
err:
	close(sock);
	return exit_code;
}

static int kerndat_has_move_mount_set_group(void)
{
	char tmpdir[] = "/tmp/.criu.move_mount_set_group.XXXXXX";
	char subdir[64];
	int exit_code = -1;

	if (mkdtemp(tmpdir) == NULL) {
		pr_perror("Fail to make dir %s", tmpdir);
		return -1;
	}

	if (mount("criu.move_mount_set_group", tmpdir, "tmpfs", 0, NULL)) {
		pr_perror("Fail to mount tmfps to %s", tmpdir);
		rmdir(tmpdir);
		return -1;
	}

	if (mount(NULL, tmpdir, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Fail to make %s private", tmpdir);
		goto out;
	}

	if (snprintf(subdir, sizeof(subdir), "%s/subdir", tmpdir) >= sizeof(subdir)) {
		pr_err("Fail to snprintf subdir\n");
		goto out;
	}

	if (mkdir(subdir, 0700)) {
		pr_perror("Fail to make dir %s", subdir);
		goto out;
	}

	if (mount(subdir, subdir, NULL, MS_BIND, NULL)) {
		pr_perror("Fail to make bind-mount %s", subdir);
		goto out;
	}

	if (mount(NULL, tmpdir, NULL, MS_SHARED, NULL)) {
		pr_perror("Fail to make %s private", tmpdir);
		goto out;
	}

	if (sys_move_mount(AT_FDCWD, tmpdir, AT_FDCWD, subdir, MOVE_MOUNT_SET_GROUP)) {
		if (errno == EINVAL || errno == ENOSYS) {
			pr_debug("No MOVE_MOUNT_SET_GROUP kernel feature\n");
			kdat.has_move_mount_set_group = false;
			exit_code = 0;
			goto out;
		}
		pr_perror("Fail to MOVE_MOUNT_SET_GROUP");
		goto out;
	}

	kdat.has_move_mount_set_group = true;
	exit_code = 0;
out:
	if (umount2(tmpdir, MNT_DETACH))
		pr_warn("Fail to umount2 %s: %s\n", tmpdir, strerror(errno));
	if (rmdir(tmpdir))
		pr_warn("Fail to rmdir %s: %s\n", tmpdir, strerror(errno));
	return exit_code;
}

static int kerndat_has_openat2(void)
{
	if (sys_openat2(AT_FDCWD, ".", NULL, 0) != -1) {
		pr_err("openat2 should fail\n");
		return -1;
	}
	if (errno == ENOSYS) {
		pr_debug("No openat2 syscall support\n");
		kdat.has_openat2 = false;
	} else {
		kdat.has_openat2 = true;
	}

	return 0;
}

int __attribute__((weak)) kdat_has_shstk(void)
{
	return 0;
}

static int kerndat_has_shstk(void)
{
	int ret = kdat_has_shstk();

	if (ret < 0) {
		pr_err("kdat_has_shstk failed\n");
		return ret;
	}

	kdat.has_shstk = !!ret;
	return 0;
}

#define KERNDAT_CACHE_NAME "criu.kdat"
#define KERNDAT_CACHE_FILE KDAT_RUNDIR "/" KERNDAT_CACHE_NAME

/*
 * Returns:
 * -1 if kdat_file was not written due to error
 * 0 if kdat_file was written
 * 1 if kdat_file was not written because cache directory undefined in env (non-root mode)
 */
static int get_kerndat_filename(char **kdat_file)
{
	int ret;

	/*
	 * Running as non-root, even with CAP_CHECKPOINT_RESTORE, does not
	 * allow to write to KDAT_RUNDIR which usually is only writable by root.
	 * Let's write criu.kdat file to XDG_RUNTIME_DIR for non-root cases.
	 * Note that XDG_RUNTIME_DIR is not always defined (e.g. when executing
	 * via su/sudo).
	 */
	if (opts.unprivileged) {
		const char *cache_dir = getenv("XDG_RUNTIME_DIR");
		if (!cache_dir) {
			pr_warn("$XDG_RUNTIME_DIR not set. Cannot find location for kerndat file\n");
			return 1;
		}
		ret = asprintf(kdat_file, "%s/%s", cache_dir, KERNDAT_CACHE_NAME);
	} else {
		ret = asprintf(kdat_file, "%s", KERNDAT_CACHE_FILE);
	}

	if (unlikely(ret < 0)) {
		pr_warn("Cannot allocate memory for kerndat file name\n");
		return -1;
	}

	return 0;
}

/*
 * Returns:
 * -1 if error
 * 0 if cache was loaded
 * 1 if cache does not exist or is stale or cache directory undefined in env (non-root mode)
 */
static int kerndat_try_load_cache(void)
{
	cleanup_free char *kdat_file = NULL;
	int fd, ret;

	ret = get_kerndat_filename(&kdat_file);
	if (ret)
		return ret;

	fd = open(kdat_file, O_RDONLY);
	if (fd < 0) {
		if (ENOENT == errno)
			pr_debug("File %s does not exist\n", kdat_file);
		else
			pr_warn("Can't load %s\n", kdat_file);
		return 1;
	}

	ret = read(fd, &kdat, sizeof(kdat));
	if (ret < 0) {
		pr_perror("Can't read kdat cache");
		close(fd);
		return -1;
	}

	close(fd);

	if (ret != sizeof(kdat) || kdat.magic1 != KDAT_MAGIC || kdat.magic2 != KDAT_MAGIC_2) {
		pr_warn("Stale %s file\n", kdat_file);
		unlink(kdat_file);
		return 1;
	}

	pr_info("Loaded kdat cache from %s\n", kdat_file);
	return 0;
}

static void kerndat_save_cache(void)
{
	int fd, ret;
	struct statfs s;
	cleanup_free char *kdat_file = NULL;
	cleanup_free char *kdat_file_tmp = NULL;

	if (get_kerndat_filename(&kdat_file))
		return;

	ret = asprintf(&kdat_file_tmp, "%s.tmp", kdat_file);

	if (unlikely(ret < 0)) {
		pr_warn("Cannot allocate memory for kerndat file name\n");
		return;
	}

	fd = open(kdat_file_tmp, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd < 0)
		/*
		 * It can happen that we race with some other criu
		 * instance. That's OK, just ignore this error and
		 * proceed.
		 */
		return;

	/*
	 * If running as root we store the cache file on a tmpfs (/run),
	 * because the file should be gone after reboot.
	 */
	if (fstatfs(fd, &s) < 0 || s.f_type != TMPFS_MAGIC) {
		pr_warn("Can't keep kdat cache on non-tempfs\n");
		close(fd);
		goto unl;
	}

	/*
	 * One magic to make sure we're reading the kdat file.
	 * One more magic to make somehow sure we don't read kdat
	 * from some other criu
	 */
	kdat.magic1 = KDAT_MAGIC;
	kdat.magic2 = KDAT_MAGIC_2;

	ret = write(fd, &kdat, sizeof(kdat));
	close(fd);

	if (ret == sizeof(kdat))
		ret = rename(kdat_file_tmp, kdat_file);
	else {
		ret = -1;
		errno = EIO;
	}

	if (ret < 0) {
		pr_perror("Couldn't save %s", kdat_file);
	unl:
		unlink(kdat_file);
	}
}

static int kerndat_uffd(void)
{
	int uffd, err = 0;

	if (opts.unprivileged)
		/*
		 * If running as non-root uffd_open() fails with
		 * 'Operation not permitted'. Just ignore uffd for
		 * non-root for now.
		 */
		return 0;

	kdat.uffd_features = 0;
	uffd = uffd_open(0, &kdat.uffd_features, &err);

	/*
	 * err == ENOSYS means userfaultfd is not supported on this system and
	 * we just happily return with kdat.has_uffd = false.
	 * err == EPERM means that userfaultfd is not allowed as we are
	 * non-root user, so we also return with kdat.has_uffd = false.
	 * Errors other than ENOSYS and EPERM would mean "Houston, Houston, we
	 * have a problem!"
	 */
	if (uffd < 0) {
		if (err == ENOSYS)
			return 0;
		if (err == EPERM) {
			pr_info("Lazy pages are not permitted\n");
			return 0;
		}
		pr_err("Lazy pages are not available\n");
		return -1;
	}

	kdat.has_uffd = true;

	/*
	 * we have to close the uffd and reopen in later in restorer
	 * to enable non-cooperative features
	 */
	close(uffd);

	return 0;
}

int kerndat_has_thp_disable(void)
{
	struct bfd f;
	void *addr;
	char *str;
	int ret = -1;
	bool vma_match = false;

	if (prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)) {
		if (errno != EINVAL) {
			pr_perror("prctl PR_SET_THP_DISABLE failed");
			return -1;
		}
		pr_info("PR_SET_THP_DISABLE is not available\n");
		return 0;
	}

	addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Can't mmap memory for THP disable test");
		return -1;
	}

	if (prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0)) {
		pr_perror("prctl PR_SET_THP_DISABLE failed");
		goto out_unmap;
	}

	f.fd = open("/proc/self/smaps", O_RDONLY);
	if (f.fd < 0) {
		pr_perror("Can't open /proc/self/smaps");
		goto out_unmap;
	}
	if (bfdopenr(&f))
		goto out_unmap;

	while ((str = breadline(&f)) != NULL) {
		if (IS_ERR(str))
			goto out_close;

		if (is_vma_range_fmt(str)) {
			unsigned long vma_addr;

			if (sscanf(str, "%lx-", &vma_addr) != 1) {
				pr_err("Can't parse: %s\n", str);
				goto out_close;
			}

			if (vma_addr == (unsigned long)addr)
				vma_match = true;
		}

		if (vma_match && !strncmp(str, "VmFlags: ", 9)) {
			u32 flags = 0;
			u64 madv = 0;
			int io_pf = 0;

			parse_vmflags(str, &flags, &madv, &io_pf);
			kdat.has_thp_disable = !(madv & (1 << MADV_NOHUGEPAGE));
			if (!kdat.has_thp_disable)
				pr_warn("prctl PR_SET_THP_DISABLE sets MADV_NOHUGEPAGE\n");
			break;
		}
	}

	ret = 0;

out_close:
	bclose(&f);
out_unmap:
	munmap(addr, PAGE_SIZE);

	return ret;
}

static int kerndat_tun_netns(void)
{
	return check_tun_netns_cr(&kdat.tun_ns);
}

static bool kerndat_has_clone3_set_tid(void)
{
	pid_t pid;
	struct _clone_args args = {};

#if defined(CONFIG_MIPS)
	/*
	 * Currently the CRIU PIE assembler clone3() wrapper is
	 * not implemented for MIPS.
	 */
	kdat.has_clone3_set_tid = false;
	return 0;
#endif

	args.set_tid = -1;
	/*
	 * On a system without clone3() this will return ENOSYS.
	 * On a system with clone3() but without set_tid this
	 * will return E2BIG.
	 * On a system with clone3() and set_tid it will return
	 * EINVAL.
	 */
	pid = syscall(__NR_clone3, &args, sizeof(args));

	if (pid != -1) {
		pr_err("Unexpected success: clone3() returned %d\n", pid);
		return -1;
	}

	if (errno == ENOSYS || errno == E2BIG)
		return 0;

	if (errno != EINVAL) {
		pr_pwarn("Unexpected error from clone3");
		return 0;
	}

	kdat.has_clone3_set_tid = true;
	return 0;
}

static void kerndat_has_pidfd_open(void)
{
	int pidfd;

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd == -1)
		kdat.has_pidfd_open = false;
	else
		kdat.has_pidfd_open = true;

	close_safe(&pidfd);
}

static int kerndat_has_pidfd_getfd(void)
{
	int ret;
	int fds[2];
	int val_a, val_b;
	int pidfd, stolen_fd;

	ret = 0;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)) {
		pr_perror("Can't open unix socket pair");
		ret = -1;
		goto out;
	}

	val_a = 1984;
	if (write(fds[0], &val_a, sizeof(val_a)) != sizeof(val_a)) {
		pr_perror("Can't write to socket");
		ret = -1;
		goto close_pair;
	}

	pidfd = syscall(SYS_pidfd_open, getpid(), 0);
	if (pidfd == -1) {
		pr_warn("Can't get pidfd\n");
		/*
		 * If pidfd_open is not supported then pidfd_getfd
		 * will not be supported as well.
		 */
		kdat.has_pidfd_getfd = false;
		goto close_pair;
	}

	stolen_fd = syscall(SYS_pidfd_getfd, pidfd, fds[1], 0);
	if (stolen_fd == -1) {
		kdat.has_pidfd_getfd = false;
		goto close_all;
	}

	if (read(fds[1], &val_b, sizeof(val_b)) != sizeof(val_b)) {
		pr_perror("Can't read from socket");
		ret = -1;
		goto close_all;
	}

	if (val_b == val_a) {
		kdat.has_pidfd_getfd = true;
	} else {
		/* If val_b != val_a, something unexpected happened. */
		pr_err("Unexpected value read from socket\n");
		ret = -1;
	}

close_all:
	close_safe(&stolen_fd);
	close_safe(&pidfd);
close_pair:
	close(fds[0]);
	close(fds[1]);
out:
	return ret;
}

int kerndat_has_nspid(void)
{
	struct bfd f;
	int ret = -1;
	char *str;

	f.fd = open("/proc/self/status", O_RDONLY);
	if (f.fd < 0) {
		pr_perror("Can't open /proc/self/status");
		return -1;
	}
	if (bfdopenr(&f))
		return -1;
	while ((str = breadline(&f)) != NULL) {
		if (IS_ERR(str))
			goto close;
		if (!strncmp(str, "NSpid:", 6)) {
			kdat.has_nspid = true;
			break;
		}
	}
	ret = 0;
close:
	bclose(&f);
	return ret;
}

#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
static int __has_nftables_concat(void *arg)
{
	bool *has = (bool *)arg;
	struct nft_ctx *nft;
	int ret = 1;

	/*
	 * Create a separate network namespace to avoid
	 * collisions between two CRIU instances.
	 */
	if (unshare(CLONE_NEWNET)) {
		pr_perror("Unable create a network namespace");
		return 1;
	}

	nft = nft_ctx_new(NFT_CTX_DEFAULT);
	if (!nft)
		return 1;

	if (NFT_RUN_CMD(nft, "create table inet CRIU")) {
		pr_warn("Can't create nftables table\n");
		*has = false; /* kdat.has_nftables_concat = false */
		ret = 0;
		goto nft_ctx_free_out;
	}

	if (NFT_RUN_CMD(nft, "add set inet CRIU conn { type ipv4_addr . inet_service ;}"))
		*has = false; /* kdat.has_nftables_concat = false */
	else
		*has = true; /* kdat.has_nftables_concat = true */

	/* Clean up */
	NFT_RUN_CMD(nft, "delete table inet CRIU");

	ret = 0;
nft_ctx_free_out:
	nft_ctx_free(nft);
	return ret;
}
#endif

static int kerndat_has_nftables_concat(void)
{
#if defined(CONFIG_HAS_NFTABLES_LIB_API_0) || defined(CONFIG_HAS_NFTABLES_LIB_API_1)
	bool has;

	if (call_in_child_process(__has_nftables_concat, (void *)&has))
		return -1;

	kdat.has_nftables_concat = has;
	return 0;
#else
	pr_warn("CRIU was built without libnftables support\n");
	kdat.has_nftables_concat = false;
	return 0;
#endif
}

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

static int __kerndat_has_ipv6_freebind(int sk)
{
	int val = 1;

	if (setsockopt(sk, SOL_IPV6, IPV6_FREEBIND, &val, sizeof(int)) == -1) {
		if (errno == ENOPROTOOPT) {
			kdat.has_ipv6_freebind = false;
			return 0;
		}
		pr_perror("Unable to setsockopt ipv6_freebind");
		return -1;
	}

	kdat.has_ipv6_freebind = true;
	return 0;
}

static int kerndat_has_ipv6_freebind(void)
{
	int sk, ret;

	if (!kdat.ipv6) {
		kdat.has_ipv6_freebind = false;
		return 0;
	}

	sk = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sk == -1) {
		pr_perror("Unable to create a ipv6 dgram socket");
		return -1;
	}

	ret = __kerndat_has_ipv6_freebind(sk);
	close(sk);
	return ret;
}

#define MEMBARRIER_CMDBIT_GET_REGISTRATIONS 9

static int kerndat_has_membarrier_get_registrations(void)
{
	int ret = syscall(__NR_membarrier, 1 << MEMBARRIER_CMDBIT_GET_REGISTRATIONS, 0);
	if (ret < 0) {
		if (errno != EINVAL) {
			return ret;
		}

		kdat.has_membarrier_get_registrations = false;
	} else {
		kdat.has_membarrier_get_registrations = true;
	}

	return 0;
}

static int kerndat_has_close_range(void)
{
	/* fd is greater than max_fd, so close_range should return EINVAL. */
	if (cr_close_range(2, 1, 0) == 0) {
		pr_err("close_range succeeded unexpectedly\n");
		return -1;
	}

	if (errno == ENOSYS) {
		pr_debug("close_range isn't supported\n");
		return 0;
	}
	if (errno != EINVAL) {
		pr_perror("close_range returned unexpected error code");
		return -1;
	}

	kdat.has_close_range = true;
	return 0;
}

static int kerndat_has_timer_cr_ids(void)
{
	if (prctl(PR_TIMER_CREATE_RESTORE_IDS,
		  PR_TIMER_CREATE_RESTORE_IDS_GET, 0, 0, 0) == -1) {
		if (errno == EINVAL) {
			pr_debug("PR_TIMER_CREATE_RESTORE_IDS isn't supported\n");
			return 0;
		}
		pr_perror("prctl returned unexpected error code");
		return -1;
	}

	kdat.has_timer_cr_ids = true;
	return 0;
}

static void breakpoint_func(void)
{
	if (raise(SIGSTOP))
		pr_perror("Unable to kill itself with SIGSTOP");
	exit(1);
}

/*
 * kerndat_breakpoints checks that hardware breakpoints work as they should.
 * In some cases, they might not work in virtual machines if the hypervisor
 * doesn't virtualize them. For example, they don't work in AMD SEV virtual
 * machines if the Debug Virtualization extension isn't supported or isn't
 * enabled in SEV_FEATURES.
 */
static int kerndat_breakpoints(void)
{
	int status, ret, exit_code = -1;
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		pr_perror("fork");
		return -1;
	}
	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0)) {
			pr_perror("ptrace(PTRACE_TRACEME)");
			exit(1);
		}
		raise(SIGSTOP);
		breakpoint_func();
		exit(1);
	}
	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("waitpid for initial stop");
		goto err;
	}
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
		pr_err("Child didn't stop as expected: status=%x\n", status);
		goto err;
	}
	ret = ptrace_set_breakpoint(pid, &breakpoint_func);
	if (ret < 0) {
		pr_err("Failed to set breakpoint\n");
		goto err;
	}
	if (ret == 0) {
		pr_debug("Hardware breakpoints appear to be disabled\n");
		goto out;
	}
	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("waitpid for breakpoint trigger");
		goto err;
	}
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		pr_warn("Hardware breakpoints don't seem to work (status=%x)\n", status);
		goto out;
	}
	kdat.has_breakpoints = true;
out:
	exit_code = 0;
err:
	if (kill(pid, SIGKILL)) {
		pr_perror("Failed to kill the child process");
		exit_code = -1;
	}
	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("Failed to wait for the child process");
		exit_code = -1;
	}
	if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) {
		pr_err("The child exited with unexpected code: %x\n", status);
		exit_code = -1;
	}
	return exit_code;
}

static int kerndat_has_madv_guard(void)
{
	void *map;

	map = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (map == MAP_FAILED) {
		pr_perror("Can't mmap a page for has_madv_guard feature test");
		return -1;
	}

	if (madvise(map, PAGE_SIZE, MADV_GUARD_INSTALL)) {
		if (errno != EINVAL) {
			pr_perror("madvise failed (has_madv_guard check)");
			goto mmap_cleanup;
		}
	} else {
		kdat.has_madv_guard = true;
	}

	munmap(map, PAGE_SIZE);
	return 0;

mmap_cleanup:
	munmap(map, PAGE_SIZE);
	return -1;
}

void kerndat_warn_about_madv_guards(void)
{
	if (kdat.has_madv_guard && !kdat.has_pagemap_scan_guard_pages)
		pr_warn("ioctl(PAGEMAP_SCAN) doesn't support PAGE_IS_GUARD flag. "
			"CRIU dump will fail if dumped processes use madvise(MADV_GUARD_INSTALL). "
			"Please, consider updating your kernel.\n");
}

/*
 * Some features depend on resource that can be dynamically changed
 * at the OS runtime. There are cases that we cannot determine the
 * availability of those features at the first time we run kerndat
 * check. So in later kerndat checks, we need to retry to get those
 * information. This function contains calls to those kerndat checks.
 *
 * Those kerndat checks must
 * Return -1 on error
 * Return 0 when the check is successful but no new information
 * Return 1 when the check is successful and there is new information
 */
int kerndat_try_load_new(void)
{
	int ret;

	ret = kerndat_get_hugetlb_dev();
	if (ret < 0)
		return ret;

	ret = kerndat_has_ptrace_get_rseq_conf();
	if (ret < 0) {
		pr_err("kerndat_has_ptrace_get_rseq_conf failed when initializing kerndat.\n");
		return ret;
	}

	ret = kerndat_has_shstk();
	if (ret < 0) {
		pr_err("kerndat_has_shstk failed when initializing kerndat.\n");
		return ret;
	}

	/* New information is found, we need to save to the cache */
	if (ret)
		kerndat_save_cache();
	return 0;
}

static int root_only_init(void)
{
	int ret = 0;

	if (opts.unprivileged)
		return 0;

	if (!ret && kerndat_loginuid()) {
		pr_err("kerndat_loginuid failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_tun_netns()) {
		pr_err("kerndat_tun_netns failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_socket_unix_file()) {
		pr_err("kerndat_socket_unix_file failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_link_nsid()) {
		pr_err("kerndat_link_nsid failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_socket_netns()) {
		pr_err("kerndat_socket_netns failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_nftables_concat()) {
		pr_err("kerndat_has_nftables_concat failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_move_mount_set_group()) {
		pr_err("kerndat_has_move_mount_set_group failed when initializing kerndat.\n");
		ret = -1;
	}

	return ret;
}

int kerndat_init(void)
{
	int ret;

	ret = kerndat_try_load_cache();
	if (ret < 0)
		return ret;

	if (ret == 0)
		return kerndat_try_load_new();

	ret = 0;

	/* kerndat_try_load_cache can leave some trash in kdat */
	memset(&kdat, 0, sizeof(kdat));

	preload_socket_modules();
	if (!opts.unprivileged)
		/*
		 * This uses 'iptables -L' to implicitly load necessary modules.
		 * If the non nft backed iptables is used it does a
		 * openat(AT_FDCWD, "/run/xtables.lock", O_RDONLY|O_CREAT, 0600) = -1 EACCES
		 * which will fail as non-root. There are no capabilities to
		 * change this. The iptables nft backend fails with
		 * openat(AT_FDCWD, "/proc/net/ip_tables_names", O_RDONLY) = -1 EACCES
		 */
		preload_netfilter_modules();

	if (check_pagemap()) {
		pr_err("check_pagemap failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_get_shmemdev()) {
		pr_err("kerndat_get_shmemdev failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_get_hugetlb_dev() < 0) {
		pr_err("kerndat_get_hugetlb_dev failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_get_dirty_track()) {
		pr_err("kerndat_get_dirty_track failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && init_zero_page_pfn()) {
		pr_err("init_zero_page_pfn failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && get_last_cap()) {
		pr_err("get_last_cap failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_fdinfo_has_lock()) {
		pr_err("kerndat_fdinfo_has_lock failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && get_task_size()) {
		pr_err("get_task_size failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && get_ipv6()) {
		pr_err("get_ipv6 failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_nsid()) {
		pr_err("kerndat_nsid failed when initializing kerndat.\n");
		ret = -1;
	}

	if (!ret && root_only_init())
		ret = -1;

	if (!ret && kerndat_iptables_has_xtlocks()) {
		pr_err("kerndat_iptables_has_xtlocks failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_tcp_repair()) {
		pr_err("kerndat_tcp_repair failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_compat_restore()) {
		pr_err("kerndat_compat_restore failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_memfd_create()) {
		pr_err("kerndat_has_memfd_create failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_memfd_hugetlb()) {
		pr_err("kerndat_has_memfd_hugetlb failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_detect_stack_guard_gap()) {
		pr_err("kerndat_detect_stack_guard_gap failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_uffd()) {
		pr_err("kerndat_uffd failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_thp_disable()) {
		pr_err("kerndat_has_thp_disable failed when initializing kerndat.\n");
		ret = -1;
	}
	/* Needs kdat.compat_cr filled before */
	if (!ret && kerndat_vdso_fill_symtable()) {
		pr_err("kerndat_vdso_fill_symtable failed when initializing kerndat.\n");
		ret = -1;
	}
	/* Depends on kerndat_vdso_fill_symtable() */
	if (!ret && kerndat_vdso_preserves_hint()) {
		pr_err("kerndat_vdso_preserves_hint failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_x86_has_ptrace_fpu_xsave_bug()) {
		pr_err("kerndat_x86_has_ptrace_fpu_xsave_bug failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_inotify_setnextwd()) {
		pr_err("kerndat_has_inotify_setnextwd failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && has_kcmp_epoll_tfd()) {
		pr_err("has_kcmp_epoll_tfd failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_fsopen()) {
		pr_err("kerndat_has_fsopen failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_clone3_set_tid()) {
		pr_err("kerndat_has_clone3_set_tid failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && has_time_namespace()) {
		pr_err("has_time_namespace failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && (!opts.unprivileged || has_cap_net_admin(opts.cap_eff)) && kerndat_has_newifindex()) {
		pr_err("kerndat_has_newifindex failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_pidfd_getfd()) {
		pr_err("kerndat_has_pidfd_getfd failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret)
		kerndat_has_pidfd_open();
	if (!ret && kerndat_has_nspid()) {
		pr_err("kerndat_has_nspid failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_sockopt_buf_lock()) {
		pr_err("kerndat_sockopt_buf_lock failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_openat2()) {
		pr_err("kerndat_has_openat2 failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_rseq()) {
		pr_err("kerndat_has_rseq failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && (kerndat_has_ptrace_get_rseq_conf() < 0)) {
		pr_err("kerndat_has_ptrace_get_rseq_conf failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && (kerndat_has_ipv6_freebind() < 0)) {
		pr_err("kerndat_has_ipv6_freebind failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_membarrier_get_registrations()) {
		pr_err("kerndat_has_membarrier_get_registrations failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_shstk()) {
		pr_err("kerndat_has_shstk failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_close_range()) {
		pr_err("kerndat_has_close_range has failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_timer_cr_ids()) {
		pr_err("kerndat_has_timer_cr_ids has failed when initializing kerndat.\n");
	}
	if (!ret && kerndat_breakpoints()) {
		pr_err("kerndat_breakpoints has failed when initializing kerndat.\n");
		ret = -1;
	}
	if (!ret && kerndat_has_madv_guard()) {
		pr_err("kerndat_has_madv_guard has failed when initializing kerndat.\n");
		ret = -1;
	}

	kerndat_lsm();
	kerndat_mmap_min_addr();
	kerndat_files_stat();

	if (!ret)
		kerndat_save_cache();

	return ret;
}
