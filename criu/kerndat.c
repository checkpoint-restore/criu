#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <sys/prctl.h>
#include <sys/inotify.h>


#include "common/config.h"
#include "int.h"
#include "log.h"
#include "restorer.h"
#include "kerndat.h"
#include "fs-magic.h"
#include "mem.h"
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
#include <compel/plugins/std/syscall-codes.h>
#include <compel/compel.h>
#include "netfilter.h"
#include "fsnotify.h"
#include "linux/userfaultfd.h"
#include "prctl.h"
#include "uffd.h"
#include "vdso.h"
#include "kcmp.h"

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
			.name	= "vm/mmap_min_addr",
			.arg	= &value,
			.type	= CTL_U64,
		},
	};

	if (sysctl_op(req, ARRAY_SIZE(req), CTL_READ, 0)) {
		pr_warn("Can't fetch %s value, use default %#lx\n",
			req[0].name, (unsigned long)default_mmap_min_addr);
		kdat.mmap_min_addr = default_mmap_min_addr;
		return;
	}

	if (value < default_mmap_min_addr) {
		pr_debug("Adjust mmap_min_addr %#lx -> %#lx\n",
			 (unsigned long)value,
			 (unsigned long)default_mmap_min_addr);
		kdat.mmap_min_addr = default_mmap_min_addr;
	} else
		kdat.mmap_min_addr = value;

	pr_debug("Found mmap_min_addr %#lx\n",
		 (unsigned long)kdat.mmap_min_addr);
}

int kerndat_files_stat(bool early)
{
	static const uint32_t NR_OPEN_DEFAULT = 1024 * 1024;
	static const uint64_t MAX_FILES_DEFAULT = 8192;
	uint64_t max_files;
	uint32_t nr_open;

	struct sysctl_req req[] = {
		{
			.name	= "fs/file-max",
			.arg	= &max_files,
			.type	= CTL_U64,
		},
		{
			.name	= "fs/nr_open",
			.arg	= &nr_open,
			.type	= CTL_U32,
		},
	};

	if (!early) {
		if (sysctl_op(req, ARRAY_SIZE(req), CTL_READ, 0)) {
			pr_warn("Can't fetch file_stat, using kernel defaults\n");
			nr_open = NR_OPEN_DEFAULT;
			max_files = MAX_FILES_DEFAULT;
		}
	} else {
		char buf[64];
		int fd1, fd2;
		ssize_t ret;

		fd1 = open("/proc/sys/fs/file-max", O_RDONLY);
		fd2 = open("/proc/sys/fs/nr_open", O_RDONLY);

		nr_open = NR_OPEN_DEFAULT;
		max_files = MAX_FILES_DEFAULT;

		if (fd1 < 0 || fd2 < 0) {
			pr_warn("Can't fetch file_stat, using kernel defaults\n");
		} else {
			ret = read(fd1, buf, sizeof(buf) - 1);
			if (ret > 0) {
				buf[ret] = '\0';
				max_files = atol(buf);
			}
			ret = read(fd2, buf, sizeof(buf) - 1);
			if (ret > 0) {
				buf[ret] = '\0';
				nr_open = atol(buf);
			}
		}

		if (fd1 >= 0)
			close(fd1);
		if (fd2 >= 0)
			close(fd2);
	}

	kdat.sysctl_nr_open = nr_open;
	kdat.files_stat_max_files = max_files;

	pr_debug("files stat: %s %lu, %s %u\n",
		 req[0].name, kdat.files_stat_max_files,
		 req[1].name, kdat.sysctl_nr_open);

	return 0;
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

	ret = vaddr_to_pfn(-1, (unsigned long)addr, &kdat.zero_page_pfn);
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

static int get_task_size(void)
{
	kdat.task_size = compel_task_size();
	pr_debug("Found task size of %lx\n", kdat.task_size);
	return 0;
}

int kerndat_fdinfo_has_lock()
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

int kerndat_loginuid(void)
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
	if (prepare_loginuid(INVALID_UID, LOG_WARN) < 0)
		return 0;
	/* Cleaning value back as it was */
	if (prepare_loginuid(saved_loginuid, LOG_WARN) < 0)
		return 0;

	kdat.luid = LUID_FULL;
	return 0;
}

static int kerndat_iptables_has_xtlocks(void)
{
	int fd;
	char *argv[4] = { "sh", "-c", "iptables -w -L", NULL };

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

int kerndat_tcp_repair(void)
{
	int sock, clnt = -1, yes = 1, exit_code = -1;
	struct sockaddr_in addr;
	socklen_t aux;

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));
	addr.sin_port = 0;
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		pr_perror("Unable to create a socket");
		return -1;
	}

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_perror("Unable to bind a socket");
		goto err;
	}

	aux = sizeof(addr);
	if (getsockname(sock, (struct sockaddr *) &addr, &aux)) {
		pr_perror("Unable to get a socket name");
		goto err;
	}

	if (listen(sock, 1)) {
		pr_perror("Unable to listen a socket");
		goto err;
	}

	clnt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (clnt < 0) {
		pr_perror("Unable to create a socket");
		goto err;
	}

	if (connect(clnt, (struct sockaddr *) &addr, sizeof(addr))) {
		pr_perror("Unable to connect a socket");
		goto err;
	}

	if (shutdown(clnt, SHUT_WR)) {
		pr_perror("Unable to shutdown a socket");
		goto err;
	}

	if (setsockopt(clnt, SOL_TCP, TCP_REPAIR, &yes, sizeof(yes))) {
		if (errno != EPERM)
			goto err;
		kdat.has_tcp_half_closed = false;
	} else
		kdat.has_tcp_half_closed = true;

	exit_code = 0;
err:
	close_safe(&clnt);
	close(sock);

	return exit_code;
}

int kerndat_nsid(void)
{
	int nsid, sk;

	sk = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sk < 0) {
		pr_perror("Unable to create a netlink socket");
		return -1;
	}

	if (net_get_nsid(sk, getpid(), &nsid) < 0) {
		pr_err("NSID is not supported\n");
		close(sk);
		return -1;
	}

	kdat.has_nsid = true;
	close(sk);
	return 0;
}

static int kerndat_compat_restore(void)
{
	int ret;

	ret = kdat_can_map_vdso();
	if (ret < 0)
		return ret;
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

	mem = mmap(NULL, (3ul << 20), PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
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
		munmap(mem, 4096);
		return -1;
	}

	while (fgets(buf, sizeof(buf), maps)) {
		num = sscanf(buf, "%lx-%lx %c%c%c%c",
			     &start, &end, &r, &w, &x, &s);
		if (num < 6) {
			pr_err("Can't parse: %s\n", buf);
			goto err;
		}

		/*
		 * When reading /proc/$pid/[s]maps the
		 * start/end addresses might be cutted off
		 * with PAGE_SIZE on kernels prior 4.12
		 * (see kernel commit 1be7107fbe18ee).
		 *
		 * Same time there was semi-complete
		 * patch released which hitted a number
		 * of repos (Ubuntu, Fedora) where instead
		 * of PAGE_SIZE the 1M gap is cutted off.
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

int kerndat_has_inotify_setnextwd(void)
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

int has_kcmp_epoll_tfd(void)
{
	kcmp_epoll_slot_t slot = { };
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

int __attribute__((weak)) kdat_x86_has_ptrace_fpu_xsave_bug(void)
{
	return 0;
}

static int kerndat_x86_has_ptrace_fpu_xsave_bug(void)
{
	int ret = kdat_x86_has_ptrace_fpu_xsave_bug();

	if (ret < 0)
		return ret;

	kdat.x86_has_ptrace_fpu_xsave_bug = !!ret;
	return 0;
}

#define KERNDAT_CACHE_FILE	KDAT_RUNDIR"/criu.kdat"
#define KERNDAT_CACHE_FILE_TMP	KDAT_RUNDIR"/.criu.kdat"

static int kerndat_try_load_cache(void)
{
	int fd, ret;

	fd = open(KERNDAT_CACHE_FILE, O_RDONLY);
	if (fd < 0) {
		if(ENOENT == errno)
			pr_debug("File %s does not exist\n", KERNDAT_CACHE_FILE);
		else
			pr_warn("Can't load %s\n", KERNDAT_CACHE_FILE);
		return 1;
	}

	ret = read(fd, &kdat, sizeof(kdat));
	if (ret < 0) {
		pr_perror("Can't read kdat cache");
		close(fd);
		return -1;
	}

	close(fd);

	if (ret != sizeof(kdat) ||
			kdat.magic1 != KDAT_MAGIC ||
			kdat.magic2 != KDAT_MAGIC_2) {
		pr_warn("Stale %s file\n", KERNDAT_CACHE_FILE);
		unlink(KERNDAT_CACHE_FILE);
		return 1;
	}

	pr_info("Loaded kdat cache from %s\n", KERNDAT_CACHE_FILE);
	return 0;
}

static void kerndat_save_cache(void)
{
	int fd, ret;
	struct statfs s;

	fd = open(KERNDAT_CACHE_FILE_TMP, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd < 0)
		/*
		 * It can happen that we race with some other criu
		 * instance. That's OK, just ignore this error and
		 * proceed.
		 */
		return;

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
		ret = rename(KERNDAT_CACHE_FILE_TMP, KERNDAT_CACHE_FILE);
	else {
		ret = -1;
		errno = EIO;
	}

	if (ret < 0) {
		pr_perror("Couldn't save %s", KERNDAT_CACHE_FILE);
unl:
		unlink(KERNDAT_CACHE_FILE_TMP);
	}
}

int kerndat_uffd(void)
{
	int uffd;

	kdat.uffd_features = 0;
	uffd = uffd_open(0, &kdat.uffd_features);

	/*
	 * uffd == -ENOSYS means userfaultfd is not supported on this
	 * system and we just happily return with kdat.has_uffd = false.
	 * Error other than -ENOSYS would mean "Houston, Houston, we
	 * have a problem!"
	 */
	if (uffd < 0) {
		if (uffd == -ENOSYS)
			return 0;

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
		if (errno != EINVAL)
			return -1;
		pr_info("PR_SET_THP_DISABLE is not available\n");
		return 0;
	}

	addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (addr == MAP_FAILED) {
		pr_perror("Can't mmap memory for THP disable test");
		return -1;
	}

	if (prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0))
		return -1;

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

int kerndat_init(void)
{
	int ret;

	ret = kerndat_try_load_cache();
	if (ret <= 0)
		return ret;

	/* kerndat_try_load_cache can leave some trash in kdat */
	memset(&kdat, 0, sizeof(kdat));

	preload_socket_modules();
	preload_netfilter_modules();

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
		ret = kerndat_loginuid();
	if (!ret)
		ret = kerndat_iptables_has_xtlocks();
	if (!ret)
		ret = kerndat_tcp_repair();
	if (!ret)
		ret = kerndat_compat_restore();
	if (!ret)
		ret = kerndat_socket_netns();
	if (!ret)
		ret = kerndat_tun_netns();
	if (!ret)
		ret = kerndat_socket_unix_file();
	if (!ret)
		ret = kerndat_nsid();
	if (!ret)
		ret = kerndat_link_nsid();
	if (!ret)
		ret = kerndat_has_memfd_create();
	if (!ret)
		ret = kerndat_detect_stack_guard_gap();
	if (!ret)
		ret = kerndat_uffd();
	if (!ret)
		ret = kerndat_has_thp_disable();
	/* Needs kdat.compat_cr filled before */
	if (!ret)
		ret = kerndat_vdso_fill_symtable();
	/* Depends on kerndat_vdso_fill_symtable() */
	if (!ret)
		ret = kerndat_vdso_preserves_hint();
	if (!ret)
		ret = kerndat_socket_netns();
	if (!ret)
		ret = kerndat_nsid();
	if (!ret)
		ret = kerndat_x86_has_ptrace_fpu_xsave_bug();
	if (!ret)
		ret = kerndat_has_inotify_setnextwd();
	if (!ret)
		ret = has_kcmp_epoll_tfd();

	kerndat_lsm();
	kerndat_mmap_min_addr();
	kerndat_files_stat(false);

	if (!ret)
		kerndat_save_cache();

	return ret;
}
