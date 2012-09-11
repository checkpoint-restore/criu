#include <sys/mman.h>
#include <errno.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/mount.h>

#include "syscall.h"
#include "parasite.h"

#include <string.h>

/*
 * Some notes on parasite code overall. There are a few
 * calling convention specfics the caller must follow
 *
 * - on success, 0 must be returned, anything else
 *   treated as error; note that if 0 returned the
 *   caller code should not expect anything sane in
 *   parasite_status_t, parasite may not touch it at
 *   all
 *
 * - every routine which takes arguments and called from
 *   parasite_head
 *     parasite_service
 *   must provide parasite_status_t argument either via
 *   plain pointer or as first member of an embedding
 *   structure so service routine will pass error code
 *   there
 */

#ifdef CONFIG_X86_64

static void *brk_start, *brk_end, *brk_tail;

static int logfd = -1;
static int tsock = -1;

#define MAX_HEAP_SIZE	(10 << 20)	/* Hope 10MB will be enough...  */

static int brk_init(void)
{
	unsigned long ret;
	/*
	 *  Map 10 MB. Hope this will be enough for unix skb's...
	 */
	ret = sys_mmap(NULL, MAX_HEAP_SIZE,
			    PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret < 0)
		return -ENOMEM;

	brk_start = brk_tail = (void *)ret;
	brk_end = brk_start + MAX_HEAP_SIZE;
	return 0;
}

static void brk_fini(void)
{
	sys_munmap(brk_start, MAX_HEAP_SIZE);
}

static void *brk_alloc(unsigned long bytes)
{
	void *addr = NULL;
	if (brk_end >= (brk_tail + bytes)) {
		addr	= brk_tail;
		brk_tail+= bytes;
	}
	return addr;
}

static void brk_free(unsigned long bytes)
{
	if (brk_start >= (brk_tail - bytes))
		brk_tail -= bytes;
}

#if 0
static const unsigned char hex[] = "0123456789abcdef";
static char *long2hex(unsigned long v)
{
	static char buf[32];
	char *p = buf;
	int i;

	for (i = sizeof(long) - 1; i >= 0; i--) {
		*p++ = hex[ ((((unsigned char *)&v)[i]) & 0xf0) >> 4 ];
		*p++ = hex[ ((((unsigned char *)&v)[i]) & 0x0f) >> 0 ];
	}
	*p = 0;

	return buf;
}
#endif

static void sys_write_msg(const char *msg)
{
	int size = 0;
	while (msg[size])
		size++;
	sys_write(logfd, msg, size);
}

#define PME_PRESENT	(1ULL << 63)
#define PME_SWAP	(1ULL << 62)
#define PME_FILE	(1ULL << 61)

static inline int should_dump_page(VmaEntry *vmae, u64 pme)
{
	if (vma_entry_is(vmae, VMA_AREA_VDSO))
		return 1;
	/*
	 * Optimisation for private mapping pages, that haven't
	 * yet being COW-ed
	 */
	if (vma_entry_is(vmae, VMA_FILE_PRIVATE) && (pme & PME_FILE))
		return 0;
	if (pme & (PME_PRESENT | PME_SWAP))
		return 1;

	return 0;
}

static int fd_pages = -1;

static int dump_pages_init()
{
	fd_pages = recv_fd(tsock);
	if (fd_pages < 0)
		return fd_pages;

	return 0;
}

static int sys_write_safe(int fd, void *buf, int size)
{
	int ret;

	ret = sys_write(fd, buf, size);
	if (ret < 0) {
		sys_write_msg("sys_write failed\n");
		return ret;
	}

	if (ret != size) {
		sys_write_msg("not all data was written\n");
		ret = -EIO;
	}

	return 0;
}

/*
 * This is the main page dumping routine, it's executed
 * inside a victim process space.
 */
static int dump_pages(struct parasite_dump_pages_args *args)
{
	unsigned long nrpages, pfn, length;
	unsigned long prot_old, prot_new;
	u64 *map, off;
	int ret = -1, fd;

	args->nrpages_dumped = 0;
	args->nrpages_skipped = 0;
	prot_old = prot_new = 0;

	pfn = args->vma_entry.start / PAGE_SIZE;
	nrpages	= (args->vma_entry.end - args->vma_entry.start) / PAGE_SIZE;
	args->nrpages_total = nrpages;
	length = nrpages * sizeof(*map);

	/*
	 * Up to 10M of pagemap will handle 5G mapping.
	 */
	map = brk_alloc(length);
	if (!map) {
		ret = -ENOMEM;
		goto err;
	}

	fd = sys_open("/proc/self/pagemap", O_RDONLY, 0);
	if (fd < 0) {
		sys_write_msg("Can't open self pagemap");
		ret = fd;
		goto err_free;
	}

	off = pfn * sizeof(*map);
	off = sys_lseek(fd, off, SEEK_SET);
	if (off != pfn * sizeof(*map)) {
		sys_write_msg("Can't seek pagemap");
		ret = off;
		goto err_close;
	}

	ret = sys_read(fd, map, length);
	if (ret != length) {
		sys_write_msg("Can't read self pagemap");
		goto err_free;
	}

	sys_close(fd);
	fd = fd_pages;

	/*
	 * Try to change page protection if needed so we would
	 * be able to dump contents.
	 */
	if (!(args->vma_entry.prot & PROT_READ)) {
		prot_old = (unsigned long)args->vma_entry.prot;
		prot_new = prot_old | PROT_READ;
		ret = sys_mprotect((void *)args->vma_entry.start,
				   (unsigned long)vma_entry_len(&args->vma_entry),
				   prot_new);
		if (ret) {
			sys_write_msg("sys_mprotect failed\n");
			goto err_free;
		}
	}

	ret = 0;
	for (pfn = 0; pfn < nrpages; pfn++) {
		unsigned long vaddr;

		if (should_dump_page(&args->vma_entry, map[pfn])) {
			/*
			 * That's the optimized write of
			 * page_entry structure, see image.h
			 */
			vaddr = (unsigned long)args->vma_entry.start + pfn * PAGE_SIZE;

			ret = sys_write_safe(fd, &vaddr, sizeof(vaddr));
			if (ret)
				return ret;
			ret = sys_write_safe(fd, (void *)vaddr, PAGE_SIZE);
			if (ret)
				return ret;

			args->nrpages_dumped++;
		} else if (map[pfn] & PME_PRESENT)
			args->nrpages_skipped++;
	}

	/*
	 * Don't left pages readable if they were not.
	 */
	if (prot_old != prot_new) {
		ret = sys_mprotect((void *)args->vma_entry.start,
				   (unsigned long)vma_entry_len(&args->vma_entry),
				   prot_old);
		if (ret) {
			sys_write_msg("PANIC: Ouch! sys_mprotect failed on restore\n");
			goto err_free;
		}
	}

	ret = 0;
err_free:
	brk_free(length);
err:
	return ret;

err_close:
	sys_close(fd);
	goto err_free;
}

static int dump_pages_fini(void)
{
	return sys_close(fd_pages);
}

static int dump_sigact(struct parasite_dump_sa_args *da)
{
	int sig, ret = 0;

	for (sig = 1; sig < SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = sys_sigaction(sig, NULL, &da->sas[sig], sizeof(rt_sigset_t));
		if (ret < 0) {
			sys_write_msg("sys_sigaction failed\n");
			break;
		}
	}

	return ret;
}

static int dump_itimers(struct parasite_dump_itimers_args *args)
{
	int ret;

	ret = sys_getitimer(ITIMER_REAL, &args->real);
	if (!ret)
		ret = sys_getitimer(ITIMER_VIRTUAL, &args->virt);
	if (!ret)
		ret = sys_getitimer(ITIMER_PROF, &args->prof);

	if (ret)
		sys_write_msg("getitimer failed\n");

	return ret;
}

static k_rtsigset_t old_blocked;
static int reset_blocked = 0;

static int dump_misc(struct parasite_dump_misc *args)
{
	args->secbits = sys_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	args->brk = sys_brk(0);
	args->blocked = old_blocked;

	args->pid = sys_getpid();
	args->sid = sys_getsid();
	args->pgid = sys_getpgid();

	return 0;
}

static int dump_tid_info(struct parasite_dump_tid_info *args)
{
	int ret;

	ret = sys_prctl(PR_GET_TID_ADDRESS, (unsigned long) &args->tid_addr, 0, 0, 0);
	if (ret)
		return ret;

	args->tid = sys_gettid();

	return 0;
}

static int drain_fds(struct parasite_drain_fd *args)
{
	int ret;

	ret = send_fds(tsock, NULL, 0,
		       args->fds, args->nr_fds, true);
	if (ret)
		sys_write_msg("send_fds failed\n");

	return ret;
}

static int init(struct parasite_init_args *args)
{
	k_rtsigset_t to_block;
	int ret;

	ret = brk_init();
	if (ret)
		return -ret;

	tsock = sys_socket(PF_UNIX, SOCK_DGRAM, 0);
	if (tsock < 0)
		return -tsock;

	ret = sys_bind(tsock, (struct sockaddr *) &args->p_addr, args->p_addr_len);
	if (ret < 0)
		return ret;

	ret = sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len);
	if (ret < 0)
		return ret;

	ksigfillset(&to_block);
	ret = sys_sigprocmask(SIG_SETMASK, &to_block, &old_blocked, sizeof(k_rtsigset_t));
	if (ret < 0)
		reset_blocked = ret;
	else
		reset_blocked = 1;

	return ret;
}

static char proc_mountpoint[] = "proc.crtools";
static int parasite_get_proc_fd()
{
	int ret, fd = -1;
	char buf[2];

	ret = sys_readlink("/proc/self", buf, sizeof(buf));
	if (ret < 0 && ret != -ENOENT) {
		sys_write_msg("Can't readlink /proc/self\n");
		return ret;
	}

	/* Fast path -- if /proc belongs to this pidns */
	if (ret == 1 && buf[0] == '1') {
		fd = sys_open("/proc", O_RDONLY, 0);
		goto out_send_fd;
	}

	if (sys_mkdir(proc_mountpoint, 0700)) {
		sys_write_msg("Can't create a directory ");
		sys_write_msg(proc_mountpoint);
		sys_write_msg("\n");
		return ret;
	}

	if (sys_mount("proc", proc_mountpoint, "proc", MS_MGC_VAL, NULL)) {
		sys_write_msg("mount failed\n");
		ret = -1;
		goto out_rmdir;
	}

	fd = sys_open(proc_mountpoint, O_RDONLY, 0);

	if (sys_umount2(proc_mountpoint, MNT_DETACH)) {
		sys_write_msg("Can't umount procfs\n");
		return -1;
	}

out_rmdir:
	if (sys_rmdir(proc_mountpoint)) {
		sys_write_msg("Can't remove directory\n");
		return -1;
	}

out_send_fd:
	if (fd < 0)
		return fd;
	ret = send_fd(tsock, NULL, 0, fd);
	sys_close(fd);
	return ret;
}

static int parasite_set_logfd()
{
	int ret;

	ret = recv_fd(tsock);
	if (ret >= 0) {
		logfd = ret;
		ret = 0;
	}

	return ret;
}

static int fini(void)
{
	if (reset_blocked == 1)
		sys_sigprocmask(SIG_SETMASK, &old_blocked, NULL, sizeof(k_rtsigset_t));
	sys_close(logfd);
	sys_close(tsock);
	brk_fini();

	return 0;
}

int __used parasite_service(unsigned long cmd, void *args)
{
	BUILD_BUG_ON(sizeof(struct parasite_dump_pages_args) > PARASITE_ARG_SIZE);
	BUILD_BUG_ON(sizeof(struct parasite_init_args) > PARASITE_ARG_SIZE);
	BUILD_BUG_ON(sizeof(struct parasite_dump_misc) > PARASITE_ARG_SIZE);
	BUILD_BUG_ON(sizeof(struct parasite_dump_tid_info) > PARASITE_ARG_SIZE);
	BUILD_BUG_ON(sizeof(struct parasite_drain_fd) > PARASITE_ARG_SIZE);

	switch (cmd) {
	case PARASITE_CMD_INIT:
		return init((struct parasite_init_args *) args);
	case PARASITE_CMD_FINI:
		return fini();
	case PARASITE_CMD_SET_LOGFD:
		return parasite_set_logfd();
	case PARASITE_CMD_DUMPPAGES_INIT:
		return dump_pages_init();
	case PARASITE_CMD_DUMPPAGES_FINI:
		return dump_pages_fini();
	case PARASITE_CMD_DUMPPAGES:
		return dump_pages((struct parasite_dump_pages_args *)args);
	case PARASITE_CMD_DUMP_SIGACTS:
		return dump_sigact((struct parasite_dump_sa_args *)args);
	case PARASITE_CMD_DUMP_ITIMERS:
		return dump_itimers((struct parasite_dump_itimers_args *)args);
	case PARASITE_CMD_DUMP_MISC:
		return dump_misc((struct parasite_dump_misc *)args);
	case PARASITE_CMD_DUMP_TID_ADDR:
		return dump_tid_info((struct parasite_dump_tid_info *)args);
	case PARASITE_CMD_DRAIN_FDS:
		return drain_fds((struct parasite_drain_fd *)args);
	case PARASITE_CMD_GET_PROC_FD:
		return parasite_get_proc_fd();
	}

	sys_write_msg("Unknown command to parasite\n");
	return -EINVAL;
}

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */
