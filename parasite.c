#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "parasite.h"
#include "util.h"
#include "util-net.h"

#ifdef CONFIG_X86_64

static void *brk_start, *brk_end, *brk_tail;

static struct page_entry page;
static struct vma_entry vma;
static int logfd = -1;
static int tsock = -1;

#define MAX_HEAP_SIZE	(10 << 20)	/* Hope 10MB will be enough...  */

static int brk_init(void)
{
	unsigned long ret;
	/*
	 *  Map 10 MB. Hope this will be enough for unix skb's...
	 */
       ret = sys_mmap(0, MAX_HEAP_SIZE,
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
	sys_munmap(brk_start, brk_end - brk_start);
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

static unsigned long builtin_strlen(char *str)
{
	unsigned long len = 0;
	while (*str++)
		len++;
	return len;
}

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

static void sys_write_msg(const char *msg)
{
	int size = 0;
	while (msg[size])
		size++;
	sys_write(logfd, msg, size);
}

static inline int should_dump_page(struct vma_entry *vmae, unsigned char mincore_flags)
{
#ifdef PAGE_ANON
	if (vma_entry_is(vmae, VMA_FILE_PRIVATE))
		return mincore_flags & PAGE_ANON;
	else
		return mincore_flags & PAGE_RSS;
#else
	return (mincore_flags & PAGE_RSS);
#endif
}

static int fd_pages[2] = { -1, -1 };

static int dump_pages_init(parasite_status_t *st)
{
	fd_pages[PG_PRIV] = recv_fd(tsock);
	if (fd_pages[PG_PRIV] < 0)
		goto err;

	fd_pages[PG_SHARED] = recv_fd(tsock);
	if (fd_pages[PG_SHARED] < 0)
		goto err_s;

	SET_PARASITE_STATUS(st, 0, 0);
	return 0;

err_s:
	sys_close(fd_pages[PG_PRIV]);
err:
	SET_PARASITE_STATUS(st, PARASITE_ERR_FAIL, -1);
	return -1;
}

/*
 * This is the main page dumping routine, it's executed
 * inside a victim process space.
 */
static int dump_pages(struct parasite_dump_pages_args *args)
{
	parasite_status_t *st = &args->status;
	unsigned long nrpages, pfn, length;
	unsigned long prot_old, prot_new;
	unsigned char *map;
	int ret = PARASITE_ERR_FAIL, fd;

	args->nrpages_dumped = 0;
	prot_old = prot_new = 0;

	fd = fd_pages[args->fd_type];

	/* Start from the end of file */
	sys_lseek(fd, 0, SEEK_END);

	length	= args->vma_entry.end - args->vma_entry.start;
	nrpages	= length / PAGE_SIZE;

	/*
	 * brk should allow us to handle up to 128M of memory,
	 * otherwise call for mmap.
	 */
	map = brk_alloc(nrpages);
	if (!map) {
		SET_PARASITE_STATUS(st, PARASITE_ERR_MMAP, (long)map);
		ret = st->ret;
		goto err;
	}

	/*
	 * Try to change page protection if needed so we would
	 * be able to dump contents.
	 */
	if (!(args->vma_entry.prot & PROT_READ)) {
		prot_old = (unsigned long)args->vma_entry.prot;
		prot_new = prot_old | PROT_READ;
		ret = sys_mprotect((unsigned long)args->vma_entry.start,
				   (unsigned long)vma_entry_len(&args->vma_entry),
				   prot_new);
		if (ret) {
			sys_write_msg("sys_mprotect failed\n");
			SET_PARASITE_STATUS(st, PARASITE_ERR_MPROTECT, ret);
			ret = st->ret;
			goto err_free;
		}
	}

	/*
	 * Dumping the whole VMA range is not a common operation
	 * so stick for mincore as a basis.
	 */

	ret = sys_mincore((unsigned long)args->vma_entry.start, length, map);
	if (ret) {
		sys_write_msg("sys_mincore failed\n");
		SET_PARASITE_STATUS(st, PARASITE_ERR_MINCORE, ret);
		ret = st->ret;
		goto err_free;
	}

	ret = 0;
	for (pfn = 0; pfn < nrpages; pfn++) {
		unsigned long vaddr, written;

		if (should_dump_page(&args->vma_entry, map[pfn])) {
			/*
			 * That's the optimized write of
			 * page_entry structure, see image.h
			 */
			vaddr = (unsigned long)args->vma_entry.start + pfn * PAGE_SIZE;
			written = 0;

			written += sys_write(fd, &vaddr, sizeof(vaddr));
			written += sys_write(fd, (void *)vaddr, PAGE_SIZE);
			if (written != sizeof(vaddr) + PAGE_SIZE) {
				SET_PARASITE_STATUS(st, PARASITE_ERR_WRITE, written);
				ret = st->ret;
				goto err_free;
			}

			args->nrpages_dumped++;
		}
	}

	/*
	 * Don't left pages readable if they were not.
	 */
	if (prot_old != prot_new) {
		ret = sys_mprotect((unsigned long)args->vma_entry.start,
				   (unsigned long)vma_entry_len(&args->vma_entry),
				   prot_old);
		if (ret) {
			sys_write_msg("PANIC: Ouch! sys_mprotect failed on restore\n");
			SET_PARASITE_STATUS(st, PARASITE_ERR_MPROTECT, ret);
			ret = st->ret;
			goto err_free;
		}
	}

	/* on success ret = 0 */
	SET_PARASITE_STATUS(st, ret, ret);

err_free:
	brk_free(nrpages);
err:
	return ret;
}

static int dump_pages_fini(void)
{
	sys_close(fd_pages[PG_PRIV]);
	sys_close(fd_pages[PG_SHARED]);
	return 0;
}

static int dump_sigact(parasite_status_t *st)
{
	rt_sigaction_t act;
	struct sa_entry e;
	int fd, sig;

	int ret = PARASITE_ERR_FAIL;

	fd = recv_fd(tsock);
	if (fd < 0)
		return fd;

	sys_lseek(fd, MAGIC_OFFSET, SEEK_SET);

	for (sig = 1; sig < SIGMAX; sig++) {
		if (sig == SIGKILL || sig == SIGSTOP)
			continue;

		ret = sys_sigaction(sig, NULL, &act);
		if (ret < 0) {
			sys_write_msg("sys_sigaction failed\n");
			SET_PARASITE_STATUS(st, PARASITE_ERR_SIGACTION, ret);
			ret = st->ret;
			goto err_close;
		}

		ASSIGN_TYPED(e.sigaction, act.rt_sa_handler);
		ASSIGN_TYPED(e.flags, act.rt_sa_flags);
		ASSIGN_TYPED(e.restorer, act.rt_sa_restorer);
		ASSIGN_TYPED(e.mask, act.rt_sa_mask.sig[0]);

		ret = sys_write(fd, &e, sizeof(e));
		if (ret != sizeof(e)) {
			sys_write_msg("sys_write failed\n");
			SET_PARASITE_STATUS(st, PARASITE_ERR_WRITE, ret);
			ret = st->ret;
			goto err_close;
		}
	}

	ret = 0;
	SET_PARASITE_STATUS(st, 0, ret);

err_close:
	sys_close(fd);
	return ret;
}

static int dump_itimer(int which, int fd, parasite_status_t *st)
{
	struct itimerval val;
	int ret;
	struct itimer_entry ie;

	ret = sys_getitimer(which, &val);
	if (ret < 0) {
		sys_write_msg("getitimer failed\n");
		SET_PARASITE_STATUS(st, PARASITE_ERR_GETITIMER, ret);
		return st->ret;
	}

	ie.isec = val.it_interval.tv_sec;
	ie.iusec = val.it_interval.tv_usec;
	ie.vsec = val.it_value.tv_sec;
	ie.vusec = val.it_value.tv_sec;

	ret = sys_write(fd, &ie, sizeof(ie));
	if (ret != sizeof(ie)) {
		sys_write_msg("sys_write failed\n");
		SET_PARASITE_STATUS(st, PARASITE_ERR_WRITE, ret);
		return st->ret;
	}

	return 0;
}

static int dump_itimers(parasite_status_t *st)
{
	rt_sigaction_t act;
	struct sa_entry e;
	int fd, sig;

	int ret = PARASITE_ERR_FAIL;

	fd = recv_fd(tsock);
	if (fd < 0)
		return fd;

	sys_lseek(fd, MAGIC_OFFSET, SEEK_SET);

	ret = dump_itimer(ITIMER_REAL, fd, st);
	if (ret < 0)
		goto err_close;

	ret = dump_itimer(ITIMER_VIRTUAL, fd, st);
	if (ret < 0)
		goto err_close;

	ret = dump_itimer(ITIMER_PROF, fd, st);
	if (ret < 0)
		goto err_close;

	ret = 0;
	SET_PARASITE_STATUS(st, 0, ret);

err_close:
	sys_close(fd);
	return ret;
}

static k_rtsigset_t old_blocked;
static int reset_blocked = 0;

static int dump_misc(struct parasite_dump_misc *args)
{
	parasite_status_t *st = &args->status;

	args->secbits = sys_prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	args->brk = sys_brk(0);
	args->blocked = old_blocked;

	SET_PARASITE_STATUS(st, 0, 0);
	return 0;
}

static int dump_tid_addr(struct parasite_dump_tid_addr *args)
{
	parasite_status_t *st = &args->status;
	int ret;

	ret = sys_prctl(PR_GET_TID_ADDR, (unsigned long) &args->tid_addr, 0, 0, 0);

	SET_PARASITE_STATUS(st, 0, ret);
	return 0;
}

static int dump_socket_queue(int img_fd, struct sk_queue_item *item, int *err)
{
	struct sk_packet_entry *pe;
	unsigned long size;
	socklen_t tmp;
	int ret, orig_peek_off;
	int sock_fd = item->fd;

	/*
	 * Save original peek offset. 
	 */
	ret = sys_getsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, &tmp);
	if (ret < 0) {
		sys_write_msg("getsockopt failed\n");
		*err = ret;
		return PARASITE_ERR_FAIL;
	}
	/*
	 * Discover max DGRAM size
	 */
	ret = sys_getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &ret, &tmp);
	if (ret < 0) {
		sys_write_msg("getsockopt failed\n");
		*err = ret;
		return PARASITE_ERR_FAIL;
	}
	/*
	 * Note: 32 bytes will be used by kernel for protocol header.
	 */
	size = ret - 32;
	/*
	 * Try to alloc buffer for max supported DGRAM + our header.
	 * Note: STREAM queue will be written by chunks of this size.
	 */
	pe = brk_alloc(size + sizeof(struct sk_packet_entry));
	if (!pe) {
		sys_write_msg("not enough mem for skb\n");
		*err = -ENOMEM;
		return PARASITE_ERR_MMAP;
	}
	/*
	 * Enable peek offset incrementation.
	 */
	ret = 0;
	*err = sys_setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &ret, sizeof(int));
	if (*err < 0) {
		sys_write_msg("setsockopt fail\n");
		ret = PARASITE_ERR_FAIL;
		goto err_brk;
	}

	pe->id_for = item->sk_id;

	while (1) {
		struct iovec iov = {
			.iov_base	= pe->data,
			.iov_len	= size,
		};
		struct msghdr msg = {
			.msg_iov	= &iov,
			.msg_iovlen	= 1,
		};

		*err = pe->length = sys_recvmsg(sock_fd, &msg, MSG_DONTWAIT | MSG_PEEK);
		if (*err < 0) {
			if (*err == -EAGAIN)
				break; /* we're done */
			sys_write_msg("sys_recvmsg fail: error\n");
			ret = PARASITE_ERR_FAIL;
			goto err_set_sock;
		}
		if (msg.msg_flags & MSG_TRUNC) {
			/*
			 * DGRAM thuncated. This should not happen. But we have
			 * to check...
			 */
			sys_write_msg("sys_recvmsg failed: truncated\n");
			ret = PARASITE_ERR_FAIL;
			*err = -E2BIG;
			goto err_set_sock;
		}
		*err = sys_write(img_fd, pe, sizeof(pe) + pe->length);
		if (*err != sizeof(pe) + pe->length) {
			sys_write_msg("sys_write failed\n");
			ret = PARASITE_ERR_WRITE;
			goto err_set_sock;
		}
	}
	ret = 0;
err_set_sock:
	/*
	 * Restore original peek offset. 
	 */
	sys_setsockopt(sock_fd, SOL_SOCKET, SO_PEEK_OFF, &orig_peek_off, sizeof(int));
err_brk:
	brk_free(size + sizeof(struct sk_packet_entry));
	return ret;
}

static int dump_skqueues(struct parasite_dump_sk_queues *args)
{
	parasite_status_t *st = &args->status;
	int img_fd, i, ret = -1;

	img_fd = recv_fd(tsock);
	if (img_fd < 0)
		return img_fd;

	for (i = 0; i < args->nr_items; i++) {
		int err;

		ret = dump_socket_queue(img_fd, &args->items[i], &err);
		if (ret < 0) {
			SET_PARASITE_STATUS(st, ret, err);
			goto err_dmp;
		}
	}

	ret = 0;
	SET_PARASITE_STATUS(st, 0, 0);
err_dmp:
	sys_close(img_fd);
	return ret;
}

static int init(struct parasite_init_args *args)
{
	int ret;
	k_rtsigset_t to_block;

	if (brk_init() < 0)
		return -1;

	tsock = sys_socket(PF_UNIX, SOCK_DGRAM, 0);
	if (tsock < 0) {
		return -1;
	}

	ret = sys_bind(tsock, (struct sockaddr *) &args->saddr, args->sun_len);
	if (ret < 0) {
		return -1;
	}

	ksigfillset(&to_block);
	ret = sys_sigprocmask(SIG_SETMASK, &to_block, &old_blocked);
	if (ret < 0)
		reset_blocked = ret;
	else
		reset_blocked = 1;

	SET_PARASITE_STATUS(&args->status, ret, ret);
	return ret;
}

static int parasite_set_logfd(void)
{
	logfd = recv_fd(tsock);
	return logfd;
}

static int fini(void)
{
	if (reset_blocked == 1)
		sys_sigprocmask(SIG_SETMASK, &old_blocked, NULL);
	sys_close(logfd);
	sys_close(tsock);
	brk_fini();
	return 0;
}

static int __used parasite_service(unsigned long cmd, void *args)
{
	BUILD_BUG_ON(sizeof(struct parasite_dump_pages_args) > PARASITE_ARG_SIZE);
	BUILD_BUG_ON(sizeof(struct parasite_init_args) > PARASITE_ARG_SIZE);
	BUILD_BUG_ON(sizeof(struct parasite_dump_misc) > PARASITE_ARG_SIZE);

	switch (cmd) {
	case PARASITE_CMD_INIT:
		return init((struct parasite_init_args *) args);
	case PARASITE_CMD_FINI:
		return fini();
	case PARASITE_CMD_SET_LOGFD:
		return parasite_set_logfd();
	case PARASITE_CMD_DUMPPAGES_INIT:
		return dump_pages_init((parasite_status_t *) args);
	case PARASITE_CMD_DUMPPAGES_FINI:
		return dump_pages_fini();
	case PARASITE_CMD_DUMPPAGES:
		return dump_pages((struct parasite_dump_pages_args *)args);
	case PARASITE_CMD_DUMP_SIGACTS:
		return dump_sigact((parasite_status_t *)args);
	case PARASITE_CMD_DUMP_ITIMERS:
		return dump_itimers((parasite_status_t *)args);
	case PARASITE_CMD_DUMP_MISC:
		return dump_misc((struct parasite_dump_misc *)args);
	case PARASITE_CMD_DUMP_TID_ADDR:
		return dump_tid_addr((struct parasite_dump_tid_addr *)args);
	case PARASITE_CMD_DUMP_SK_QUEUES:
		return dump_skqueues((struct parasite_dump_sk_queues *)args);
	default:
		sys_write_msg("Unknown command to parasite\n");
		break;
	}

	return -1;
}

static void __parasite_head __used parasite_head(void)
{
	/*
	 * The linker will handle the stack allocation.
	 */
	asm volatile("parasite_head_start:				\n"
		     "leaq parasite_stack(%rip), %rsp			\n"
		     "subq $16, %rsp					\n"
		     "andq $~15, %rsp					\n"
		     "pushq $0						\n"
		     "movq %rsp, %rbp					\n"
		     "movl parasite_cmd(%rip), %edi			\n"
		     "leaq parasite_args(%rip), %rsi			\n"
		     "call parasite_service				\n"
		     "parasite_service_complete:			\n"
		     "int $0x03						\n"
		     ".align 8						\n"
		     "parasite_cmd:					\n"
		     ".long 0						\n"
		     "parasite_args:					\n"
		     ".long 0						\n"
		     ".space "__stringify(PARASITE_ARG_SIZE)",0		\n"
		     ".space "__stringify(PARASITE_STACK_SIZE)", 0	\n"
		     "parasite_stack:					\n"
		     ".long 0						\n");
}

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */
