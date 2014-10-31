#ifndef __CR_PARASITE_H__
#define __CR_PARASITE_H__

#define PARASITE_STACK_SIZE	(16 << 10)
#define PARASITE_ARG_SIZE_MIN	( 1 << 12)

#define PARASITE_MAX_SIZE	(64 << 10)

#ifndef __ASSEMBLY__

#include <sys/un.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include "image.h"
#include "util-pie.h"

#include "protobuf/vma.pb-c.h"

#define __head __used __section(.head.text)

enum {
	PARASITE_CMD_IDLE		= 0,
	PARASITE_CMD_ACK,

	PARASITE_CMD_INIT_DAEMON,
	PARASITE_CMD_DUMP_THREAD,
	PARASITE_CMD_UNMAP,

	/*
	 * These two must be greater than INITs.
	 */
	PARASITE_CMD_DAEMONIZED,

	PARASITE_CMD_FINI,

	PARASITE_CMD_MPROTECT_VMAS,
	PARASITE_CMD_DUMPPAGES,

	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_POSIX_TIMERS,
	PARASITE_CMD_DUMP_MISC,
	PARASITE_CMD_DUMP_CREDS,
	PARASITE_CMD_DRAIN_FDS,
	PARASITE_CMD_GET_PROC_FD,
	PARASITE_CMD_DUMP_TTY,
	PARASITE_CMD_CHECK_VDSO_MARK,

	PARASITE_CMD_MAX,
};

struct ctl_msg {
	unsigned int	cmd;			/* command itself */
	unsigned int	ack;			/* ack on command */
	int		err;			/* error code on reply */
};

#define ctl_msg_cmd(_cmd)		\
	(struct ctl_msg){.cmd = _cmd, }

#define ctl_msg_ack(_cmd, _err)	\
	(struct ctl_msg){.cmd = _cmd, .ack = _cmd, .err = _err, }

struct parasite_init_args {
	int			h_addr_len;
	struct sockaddr_un	h_addr;

	int			log_level;

	struct rt_sigframe	*sigframe;

	void			*sigreturn_addr;
};

struct parasite_unmap_args {
	void			*parasite_start;
	unsigned long		parasite_len;
};

struct parasite_vma_entry
{
	unsigned long	start;
	unsigned long	len;
	int		prot;
};

struct parasite_vdso_vma_entry {
	unsigned long	start;
	unsigned long	len;
	unsigned long	proxy_vdso_addr;
	unsigned long	proxy_vvar_addr;
	int		is_marked;
};

struct parasite_dump_pages_args {
	unsigned int	nr_vmas;
	unsigned int	add_prot;
	unsigned int	off;
	unsigned int	nr_segs;
	unsigned int	nr_pages;
};

static inline struct parasite_vma_entry *pargs_vmas(struct parasite_dump_pages_args *a)
{
	return (struct parasite_vma_entry *)(a + 1);
}

static inline struct iovec *pargs_iovs(struct parasite_dump_pages_args *a)
{
	return (struct iovec *)(pargs_vmas(a) + a->nr_vmas);
}

struct parasite_dump_sa_args {
	rt_sigaction_t sas[SIGMAX];
};

struct parasite_dump_itimers_args {
	struct itimerval real;
	struct itimerval virt;
	struct itimerval prof;
};

struct posix_timer {
	int it_id;
	struct itimerspec val;
	int overrun;
};

struct parasite_dump_posix_timers_args {
	int timer_n;
	struct posix_timer timer[0];
};

static inline int posix_timers_dump_size(int timer_n)
{
	return sizeof(int) + sizeof(struct posix_timer) * timer_n;
}

struct parasite_dump_thread {
	unsigned int		*tid_addr;
	pid_t			tid;
	tls_t			tls;
	stack_t			sas;
	int			pdeath_sig;
};

/*
 * Misc sfuff, that is too small for separate file, but cannot
 * be read w/o using parasite
 */

struct parasite_dump_misc {
	unsigned long		brk;

	u32 pid;
	u32 sid;
	u32 pgid;
	u32 umask;

	struct parasite_dump_thread	ti;

	int dumpable;
};

/*
 * Calculate how long we can make the groups array in parasite_dump_creds
 * and still fit the struct in one page
 */
#define PARASITE_MAX_GROUPS							\
	(PAGE_SIZE -								\
	 offsetof(struct parasite_dump_creds, groups)				\
	) / sizeof(unsigned int)		/* groups */

struct parasite_dump_creds {
	unsigned int		cap_last_cap;

	u32			cap_inh[CR_CAP_SIZE];
	u32			cap_prm[CR_CAP_SIZE];
	u32			cap_eff[CR_CAP_SIZE];
	u32			cap_bnd[CR_CAP_SIZE];

	int			uids[4];
	int			gids[4];
	unsigned int		secbits;
	unsigned int		ngroups;
	/*
	 * FIXME -- this structure is passed to parasite code
	 * through parasite args area so in parasite_dump_creds()
	 * call we check for size of this data fits the size of
	 * the area. Unfortunatelly, we _actually_ use more bytes
	 * than the sizeof() -- we put PARASITE_MAX_GROUPS int-s
	 * in there, so the size check is not correct.
	 *
	 * However, all this works simply because we make sure
	 * the PARASITE_MAX_GROUPS is so, that the total amount
	 * of memory in use doesn't exceed the PAGE_SIZE and the
	 * args area is at least one page (PARASITE_ARG_SIZE_MIN).
	 */
	unsigned int		groups[0];
};

static inline void copy_sas(ThreadSasEntry *dst, const stack_t *src)
{
	dst->ss_sp = encode_pointer(src->ss_sp);
	dst->ss_size = (u64)src->ss_size;
	dst->ss_flags = src->ss_flags;
}

#define PARASITE_MAX_FDS	(PAGE_SIZE / sizeof(int))

struct parasite_drain_fd {
	int	nr_fds;
	int	fds[PARASITE_MAX_FDS];
};

static inline int drain_fds_size(struct parasite_drain_fd *dfds)
{
	return sizeof(dfds->nr_fds) + dfds->nr_fds * sizeof(dfds->fds[0]);
}

struct parasite_tty_args {
	int	fd;
	int	type;

	int	sid;
	int	pgrp;
	bool	hangup;

	int	st_pckt;
	int	st_lock;
	int	st_excl;
};

/* the parasite prefix is added by gen_offsets.sh */
#define parasite_sym(pblob, name) ((void *)(pblob) + parasite_blob_offset__##name)

#endif /* !__ASSEMBLY__ */

#endif /* __CR_PARASITE_H__ */
