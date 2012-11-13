#ifndef CR_PARASITE_H_
#define CR_PARASITE_H_

#define PARASITE_STACK_SIZE	(16 << 10)
#define PARASITE_ARG_SIZE	8196

#define PARASITE_MAX_SIZE	(64 << 10)

#ifndef __ASSEMBLY__

#include <sys/un.h>

#include "image.h"
#include "util-net.h"

#include "../protobuf/vma.pb-c.h"

#define __head __used __section(.head.text)

enum {
	PARASITE_CMD_INIT,
	PARASITE_CMD_INIT_THREAD,
	PARASITE_CMD_CFG_LOG,
	PARASITE_CMD_FINI,
	PARASITE_CMD_FINI_THREAD,

	PARASITE_CMD_DUMPPAGES_INIT,
	PARASITE_CMD_DUMPPAGES,
	PARASITE_CMD_DUMPPAGES_FINI,

	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_MISC,
	PARASITE_CMD_DUMP_CREDS,
	PARASITE_CMD_DUMP_THREAD,
	PARASITE_CMD_DRAIN_FDS,
	PARASITE_CMD_GET_PROC_FD,
	PARASITE_CMD_DUMP_TTY,

	PARASITE_CMD_MAX,
};

struct parasite_init_args {
	int			h_addr_len;
	struct sockaddr_un	h_addr;

	int			p_addr_len;
	struct sockaddr_un	p_addr;

	int			nr_threads;
};

struct parasite_log_args {
	int log_level;
};

struct parasite_dump_pages_args {
	VmaEntry		vma_entry;
	unsigned long		nrpages_dumped;	/* how many pages are dumped */
	unsigned long		nrpages_skipped;
	unsigned long		nrpages_total;
};

struct parasite_dump_sa_args {
	rt_sigaction_t sas[SIGMAX];
};

struct parasite_dump_itimers_args {
	struct itimerval real;
	struct itimerval virt;
	struct itimerval prof;
};

/*
 * Misc sfuff, that is too small for separate file, but cannot
 * be read w/o using parasite
 */

struct parasite_dump_misc {
	unsigned long		brk;
	k_rtsigset_t		blocked;

	u32 pid;
	u32 sid;
	u32 pgid;
};

#define PARASITE_MAX_GROUPS	(PAGE_SIZE / sizeof(unsigned int))

struct parasite_dump_creds {
	unsigned int		secbits;
	unsigned int		ngroups;
	unsigned int		groups[PARASITE_MAX_GROUPS];
};

struct parasite_dump_thread {
	unsigned int		*tid_addr;
	pid_t			tid;
	k_rtsigset_t		blocked;
};

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
#endif /* CR_PARASITE_H_ */
