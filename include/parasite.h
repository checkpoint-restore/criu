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
	PARASITE_CMD_SET_LOGFD,
	PARASITE_CMD_FINI,

	PARASITE_CMD_DUMPPAGES_INIT,
	PARASITE_CMD_DUMPPAGES,
	PARASITE_CMD_DUMPPAGES_FINI,

	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_MISC,
	PARASITE_CMD_DUMP_TID_ADDR,
	PARASITE_CMD_DRAIN_FDS,
	PARASITE_CMD_GET_PROC_FD,

	PARASITE_CMD_MAX,
};

struct parasite_init_args {
	int			h_addr_len;
	struct sockaddr_un	h_addr;

	int			p_addr_len;
	struct sockaddr_un	p_addr;
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
	unsigned int		secbits;
	unsigned long		brk;
	k_rtsigset_t		blocked;

	u32 pid;
	u32 sid;
	u32 pgid;
};

struct parasite_dump_tid_info {
	unsigned int		*tid_addr;
	int			tid;
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

/*
 * Some useful offsets
 */

#define PARASITE_ARGS_ADDR(start)				\
	((start) + parasite_blob_offset____export_parasite_args)
#define PARASITE_CMD_ADDR(start)				\
	((start) + parasite_blob_offset____export_parasite_cmd)
#define PARASITE_HEAD_ADDR(start)				\
	((start) + parasite_blob_offset____export_parasite_head_start)

#endif /* !__ASSEMBLY__ */
#endif /* CR_PARASITE_H_ */
