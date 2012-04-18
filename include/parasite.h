#ifndef CR_PARASITE_H_
#define CR_PARASITE_H_

#include <sys/types.h>
#include <sys/un.h>
#include <limits.h>

#include "compiler.h"
#include "image.h"
#include "sockets.h"

#include "util-net.h"

#define __head __used __section(.head.text)

#define PARASITE_STACK_SIZE	2048
#define PARASITE_ARG_SIZE	8196

#define PARASITE_MAX_SIZE	(64 << 10)

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

	PARASITE_CMD_MAX,
};

typedef struct  {
	long			ret;		/* ret code */
	long			line;		/* where we're failed */
} parasite_status_t;

#define SET_PARASITE_RET(st, err)		\
	do {					\
		(st)->ret	= err,		\
		(st)->line	= __LINE__;	\
	} while (0)

struct parasite_init_args {
	parasite_status_t	status;

	int			sun_len;
	struct sockaddr_un	saddr;
};

struct parasite_dump_pages_args {
	parasite_status_t       status;

	struct vma_entry	vma_entry;
	unsigned long		nrpages_dumped;	/* how many pages are dumped */
};

/*
 * Misc sfuff, that is too small for separate file, but cannot
 * be read w/o using parasite
 */

struct parasite_dump_misc {
	parasite_status_t	status;

	unsigned int		secbits;
	unsigned long		brk;
	k_rtsigset_t		blocked;
};

struct parasite_dump_tid_addr {
	parasite_status_t	status;

	unsigned int *tid_addr;
};

#define PARASITE_MAX_FDS	(PAGE_SIZE / sizeof(int))

struct parasite_drain_fd {
	parasite_status_t	status;

	struct sockaddr_un	saddr;
	int			sun_len;
	int			fds[PARASITE_MAX_FDS];
	int			nr_fds;
};

/*
 * Some useful offsets
 */

#define PARASITE_ARGS_ADDR(start)				\
	((start) + parasite_blob_offset____export_parasite_args)
#define PARASITE_CMD_ADDR(start)				\
	((start) + parasite_blob_offset____export_parasite_cmd)
#define PARASITE_HEAD_ADDR(start)				\
	((start) + parasite_blob_offset____export_parasite_head_start)

#endif /* CR_PARASITE_H_ */
