#ifndef CR_PARASITE_H_
#define CR_PARASITE_H_

#include <sys/types.h>
#include <limits.h>

#include "compiler.h"
#include "syscall.h"
#include "image.h"

#define __parasite_head		__used __section(.parasite.head.text)

#define PARASITE_STACK_SIZE	2048
#define PARASITE_ARG_SIZE	8196
#define PARASITE_BRK_SIZE	32768

#define PARASITE_MAX_SIZE	(64 << 10)

/* we need own error code for diagnostics */
#define PARASITE_ERR_FAIL	-1024
#define PARASITE_ERR_OPEN	-1025
#define PARASITE_ERR_MMAP	-1026
#define PARASITE_ERR_MINCORE	-1027
#define PARASITE_ERR_MUNMAP	-1028
#define PARASITE_ERR_CLOSE	-1029
#define PARASITE_ERR_WRITE	-1030
#define PARASITE_ERR_MPROTECT	-1031
#define PARASITE_ERR_SIGACTION  -1032
#define PARASITE_ERR_GETITIMER  -1033

enum {
	PARASITE_CMD_PINGME,
	PARASITE_CMD_DUMPPAGES,
	PARASITE_CMD_DUMP_SIGACTS,
	PARASITE_CMD_DUMP_ITIMERS,
	PARASITE_CMD_DUMP_MISC,

	PARASITE_CMD_MAX,
};

typedef struct {
	unsigned long		command;
	unsigned long		args_size;
	void			*args;
} parasite_args_t;

typedef struct  {
	long			ret;		/* custom ret code */
	long			sys_ret;	/* syscall ret code */
	long			line;		/* where we're failed */
} parasite_status_t;

#define SET_PARASITE_STATUS(st, ret_code, sys_ret_code)	\
	do {						\
		(st)->ret	= ret_code,		\
		(st)->sys_ret	= sys_ret_code,		\
		(st)->line	= __LINE__;		\
	} while (0)

struct parasite_dump_file_args {
	parasite_status_t	status;
	unsigned long		open_mode;
	unsigned long		open_flags;
	char			open_path[PATH_MAX];
};

struct parasite_dump_pages_args {
	struct parasite_dump_file_args fa;

	struct vma_entry	vma_entry;
	unsigned long		nrpages_dumped;	/* how many pages are dumped */
	unsigned long		fd;
};

/*
 * Misc sfuff, that is too small for separate file, but cannot
 * be read w/o using parasite
 */

struct parasite_dump_misc {
	parasite_status_t	status;
	unsigned int		secbits;
};

/*
 * Some useful offsets
 */

#define PARASITE_ARGS_ADDR(start)				\
	((start) + parasite_blob_offset__parasite_args)
#define PARASITE_CMD_ADDR(start)				\
	((start) + parasite_blob_offset__parasite_cmd)
#define PARASITE_HEAD_ADDR(start)				\
	((start) + parasite_blob_offset__parasite_head_start)
#define PARASITE_COMPLETE_ADDR(start)				\
	((start) + parasite_blob_offset__parasite_service_complete)

#endif /* CR_PARASITE_H_ */
