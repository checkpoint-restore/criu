#ifndef CR_PARASITE_H_
#define CR_PARASITE_H_

#include "compiler.h"
#include "syscall.h"
#include "image.h"

#define __parasite_head		__used __section(.parasite.head.text)

#define PARASITE_STACK_SIZE	2048
#define PARASITE_ARG_SIZE	256
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

enum {
	PARASITE_CMD_NONE,
	PARASITE_CMD_KILLME,
	PARASITE_CMD_PINGME,
	PARASITE_CMD_DUMPPAGES,

	PARASITE_CMD_MAX,
};

typedef struct {
	unsigned long		command;
	unsigned long		args_size;
	void			*args;
} parasite_args_t;

typedef struct {
	struct vma_entry	vma_entry;
	unsigned long		nrpages_dumped;	/* how many pages are dumped */
	unsigned long		fd;
	long			ret;
	long			sys_ret;
	long			line;
	unsigned long		open_mode;
	unsigned long		open_flags;
	char			open_path[64];
} parasite_args_cmd_dumppages_t;

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
