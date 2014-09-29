#ifndef __CR_IMAGE_H__
#define __CR_IMAGE_H__

#include <stdbool.h>

#include "compiler.h"
#include "servicefd.h"
#include "image-desc.h"
#include "fcntl.h"
#include "magic.h"
#include "bfd.h"
#include "bug.h"

#define PAGE_IMAGE_SIZE	4096
#define PAGE_RSS	1
#define PAGE_ANON	2

/*
 * Top bit set in the tgt id means we've remapped
 * to a ghost file.
 */
#define REMAP_GHOST	(1 << 31)

/*
 * By-default, when dumping a unix socket, we should dump its peer
 * as well. Which in turn means, we should dump the task(s) that have
 * this peer opened.
 *
 * Sometimes, we can break this rule and dump only one end of the
 * unix sockets pair, and on restore time connect() this end back to
 * its peer.
 *
 * So, to resolve this situation we mark the peers we don't dump
 * as "external" and require the --ext-unix-sk option.
 */

#define USK_EXTERN	(1 << 0)
#define USK_SERVICE	(1 << 1)
#define USK_CALLBACK	(1 << 2)

#define VMA_AREA_NONE		(0 <<  0)
#define VMA_AREA_REGULAR	(1 <<  0)	/* Dumpable area */
#define VMA_AREA_STACK		(1 <<  1)
#define VMA_AREA_VSYSCALL	(1 <<  2)
#define VMA_AREA_VDSO		(1 <<  3)
#define VMA_FORCE_READ		(1 <<  4)	/* VMA changed to be readable */
#define VMA_AREA_HEAP		(1 <<  5)

#define VMA_FILE_PRIVATE	(1 <<  6)
#define VMA_FILE_SHARED		(1 <<  7)
#define VMA_ANON_SHARED		(1 <<  8)
#define VMA_ANON_PRIVATE	(1 <<  9)

#define VMA_AREA_SYSVIPC	(1 <<  10)
#define VMA_AREA_SOCKET		(1 <<  11)
#define VMA_AREA_VVAR		(1 <<  12)

#define VMA_UNSUPP		(1 <<  31)	/* Unsupported VMA */

#define CR_CAP_SIZE	2

#define TASK_COMM_LEN 16

#define TASK_ALIVE		0x1
#define TASK_DEAD		0x2
#define TASK_STOPPED		0x3
#define TASK_HELPER		0x4

#define CR_PARENT_LINK "parent"

extern bool fdinfo_per_id;
extern bool ns_per_id;

#define O_OPT	(O_PATH)
#define O_NOBUF	(O_DIRECT)

#define O_DUMP	(O_RDWR | O_CREAT | O_TRUNC)
#define O_SHOW	(O_RDONLY | O_NOBUF)
#define O_RSTR	(O_RDONLY)

struct cr_img {
	struct bfd _x;
};

static inline int img_raw_fd(struct cr_img *img)
{
	BUG_ON(bfd_buffered(&img->_x));
	return img->_x.fd;
}

extern int open_image_dir(char *dir);
extern void close_image_dir(void);

extern struct cr_img *open_image_at(int dfd, int type, unsigned long flags, ...);
#define open_image(typ, flags, ...) open_image_at(get_service_fd(IMG_FD_OFF), typ, flags, ##__VA_ARGS__)
extern struct cr_img *open_pages_image(unsigned long flags, struct cr_img *pmi);
extern struct cr_img *open_pages_image_at(int dfd, unsigned long flags, struct cr_img *pmi);
extern void up_page_ids_base(void);

extern struct cr_img *img_from_fd(int fd); /* for cr-show mostly */

extern int write_img_buf(struct cr_img *, const void *ptr, int size);
#define write_img(img, ptr)	write_img_buf((img), (ptr), sizeof(*(ptr)))
extern int read_img_buf_eof(struct cr_img *, void *ptr, int size);
#define read_img_eof(img, ptr)	read_img_buf_eof((img), (ptr), sizeof(*(ptr)))
extern int read_img_buf(struct cr_img *, void *ptr, int size);
#define read_img(img, ptr)	read_img_buf((img), (ptr), sizeof(*(ptr)))
extern int read_img_str(struct cr_img *, char **pstr, int size);

extern void close_image(struct cr_img *);

#endif /* __CR_IMAGE_H__ */
