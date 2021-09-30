#ifndef __CR_IMAGE_H__
#define __CR_IMAGE_H__

#include <stdbool.h>

#include "common/compiler.h"
#include "servicefd.h"
#include "image-desc.h"
#include "fcntl.h"
#include "magic.h"
#include "bfd.h"
#include "log.h"
#include "common/bug.h"

#define PAGE_RSS  1
#define PAGE_ANON 2

/*
 * Top bit set in the tgt id means we've remapped
 * to a ghost file.
 */
#define REMAP_GHOST (1 << 31)

/*
 * VMA_AREA status:
 *
 *  - none
 *	VmaEntry is just allocated and has not been used
 *	for anything yet
 *  - regular
 *  	VmaEntry represent some memory area which should be
 *  	dumped and restored; this is a general sign that we
 *  	should not skip the area content from processing in
 *  	compare with special areas such as vsyscall
 *  - stack
 *  	the memory area is used in application stack so we
 *  	should be careful about guard page here
 *  - vsyscall
 *  	special memory area injected into the task memory
 *  	space by the kernel itself, represent virtual syscall
 *  	implementation and it is specific to every kernel version,
 *  	its contents should not be dumped ever
 *  - vdso,vvar
 *  	the vDSO area, it might reqire additional memory
 *  	contents modification especially when tasks are
 *  	migrating between different kernel versions
 *  - heap
 *  	"heap" area in application, currently for information only
 *  - file private
 *  	stands for privately memory mapped files
 *  - file shared
 *  	stands for shared memory mapped files
 *  - anon shared
 *  	represent shared anonymous memory areas
 *  - anon private
 *  	represent private anonymous memory areas
 *  - SysV IPC
 *  	IPC shared memory area
 *  - socket
 *  	memory map for socket
 *  - AIO ring
 *  	memory area serves AIO buffers
 *  - unsupported
 *  	stands for any unknown memory areas, usually means
 *  	we don't know how to work with it and should stop
 *  	processing exiting with error; while the rest of bits
 *  	are part of image ABI, this particular one must never
 *  	be used in image.
 */
#define VMA_AREA_NONE	  (0 << 0)
#define VMA_AREA_REGULAR  (1 << 0)
#define VMA_AREA_STACK	  (1 << 1)
#define VMA_AREA_VSYSCALL (1 << 2)
#define VMA_AREA_VDSO	  (1 << 3)
#define VMA_AREA_HEAP	  (1 << 5)

#define VMA_FILE_PRIVATE (1 << 6)
#define VMA_FILE_SHARED	 (1 << 7)
#define VMA_ANON_SHARED	 (1 << 8)
#define VMA_ANON_PRIVATE (1 << 9)

#define VMA_AREA_SYSVIPC (1 << 10)
#define VMA_AREA_SOCKET	 (1 << 11)
#define VMA_AREA_VVAR	 (1 << 12)
#define VMA_AREA_AIORING (1 << 13)
#define VMA_AREA_MEMFD	 (1 << 14)

#define VMA_EXT_PLUGIN	  (1 << 27)
#define VMA_CLOSE	  (1 << 28)
#define VMA_NO_PROT_WRITE (1 << 29)
#define VMA_PREMMAPED	  (1 << 30)
#define VMA_UNSUPP	  (1 << 31)

#define CR_CAP_SIZE 2

#define TASK_COMM_LEN 16

#define CR_PARENT_LINK "parent"

extern bool ns_per_id;
extern bool img_common_magic;

#define O_NOBUF	      (O_DIRECT)
#define O_SERVICE     (O_DIRECTORY)
#define O_DUMP	      (O_WRONLY | O_CREAT | O_TRUNC)
#define O_RSTR	      (O_RDONLY)
#define O_FORCE_LOCAL (O_SYNC)

struct cr_img {
	union {
		struct bfd _x;
		struct {
			int fd; /* should be first to coincide with _x.fd */
			int type;
			unsigned long oflags;
			char *path;
		};
	};
};

#define EMPTY_IMG_FD (-404)
#define LAZY_IMG_FD  (-505)

static inline bool empty_image(struct cr_img *img)
{
	return img && img->_x.fd == EMPTY_IMG_FD;
}

static inline bool lazy_image(struct cr_img *img)
{
	return img->_x.fd == LAZY_IMG_FD;
}

extern int open_image_lazy(struct cr_img *img);

static inline int img_raw_fd(struct cr_img *img)
{
	if (!img)
		return -1;
	if (lazy_image(img) && open_image_lazy(img))
		return -1;

	BUG_ON(bfd_buffered(&img->_x));
	return img->_x.fd;
}

extern off_t img_raw_size(struct cr_img *img);

extern int open_image_dir(char *dir, int mode);
extern void close_image_dir(void);
/*
 * Return -1 -- parent symlink points to invalid target
 * Return 0 && pfd < 0 -- parent symlink does not exist
 * Return 0 && pfd >= 0 -- opened
 */
extern int open_parent(int dfd, int *pfd);

extern struct cr_img *open_image_at(int dfd, int type, unsigned long flags, ...);
#define open_image(typ, flags, ...) open_image_at(-1, typ, flags, ##__VA_ARGS__)
extern int open_image_lazy(struct cr_img *img);
extern struct cr_img *open_pages_image(unsigned long flags, struct cr_img *pmi, u32 *pages_id);
extern struct cr_img *open_pages_image_at(int dfd, unsigned long flags, struct cr_img *pmi, u32 *pages_id);
extern void up_page_ids_base(void);

extern struct cr_img *img_from_fd(int fd); /* for cr-show mostly */

extern int write_img_buf(struct cr_img *, const void *ptr, int size);
#define write_img(img, ptr) write_img_buf((img), (ptr), sizeof(*(ptr)))
extern int read_img_buf_eof(struct cr_img *, void *ptr, int size);
#define read_img_eof(img, ptr) read_img_buf_eof((img), (ptr), sizeof(*(ptr)))
extern int read_img_buf(struct cr_img *, void *ptr, int size);
#define read_img(img, ptr) read_img_buf((img), (ptr), sizeof(*(ptr)))
extern int read_img_str(struct cr_img *, char **pstr, int size);

extern void close_image(struct cr_img *);

#endif /* __CR_IMAGE_H__ */
