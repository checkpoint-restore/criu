#ifndef UTIL_H_
#define UTIL_H_

/*
 * Some bits are stolen from perf and kvm tools
 */
#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/statfs.h>
#include <dirent.h>

#include "compiler.h"
#include "types.h"
#include "log.h"

#include "../protobuf/vma.pb-c.h"

#define PREF_SHIFT_OP(pref, op, size)	((size) op (pref ##BYTES_SHIFT))
#define KBYTES_SHIFT	10
#define MBYTES_SHIFT	20
#define GBYTES_SHIFT	30

#define KBYTES(size)	PREF_SHIFT_OP(K, >>, size)
#define MBYTES(size)	PREF_SHIFT_OP(M, >>, size)
#define GBYTES(size)	PREF_SHIFT_OP(G, >>, size)

#define KILO(size)	PREF_SHIFT_OP(K, <<, size)
#define MEGA(size)	PREF_SHIFT_OP(K, <<, size)
#define GIGA(size)	PREF_SHIFT_OP(K, <<, size)

#ifndef BUG_ON_HANDLER

#ifdef CR_NOGLIBC

#define BUG_ON_HANDLER(condition)					\
	do {								\
		if ((condition)) {					\
			write_string("BUG at " __FILE__ ": ");		\
			write_num(__LINE__);				\
			write_string("\n");				\
			*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__;	\
		}							\
	} while (0)

#else /* CR_NOGLIBC */

# define BUG_ON_HANDLER(condition)					\
	do {								\
		if ((condition)) {					\
			pr_err("BUG at %s:%d\n", __FILE__, __LINE__);	\
			raise(SIGABRT);					\
			*(volatile unsigned long *)NULL = 0xdead0000 + __LINE__; \
		}							\
	} while (0)

#endif /* CR_NOGLIBC */

#endif /* BUG_ON_HANDLER */

#define BUG_ON(condition)	BUG_ON_HANDLER((condition))

/*
 * Write buffer @ptr of @size bytes into @fd file
 * Returns
 *	0  on success
 *	-1 on error (error message is printed)
 */
static inline int write_img_buf(int fd, const void *ptr, int size)
{
	int ret;
	ret = write(fd, ptr, size);
	if (ret == size)
		return 0;

	if (ret < 0)
		pr_perror("Can't write img file");
	else
		pr_err("Img trimmed %d/%d\n", ret, size);
	return -1;
}

#define write_img(fd, ptr)	write_img_buf((fd), (ptr), sizeof(*(ptr)))

/*
 * Read buffer @ptr of @size bytes from @fd file
 * Returns
 *	1  on success
 *	0  on EOF (silently)
 *	-1 on error (error message is printed)
 */
static inline int read_img_buf_eof(int fd, void *ptr, int size)
{
	int ret;
	ret = read(fd, ptr, size);
	if (ret == size)
		return 1;
	if (ret == 0)
		return 0;

	if (ret < 0)
		pr_perror("Can't read img file");
	else
		pr_err("Img trimmed %d/%d\n", ret, size);
	return -1;
}

#define read_img_eof(fd, ptr)	read_img_buf_eof((fd), (ptr), sizeof(*(ptr)))

/*
 * Read buffer @ptr of @size bytes from @fd file
 * Returns
 *	1  on success
 *	-1 on error or EOF (error message is printed)
 */
static inline int read_img_buf(int fd, void *ptr, int size)
{
	int ret;

	ret = read_img_buf_eof(fd, ptr, size);
	if (ret == 0) {
		pr_err("Unexpected EOF\n");
		ret = -1;
	}

	return ret;
}

#define read_img(fd, ptr)	read_img_buf((fd), (ptr), sizeof(*(ptr)))

#define memzero_p(p)		memset(p, 0, sizeof(*p))
#define memzero(p, size)	memset(p, 0, size)

struct vma_area;
struct list_head;

extern void pr_vma(unsigned int loglevel, const struct vma_area *vma_area);

#define pr_info_vma(vma_area)	pr_vma(LOG_INFO, vma_area)
#define pr_msg_vma(vma_area)	pr_vma(LOG_MSG, vma_area)

#define pr_vma_list(level, head)				\
	do {							\
		struct vma_area *vma;				\
		list_for_each_entry(vma, head, list)		\
			pr_vma(level, vma);			\
	} while (0)
#define pr_info_vma_list(head)	pr_vma_list(LOG_INFO, head)

/*
 * Note since VMA_AREA_NONE = 0 we can skip assignment
 * here and simply rely on xzalloc
 */
#define alloc_vma_area()					\
	({							\
		struct vma_area *p__ = xzalloc(sizeof(*p__));	\
		if (p__) {					\
			vma_entry__init(&p__->vma);		\
			p__->vm_file_fd = -1;			\
			p__->vma.fd	= -1;			\
		}						\
		p__;						\
	})

extern int move_img_fd(int *img_fd, int want_fd);
extern int close_safe(int *fd);

extern int reopen_fd_as_safe(char *file, int line, int new_fd, int old_fd, bool allow_reuse_fd);
#define reopen_fd_as(new_fd, old_fd)		reopen_fd_as_safe(__FILE__, __LINE__, new_fd, old_fd, false)
#define reopen_fd_as_nocheck(new_fd, old_fd)	reopen_fd_as_safe(__FILE__, __LINE__, new_fd, old_fd, true)

int set_proc_mountpoint(char *path);
void close_proc(void);
int open_pid_proc(pid_t pid);
int close_pid_proc(void);

int do_open_proc(pid_t pid, int flags, const char *fmt, ...);

#define __open_proc(pid, flags, fmt, ...)			\
	({							\
		int __fd = do_open_proc(pid, flags,		\
					fmt, ##__VA_ARGS__);	\
		if (__fd < 0)					\
			pr_perror("Can't open /proc/%d/" fmt,	\
					pid, ##__VA_ARGS__);	\
								\
		__fd;						\
	})

/* int open_proc(pid_t pid, const char *fmt, ...); */
#define open_proc(pid, fmt, ...)				\
	__open_proc(pid, O_RDONLY, fmt, ##__VA_ARGS__)

/* int open_proc_rw(pid_t pid, const char *fmt, ...); */
#define open_proc_rw(pid, fmt, ...)				\
	__open_proc(pid, O_RDWR, fmt, ##__VA_ARGS__)

/* DIR *opendir_proc(pid_t pid, const char *fmt, ...); */
#define opendir_proc(pid, fmt, ...)					\
	({								\
		int __fd = open_proc(pid, fmt, ##__VA_ARGS__);		\
		DIR *__d = NULL;					\
									\
		if (__fd >= 0)						\
			__d = fdopendir(__fd);				\
			if (__d == NULL)				\
				pr_perror("Can't fdopendir %d "		\
					"(/proc/%d/" fmt ")",		\
					__fd, pid, ##__VA_ARGS__);	\
									\
		__d;							\
	 })

/* FILE *fopen_proc(pid_t pid, const char *fmt, ...); */
#define fopen_proc(pid, fmt, ...)					\
	({								\
		int __fd = open_proc(pid,  fmt, ##__VA_ARGS__);		\
		FILE *__f = NULL;					\
									\
		if (__fd >= 0)						\
			__f = fdopen(__fd, "r");			\
			if (__f == NULL)				\
				pr_perror("Can't fdopen %d "		\
					"(/proc/%d/" fmt ")",		\
					__fd, pid, ##__VA_ARGS__);	\
									\
		__f;							\
	 })

#define __xalloc(op, size, ...)						\
	({								\
		void *___p = op( __VA_ARGS__ );				\
		if (!___p)						\
			pr_err("%s: Can't allocate %li bytes\n",	\
			       __func__, (long)(size));			\
		___p;							\
	})

#include <stdlib.h>

#define xstrdup(str)		__xalloc(strdup, strlen(str) + 1, str)
#define xmalloc(size)		__xalloc(malloc, size, size)
#define xzalloc(size)		__xalloc(calloc, size, 1, size)
#define xrealloc(p, size)	__xalloc(realloc, size, p, size)

#define xfree(p)		do { if (p) free(p); } while (0)

#define xrealloc_safe(pptr, size)					\
	({								\
		int __ret = -1;						\
		void *new = xrealloc(*pptr, size);			\
		if (new) {						\
			*pptr = new;					\
			__ret = 0;					\
		}							\
		__ret;							\
	 })

#define pr_img_head(type, ...)	pr_msg("\n"#type __VA_ARGS__ "\n----------------\n")
#define pr_img_tail(type)	pr_msg("----------------\n")

#define KDEV_MINORBITS	20
#define KDEV_MINORMASK	((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma,mi)	(((ma) << KDEV_MINORBITS) | (mi))

static inline u32 kdev_major(u32 kdev)
{
	return kdev >> KDEV_MINORBITS;
}

static inline u32 kdev_minor(u32 kdev)
{
	return kdev & KDEV_MINORMASK;
}

static inline dev_t kdev_to_odev(u32 kdev)
{
	/*
	 * New kernels envcode devices in a new form
	 */
	return (kdev_major(kdev) << 8) | kdev_minor(kdev);
}

int copy_file(int fd_in, int fd_out, size_t bytes);
bool is_anon_inode(struct statfs *statfs);
int is_anon_link_type(int lfd, char *type);

#define is_hex_digit(c)				\
	(((c) >= '0' && (c) <= '9')	||	\
	 ((c) >= 'a' && (c) <= 'f')	||	\
	 ((c) >= 'A' && (c) <= 'F'))

/*
 * read_img_str -- same as read_img_buf, but allocates memory for
 * the buffer and puts the '\0' at the end
 */

static inline int read_img_str(int fd, char **pstr, int size)
{
	int ret;
	char *str;

	str = xmalloc(size + 1);
	if (!str)
		return -1;

	ret = read_img_buf(fd, str, size);
	if (ret < 0) {
		xfree(str);
		return -1;
	}

	str[size] = '\0';
	*pstr = str;
	return 0;
}

#endif /* UTIL_H_ */
