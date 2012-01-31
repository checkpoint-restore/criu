#ifndef UTIL_H_
#define UTIL_H_

/*
 * Some bits are stolen from perf and kvm tools
 */
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <dirent.h>

#include "compiler.h"
#include "types.h"

extern void printk(const char *format, ...);

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

#define pr_info(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	printk("Error (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_panic(fmt, ...)	printk("PANIC (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define pr_warning(fmt, ...)	printk("Warning (%s:%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_err_jmp(label)					\
	do {							\
		printk("EJMP: %s:%d\n", __FILE__, __LINE__);	\
		goto label;					\
	} while (0)

#define jerr(code, label)					\
	do {							\
		if ((code))					\
			pr_err_jmp(label);			\
	} while (0)

#define jerr_cond(code, cond, label)				\
	do {							\
		if ((code) cond)				\
			pr_err_jmp(label);			\
	} while (0)

#define jerr_rc(code, rc, label)				\
	do {							\
		rc = (code);					\
		if (rc)						\
			pr_err_jmp(label);			\
	} while (0)

#ifdef CR_DEBUG
#define pr_debug(fmt, ...)					\
	do {							\
		printk("%s:%d:%s: " fmt,			\
		       __FILE__, __LINE__,__func__,		\
		       ##__VA_ARGS__);				\
	} while (0)
#define dprintk(fmt, ...)	printk(fmt, ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...)
#define dprintk(fmt, ...)
#endif

#define die(fmt, ...)						\
	do {							\
		printk("die (%s:%d): " fmt, __FILE__,		\
			__LINE__, ##__VA_ARGS__);		\
		exit(1);					\
	} while (0)

#define pr_perror(fmt, ...)					\
	do {							\
		pr_err(fmt ": %m\n", ##__VA_ARGS__);		\
	} while (0)

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
			pr_err("BUG at %s:%d", __FILE__, __LINE__);	\
			raise(SIGABRT);					\
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
static inline int write_img_buf(int fd, void *ptr, int size)
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

extern void printk_siginfo(siginfo_t *siginfo);

struct vma_area;
struct list_head;

extern void printk_vma(struct vma_area *vma_area);

#define pr_info_vma_list(head)					\
	do {							\
		struct vma_area *vma;				\
		list_for_each_entry(vma, head, list)		\
			pr_info_vma(vma);			\
	} while (0)

/*
 * Note since VMA_AREA_NONE = 0 we can skip assignment
 * here and simply rely on xzalloc
 */
#define alloc_vma_area()					\
	({							\
		struct vma_area *p__ = xzalloc(sizeof(*p__));	\
		if (p__) {					\
			p__->shmid	= -1;			\
			p__->vm_file_fd = -1;			\
			p__->vma.fd	= -1;			\
		}						\
		p__;						\
	})

#define pr_info_vma(vma_area)		printk_vma(vma_area)
#define pr_info_siginfo(siginfo)	printk_siginfo(siginfo)

extern int move_img_fd(int *img_fd, int want_fd);
extern int close_safe(int *fd);

extern int reopen_fd_as_safe(int new_fd, int old_fd, bool allow_reuse_fd);
#define reopen_fd_as(new_fd, old_fd)		reopen_fd_as_safe(new_fd, old_fd, false)
#define reopen_fd_as_nocheck(new_fd, old_fd)	reopen_fd_as_safe(new_fd, old_fd, true)

extern void hex_dump(void *addr, unsigned long len);

int open_pid_proc(pid_t pid);
int open_proc(int pid_dir_fd, char *fmt, ...);
DIR *opendir_proc(int pid_dir_fd, char *fmt, ...);
FILE *fopen_proc(int pid_dir_fd, char *fmt, ...);

#define __xalloc(op, size, ...)						\
	({								\
		void *___p = op( __VA_ARGS__ );				\
		if (!___p)						\
			pr_err("%s: Can't allocate %li bytes\n",	\
			       __func__, (long)(size));			\
		___p;							\
	})

#define xstrdup(str)		__xalloc(strdup, strlen(str) + 1, str)
#define xmalloc(size)		__xalloc(malloc, size, size)
#define xzalloc(size)		__xalloc(calloc, size, 1, size)
#define xrealloc(p, size)	__xalloc(realloc, size, p, size)

#define xfree(p)		if (p) free(p)

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

#define pr_img_head(type, ...)	pr_info("\n"#type __VA_ARGS__ "\n----------------\n")
#define pr_img_tail(type)	pr_info("----------------\n")

#endif /* UTIL_H_ */
