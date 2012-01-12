#ifndef UTIL_H_
#define UTIL_H_

/*
 * Some bits are stolen from perf and kvm tools
 */
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

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
		pr_err("%s: " fmt,  strerror(errno),		\
			##__VA_ARGS__);				\
	} while (0)

#ifndef BUG_ON_HANDLER
# define BUG_ON_HANDLER(condition)					\
	do {								\
		if ((condition)) {					\
			pr_err("BUG at %s:%d", __FILE__, __LINE__);	\
			raise(SIGABRT);					\
		}							\
	} while (0)
#endif

#define BUG_ON(condition)	BUG_ON_HANDLER((condition))

#define write_ptr(fd, ptr)			\
	write(fd, (ptr), sizeof(*(ptr)))

#define write_ptr_safe(fd, ptr, err)		\
	jerr(write_ptr(fd, ptr) != sizeof(*(ptr)), err)

#define write_safe(fd, ptr, size, err)		\
	jerr(write(fd, (ptr), (size)) != (size), err)

#define write_safe_imm(fd, imm, err)		\
	do {					\
		typeof(imm) x__ = imm;		\
		write_ptr_safe(fd, &x__, err);	\
	} while (0)

#define read_safe(fd, ptr, size, err)		\
	jerr(read(fd, ptr, (size)) != (size), err)

#define read_ptr_safe(fd, ptr, err)		\
	jerr(read(fd, ptr, sizeof(*(ptr))) != sizeof(*(ptr)), err)

#define read_safe_eof(fd, ptr, size, err)			\
	({							\
		size_t rc__ = read(fd, ptr, (size));		\
		if (rc__ && rc__ != (size))			\
			goto err;				\
		rc__;						\
	})

#define read_ptr_safe_eof(fd, ptr, err)				\
	read_safe_eof(fd, ptr, sizeof(*(ptr)), err)

#define memzero_p(p)		memset(p, 0, sizeof(*p))
#define memzero(p, size)	memset(p, 0, size)

extern void printk_registers(user_regs_struct_t *regs);
extern void printk_siginfo(siginfo_t *siginfo);

struct vma_area;
struct list_head;

extern void printk_vma(struct vma_area *vma_area);

#define pr_info_vma_list(head)						\
	do {								\
		struct vma_area *vma;					\
		list_for_each_entry(vma, head, list)			\
			pr_info_vma(vma);				\
	} while (0)

/* Note while VMA_AREA_NONE we rely on xzalloc */
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
#define pr_info_registers(regs)		printk_registers(regs)
#define pr_info_siginfo(siginfo)	printk_siginfo(siginfo)

extern int move_img_fd(int *img_fd, int want_fd);
extern int parse_maps(pid_t pid, int pid_dir, struct list_head *vma_area_list, bool use_map_files);
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
#define pr_img_tail(type)	pr_info("\n----------------\n")

#endif /* UTIL_H_ */
