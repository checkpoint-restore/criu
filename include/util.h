#ifndef __CR_UTIL_H__
#define __CR_UTIL_H__

/*
 * Some bits are stolen from perf and kvm tools
 */
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/statfs.h>
#include <dirent.h>

#include "compiler.h"
#include "asm/types.h"
#include "xmalloc.h"
#include "bug.h"
#include "log.h"
#include "err.h"

#include "protobuf/vma.pb-c.h"

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

extern int move_img_fd(int *img_fd, int want_fd);
extern int close_safe(int *fd);

extern int reopen_fd_as_safe(char *file, int line, int new_fd, int old_fd, bool allow_reuse_fd);
#define reopen_fd_as(new_fd, old_fd)		reopen_fd_as_safe(__FILE__, __LINE__, new_fd, old_fd, false)
#define reopen_fd_as_nocheck(new_fd, old_fd)	reopen_fd_as_safe(__FILE__, __LINE__, new_fd, old_fd, true)

extern void close_proc(void);
extern int open_pid_proc(pid_t pid);
extern int close_pid_proc(void);
extern int set_proc_fd(int fd);

extern int do_open_proc(pid_t pid, int flags, const char *fmt, ...);

#define __open_proc(pid, flags, fmt, ...)				\
	({								\
		int __fd = do_open_proc(pid, flags,			\
					fmt, ##__VA_ARGS__);		\
		if (__fd < 0)						\
			pr_perror("Can't open %d/" fmt " on procfs",	\
					pid, ##__VA_ARGS__);		\
									\
		__fd;							\
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
		if (__fd >= 0) {					\
			__d = fdopendir(__fd);				\
			if (__d == NULL)				\
				pr_perror("Can't fdopendir %d "		\
					"(%d/" fmt " on procfs)",	\
					__fd, pid, ##__VA_ARGS__);	\
		}							\
		__d;							\
	 })

/* FILE *fopen_proc(pid_t pid, const char *fmt, ...); */
#define fopen_proc(pid, fmt, ...)					\
	({								\
		int __fd = open_proc(pid,  fmt, ##__VA_ARGS__);		\
		FILE *__f = NULL;					\
									\
		if (__fd >= 0) {					\
			__f = fdopen(__fd, "r");			\
			if (__f == NULL)				\
				pr_perror("Can't fdopen %d "		\
					"(%d/" fmt " on procfs)",	\
					__fd, pid, ##__VA_ARGS__);	\
		}							\
		__f;							\
	 })

#define pr_img_head(type, ...)	pr_msg("\n"#type __VA_ARGS__ "\n----------------\n")
#define pr_img_tail(type)	pr_msg("----------------\n")

#define DEVZERO		(makedev(1, 5))

#define KDEV_MINORBITS	20
#define KDEV_MINORMASK	((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma, mi)	(((ma) << KDEV_MINORBITS) | (mi))

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
	 * New kernels encode devices in a new form.
	 * See kernel's fs/stat.c for details, there
	 * choose_32_64 helpers which are the key.
	 */
	unsigned major = kdev_major(kdev);
	unsigned minor = kdev_minor(kdev);
#if BITS_PER_LONG == 32
	return (major << 8) | minor;
#else
	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
#endif
}

extern int copy_file(int fd_in, int fd_out, size_t bytes);
extern int is_anon_link_type(char *link, char *type);

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

extern void *shmalloc(size_t bytes);
extern void shfree_last(void *ptr);
extern int run_scripts(char *action);

extern int cr_system(int in, int out, int err, char *cmd, char *const argv[]);
extern int cr_daemon(int nochdir, int noclose);
extern int is_root_user(void);

static inline bool dir_dots(struct dirent *de)
{
	return !strcmp(de->d_name, ".") || !strcmp(de->d_name, "..");
}

/*
 * Size of buffer to carry the worst case or /proc/self/fd/N
 * path. Since fd is an integer, we can easily estimate one :)
 */
#define PSFDS	(sizeof("/proc/self/fd/2147483647"))

extern int read_fd_link(int lfd, char *buf, size_t size);

#define USEC_PER_SEC	1000000L
#define NSEC_PER_SEC    1000000000L

int vaddr_to_pfn(unsigned long vaddr, u64 *pfn);

#endif /* __CR_UTIL_H__ */
