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
#include <sys/sysmacros.h>
#include <dirent.h>
#include <poll.h>

#include "int.h"
#include "common/compiler.h"
#include "xmalloc.h"
#include "common/bug.h"
#include "log.h"
#include "common/err.h"

#define PREF_SHIFT_OP(pref, op, size) ((size)op(pref##BYTES_SHIFT))
#define KBYTES_SHIFT		      10
#define MBYTES_SHIFT		      20
#define GBYTES_SHIFT		      30

#define KBYTES(size) PREF_SHIFT_OP(K, >>, size)
#define MBYTES(size) PREF_SHIFT_OP(M, >>, size)
#define GBYTES(size) PREF_SHIFT_OP(G, >>, size)

#define KILO(size) PREF_SHIFT_OP(K, <<, size)
#define MEGA(size) PREF_SHIFT_OP(M, <<, size)
#define GIGA(size) PREF_SHIFT_OP(G, <<, size)

struct vma_area;
struct list_head;

extern int service_fd_rlim_cur;

extern void pr_vma(const struct vma_area *vma_area);

#define pr_info_vma(vma_area) pr_vma(vma_area)

#define pr_vma_list(head)                            \
	do {                                         \
		struct vma_area *vma;                \
		list_for_each_entry(vma, head, list) \
			pr_vma(vma);                 \
	} while (0)
#define pr_info_vma_list(head) pr_vma_list(head)

extern int move_fd_from(int *img_fd, int want_fd);
extern int close_safe(int *fd);

extern int reopen_fd_as_safe(char *file, int line, int new_fd, int old_fd, bool allow_reuse_fd);
#define reopen_fd_as(new_fd, old_fd)	     reopen_fd_as_safe(__FILE__, __LINE__, new_fd, old_fd, false)
#define reopen_fd_as_nocheck(new_fd, old_fd) reopen_fd_as_safe(__FILE__, __LINE__, new_fd, old_fd, true)

extern void close_proc(void);
extern int open_pid_proc(pid_t pid);
extern int close_pid_proc(void);
extern int set_proc_fd(int fd);

extern pid_t sys_clone_unified(unsigned long flags, void *child_stack, void *parent_tid, void *child_tid,
			       unsigned long newtls);

/*
 * Values for pid argument of the proc opening routines below.
 * SELF would open file under /proc/self
 * GEN would open a file under /proc itself
 * NONE is internal, don't use it ;)
 */

#define PROC_SELF 0
#define PROC_GEN  -1
#define PROC_NONE -2

extern int do_open_proc(pid_t pid, int flags, const char *fmt, ...) __attribute__((__format__(__printf__, 3, 4)));

#define __open_proc(pid, ier, flags, fmt, ...)                                            \
	({                                                                                \
		int __fd = do_open_proc(pid, flags, fmt, ##__VA_ARGS__);                  \
		if (__fd < 0 && (errno != (ier)))                                         \
			pr_perror("Can't open %d/" fmt " on procfs", pid, ##__VA_ARGS__); \
                                                                                          \
		__fd;                                                                     \
	})

/* int open_proc(pid_t pid, const char *fmt, ...); */
#define open_proc(pid, fmt, ...) __open_proc(pid, 0, O_RDONLY, fmt, ##__VA_ARGS__)

/* int open_proc_rw(pid_t pid, const char *fmt, ...); */
#define open_proc_rw(pid, fmt, ...) __open_proc(pid, 0, O_RDWR, fmt, ##__VA_ARGS__)

#define open_proc_path(pid, fmt, ...) __open_proc(pid, 0, O_PATH, fmt, ##__VA_ARGS__)

/* DIR *opendir_proc(pid_t pid, const char *fmt, ...); */
#define opendir_proc(pid, fmt, ...)                                  \
	({                                                           \
		int __fd = open_proc(pid, fmt, ##__VA_ARGS__);       \
		DIR *__d = NULL;                                     \
                                                                     \
		if (__fd >= 0) {                                     \
			__d = fdopendir(__fd);                       \
			if (__d == NULL)                             \
				pr_perror("Can't fdopendir %d "      \
					  "(%d/" fmt " on procfs)",  \
					  __fd, pid, ##__VA_ARGS__); \
		}                                                    \
		__d;                                                 \
	})

/* FILE *fopen_proc(pid_t pid, const char *fmt, ...); */
#define fopen_proc(pid, fmt, ...)                                    \
	({                                                           \
		int __fd = open_proc(pid, fmt, ##__VA_ARGS__);       \
		FILE *__f = NULL;                                    \
                                                                     \
		if (__fd >= 0) {                                     \
			__f = fdopen(__fd, "r");                     \
			if (__f == NULL)                             \
				pr_perror("Can't fdopen %d "         \
					  "(%d/" fmt " on procfs)",  \
					  __fd, pid, ##__VA_ARGS__); \
		}                                                    \
		__f;                                                 \
	})

#define DEVZERO (makedev(1, 5))

#define KDEV_MINORBITS 20
#define KDEV_MINORMASK ((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma, mi) (((ma) << KDEV_MINORBITS) | (mi))

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

	return makedev(major, minor);
}

extern int copy_file(int fd_in, int fd_out, size_t bytes);
extern int is_anon_link_type(char *link, char *type);

#define is_hex_digit(c) (((c) >= '0' && (c) <= '9') || ((c) >= 'a' && (c) <= 'f') || ((c) >= 'A' && (c) <= 'F'))

#define CRS_CAN_FAIL 0x1 /* cmd can validly exit with non zero code */

extern int cr_system(int in, int out, int err, char *cmd, char *const argv[], unsigned flags);
extern int cr_system_userns(int in, int out, int err, char *cmd, char *const argv[], unsigned flags, int userns_pid);
extern pid_t fork_and_ptrace_attach(int (*child_setup)(void));
extern int cr_daemon(int nochdir, int noclose, int close_fd);
extern int status_ready(void);
extern int is_root_user(void);

extern int set_proc_self_fd(int fd);

static inline bool dir_dots(const struct dirent *de)
{
	return !strcmp(de->d_name, ".") || !strcmp(de->d_name, "..");
}

extern int is_empty_dir(int dirfd);

/*
 * Size of buffer to carry the worst case or /proc/self/fd/N
 * path. Since fd is an integer, we can easily estimate one :)
 */
#define PSFDS (sizeof("/proc/self/fd/2147483647"))

extern int read_fd_link(int lfd, char *buf, size_t size);

#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L

int vaddr_to_pfn(int fd, unsigned long vaddr, u64 *pfn);

/*
 * Check whether @str starts with @sub and report the
 * next character of @str in @end
 */
static inline bool strstartswith2(const char *str, const char *sub, char *end)
{
	while (1) {
		if (*sub == '\0') /* end of sub -- match */ {
			if (end) {
				if (*(sub - 1) == '/') /* "/", "./" or "path/" */
					*end = '/';
				else
					*end = *str;
			}

			return true;
		}
		if (*str == '\0') /* end of str, sub is NOT ended -- miss */
			return false;
		if (*str != *sub)
			return false;

		str++;
		sub++;
	}
}

static inline bool strstartswith(const char *str, const char *sub)
{
	return strstartswith2(str, sub, NULL);
}

/*
 * Checks whether the @path has @sub_path as a sub path, i.e.
 * sub_path is the beginning of path and the last component
 * match is full (next character terminates path component).
 *
 * Paths shouldn't contain excessive /-s, i.e. only one slash
 * between path components and no slash at the end (except for
 * the "/" path. This is pretty good assumption to what paths
 * are used by criu.
 */

static inline bool issubpath(const char *path, const char *sub_path)
{
	char end;
	return strstartswith2(path, sub_path, &end) && (end == '/' || end == '\0');
}

extern char *get_relative_path(char *path, char *sub_path);
extern bool is_sub_path(char *path, char *sub_path);
extern bool is_same_path(char *path1, char *path2);

int strip_deleted(char *path, int len);
int cut_path_ending(char *path, char *sub_path);

/*
 * mkdir -p
 */
int mkdirpat(int fd, const char *path, int mode);

/*
 * Tests whether a path is a prefix of another path. This is different than
 * strstartswith because "/foo" is _not_ a path prefix of "/foobar", since they
 * refer to different directories.
 */
bool is_path_prefix(const char *path, const char *prefix);
FILE *fopenat(int dirfd, char *path, char *cflags);
void split(char *str, char token, char ***out, int *n);

int fd_has_data(int lfd);

int make_yard(char *path);

static inline int sk_wait_data(int sk)
{
	struct pollfd pfd = { sk, POLLIN, 0 };
	return poll(&pfd, 1, -1);
}

void fd_set_nonblocking(int fd, bool on);
void tcp_nodelay(int sk, bool on);
void tcp_cork(int sk, bool on);

const char *ns_to_string(unsigned int ns);

int xatol(const char *string, long *number);
int xatoi(const char *string, int *number);

char *xstrcat(char *str, const char *fmt, ...) __attribute__((__format__(__printf__, 2, 3)));
char *xsprintf(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

int setup_tcp_server(char *type, char *addr, unsigned short *port);
int run_tcp_server(bool daemon_mode, int *ask, int cfd, int sk);
int setup_tcp_client(char *hostname);

/* path should be writable and no more than PATH_MAX long */
int rmrf(char *path);

#define LAST_PID_PATH "sys/kernel/ns_last_pid"
#define PID_MAX_PATH  "sys/kernel/pid_max"

#define block_sigmask(saved_mask, sig_mask)                                       \
	({                                                                        \
		sigset_t ___blocked_mask;                                         \
		int ___ret = 0;                                                   \
		sigemptyset(&___blocked_mask);                                    \
		sigaddset(&___blocked_mask, sig_mask);                            \
		if (sigprocmask(SIG_BLOCK, &___blocked_mask, saved_mask) == -1) { \
			pr_perror("Can not set mask of blocked signals");         \
			___ret = -1;                                              \
		}                                                                 \
		___ret;                                                           \
	})

#define restore_sigmask(saved_mask)                                         \
	({                                                                  \
		int ___ret = 0;                                             \
		if (sigprocmask(SIG_SETMASK, saved_mask, NULL) == -1) {     \
			pr_perror("Can not unset mask of blocked signals"); \
			___ret = -1;                                        \
		}                                                           \
		___ret;                                                     \
	})

/*
 * Helpers to organize asynchronous reading from a bunch
 * of file descriptors.
 */
#include <sys/epoll.h>

struct epoll_rfd {
	int fd;
	/*
	 * EPOLLIN notification. The data is available for read in
	 * rfd->fd.
	 * @return 0 to resume polling, 1 to stop polling or a
	 * negative error code
	 */
	int (*read_event)(struct epoll_rfd *);

	/*
	 * EPOLLHUP | EPOLLRDHUP notification. The remote side has
	 * close the connection for rfd->fd.
	 * @return 0 to resume polling, 1 to stop polling or a
	 * negative error code
	 */
	int (*hangup_event)(struct epoll_rfd *);
};

extern int epoll_add_rfd(int epfd, struct epoll_rfd *);
extern int epoll_del_rfd(int epfd, struct epoll_rfd *rfd);
extern int epoll_run_rfds(int epfd, struct epoll_event *evs, int nr_fds, int tmo);
extern int epoll_prepare(int nr_events, struct epoll_event **evs);

extern void rlimit_unlimit_nofile(void);

extern int call_in_child_process(int (*fn)(void *), void *arg);
#ifdef __GLIBC__
extern void print_stack_trace(pid_t pid);
#else
static inline void print_stack_trace(pid_t pid)
{
}
#endif

#define block_sigmask(saved_mask, sig_mask)                                       \
	({                                                                        \
		sigset_t ___blocked_mask;                                         \
		int ___ret = 0;                                                   \
		sigemptyset(&___blocked_mask);                                    \
		sigaddset(&___blocked_mask, sig_mask);                            \
		if (sigprocmask(SIG_BLOCK, &___blocked_mask, saved_mask) == -1) { \
			pr_perror("Can not set mask of blocked signals");         \
			___ret = -1;                                              \
		}                                                                 \
		___ret;                                                           \
	})

#define restore_sigmask(saved_mask)                                         \
	({                                                                  \
		int ___ret = 0;                                             \
		if (sigprocmask(SIG_SETMASK, saved_mask, NULL) == -1) {     \
			pr_perror("Can not unset mask of blocked signals"); \
			___ret = -1;                                        \
		}                                                           \
		___ret;                                                     \
	})

extern int mount_detached_fs(const char *fsname);

extern char *get_legacy_iptables_bin(bool ipv6, bool restore);

extern int set_opts_cap_eff(void);

extern ssize_t read_all(int fd, void *buf, size_t size);
extern ssize_t write_all(int fd, const void *buf, size_t size);

#define cleanup_free __attribute__((cleanup(cleanup_freep)))
static inline void cleanup_freep(void *p)
{
	void **pp = (void **)p;
	free(*pp);
}

extern int run_command(char *buf, size_t buf_size, int (*child_fn)(void *), void *args);

/*
 * criu_run_id is a unique value of the current run. It can be used to
 * generate resource ID-s to avoid conflicts with other CRIU processes.
 */
extern uint64_t criu_run_id;
extern void util_init(void);

extern char *resolve_mountpoint(char *path);

#endif /* __CR_UTIL_H__ */
