#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>

#include "linux/mount.h"

#include "kerndat.h"
#include "page.h"
#include "util.h"
#include "image.h"
#include "vma.h"
#include "mem.h"
#include "namespaces.h"
#include "criu-log.h"

#include "clone-noasan.h"
#include "cr_options.h"
#include "cr-service.h"
#include "files.h"
#include "pstree.h"
#include "sched.h"

#include "cr-errno.h"
#include "action-scripts.h"

#define VMA_OPT_LEN 128

static int xatol_base(const char *string, long *number, int base)
{
	char *endptr;
	long nr;

	errno = 0;
	nr = strtol(string, &endptr, base);
	if ((errno == ERANGE && (nr == LONG_MAX || nr == LONG_MIN)) || (errno != 0 && nr == 0)) {
		pr_perror("failed to convert string '%s'", string);
		return -EINVAL;
	}

	if ((endptr == string) || (*endptr != '\0')) {
		pr_err("String is not a number: '%s'\n", string);
		return -EINVAL;
	}
	*number = nr;
	return 0;
}

int xatol(const char *string, long *number)
{
	return xatol_base(string, number, 10);
}

int xatoi(const char *string, int *number)
{
	long tmp;
	int err;

	err = xatol(string, &tmp);
	if (err)
		return err;

	if (tmp > INT_MAX || tmp < INT_MIN) {
		pr_err("value %#lx (%ld) is out of int range\n", tmp, tmp);
		return -ERANGE;
	}

	*number = (int)tmp;
	return 0;
}

/*
 * This function reallocates passed str pointer.
 * It means:
 * 1) passed pointer can be either NULL, or previously allocated by malloc.
 * 2) Passed pointer can' be reused. It's either freed in case of error or can
 * be changed.
 */
static char *xvstrcat(char *str, const char *fmt, va_list args)
{
	size_t offset = 0, delta;
	int ret;
	char *new;
	va_list tmp;

	if (str)
		offset = strlen(str);
	delta = strlen(fmt) * 2;

	do {
		new = xrealloc(str, offset + delta);
		if (!new) {
			/* realloc failed. We must release former string */
			xfree(str);
			pr_err("Failed to allocate string\n");
			return new;
		}

		va_copy(tmp, args);
		ret = vsnprintf(new + offset, delta, fmt, tmp);
		va_end(tmp);
		if (ret < delta) /* an error, or all was written */
			break;

		/* NOTE: vsnprintf returns the amount of bytes
		 * to allocate. */
		delta = ret + 1;
		str = new;
	} while (1);

	if (ret < 0) {
		/* vsnprintf failed */
		pr_err("Failed to print string\n");
		xfree(new);
		new = NULL;
	}
	return new;
}

char *xstrcat(char *str, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	str = xvstrcat(str, fmt, args);
	va_end(args);

	return str;
}

char *xsprintf(const char *fmt, ...)
{
	va_list args;
	char *str;

	va_start(args, fmt);
	str = xvstrcat(NULL, fmt, args);
	va_end(args);

	return str;
}

static void vma_opt_str(const struct vma_area *v, char *opt)
{
	int p = 0;

#define opt2s(_o, _s)                                  \
	do {                                           \
		if (v->e->status & _o)                 \
			p += sprintf(opt + p, _s " "); \
	} while (0)

	opt[p] = '\0';
	opt2s(VMA_AREA_REGULAR, "reg");
	opt2s(VMA_AREA_STACK, "stk");
	opt2s(VMA_AREA_VSYSCALL, "vsys");
	opt2s(VMA_AREA_VDSO, "vdso");
	opt2s(VMA_AREA_VVAR, "vvar");
	opt2s(VMA_AREA_HEAP, "heap");
	opt2s(VMA_FILE_PRIVATE, "fp");
	opt2s(VMA_FILE_SHARED, "fs");
	opt2s(VMA_ANON_SHARED, "as");
	opt2s(VMA_ANON_PRIVATE, "ap");
	opt2s(VMA_AREA_SYSVIPC, "sysv");
	opt2s(VMA_AREA_SOCKET, "sk");

#undef opt2s
}

void pr_vma(const struct vma_area *vma_area)
{
	char opt[VMA_OPT_LEN];
	memset(opt, 0, VMA_OPT_LEN);

	if (!vma_area)
		return;

	vma_opt_str(vma_area, opt);
	pr_info("%#" PRIx64 "-%#" PRIx64 " (%" PRIi64 "K) prot %#x flags %#x fdflags %#o st %#x off %#" PRIx64 " "
		"%s shmid: %#" PRIx64 "\n",
		vma_area->e->start, vma_area->e->end, KBYTES(vma_area_len(vma_area)), vma_area->e->prot,
		vma_area->e->flags, vma_area->e->fdflags, vma_area->e->status, vma_area->e->pgoff, opt,
		vma_area->e->shmid);
}

int close_safe(int *fd)
{
	int ret = 0;

	if (*fd > -1) {
		ret = close(*fd);
		if (!ret)
			*fd = -1;
		else
			pr_perror("Unable to close fd %d", *fd);
	}

	return ret;
}

int reopen_fd_as_safe(char *file, int line, int new_fd, int old_fd, bool allow_reuse_fd)
{
	int tmp;

	if (old_fd != new_fd) {
		if (!allow_reuse_fd)
			tmp = fcntl(old_fd, F_DUPFD, new_fd);
		else
			tmp = dup2(old_fd, new_fd);
		if (tmp < 0) {
			pr_perror("Dup %d -> %d failed (called at %s:%d)", old_fd, new_fd, file, line);
			return tmp;
		} else if (tmp != new_fd) {
			close(tmp);
			pr_err("fd %d already in use (called at %s:%d)\n", new_fd, file, line);
			return -1;
		}

		/* Just to have error message if failed */
		close_safe(&old_fd);
	}

	return 0;
}

int move_fd_from(int *img_fd, int want_fd)
{
	if (*img_fd == want_fd) {
		int tmp;

		tmp = dup(*img_fd);
		if (tmp < 0) {
			pr_perror("Can't dup file");
			return -1;
		}

		close(*img_fd);

		*img_fd = tmp;
	}

	return 0;
}

/*
 * Cached opened /proc/$pid and /proc/self files.
 * Used for faster access to /proc/.../foo files
 * by using openat()-s
 */

static pid_t open_proc_pid = PROC_NONE;
static pid_t open_proc_self_pid;

int set_proc_self_fd(int fd)
{
	int ret;

	if (fd < 0)
		return close_service_fd(PROC_SELF_FD_OFF);

	open_proc_self_pid = getpid();
	ret = install_service_fd(PROC_SELF_FD_OFF, fd);

	return ret;
}

static inline int set_proc_pid_fd(int pid, int fd)
{
	int ret;

	if (fd < 0)
		return close_service_fd(PROC_PID_FD_OFF);

	open_proc_pid = pid;
	ret = install_service_fd(PROC_PID_FD_OFF, fd);

	return ret;
}

static inline int get_proc_fd(int pid)
{
	if (pid == PROC_SELF) {
		int open_proc_self_fd;

		open_proc_self_fd = get_service_fd(PROC_SELF_FD_OFF);
		/**
		 * FIXME in case two processes from different pidnses have the
		 * same pid from getpid() and one inherited service fds from
		 * another or they share them by shared fdt - this check will
		 * not detect that one of them reuses /proc/self of another.
		 * Everything proc related may break in this case.
		 */
		if (open_proc_self_fd >= 0 && open_proc_self_pid != getpid())
			open_proc_self_fd = -1;
		return open_proc_self_fd;
	} else if (pid == open_proc_pid)
		return get_service_fd(PROC_PID_FD_OFF);
	else
		return -1;
}

int close_pid_proc(void)
{
	set_proc_self_fd(-1);
	set_proc_pid_fd(PROC_NONE, -1);
	return 0;
}

void close_proc(void)
{
	close_pid_proc();
	close_service_fd(PROC_FD_OFF);
}

int set_proc_fd(int fd)
{
	int _fd;

	_fd = dup(fd);
	if (_fd < 0) {
		pr_perror("dup() failed");
		return -1;
	}
	if (install_service_fd(PROC_FD_OFF, _fd) < 0)
		return -1;
	return 0;
}

static int open_proc_sfd(char *path)
{
	int fd, ret;

	close_proc();
	fd = open(path, O_DIRECTORY | O_PATH);
	if (fd == -1) {
		pr_perror("Can't open %s", path);
		return -1;
	}

	ret = install_service_fd(PROC_FD_OFF, fd);
	if (ret < 0)
		return -1;

	return 0;
}

inline int open_pid_proc(pid_t pid)
{
	char path[18];
	int fd;
	int dfd;

	fd = get_proc_fd(pid);
	if (fd >= 0)
		return fd;

	dfd = get_service_fd(PROC_FD_OFF);
	if (dfd < 0) {
		if (open_proc_sfd("/proc") < 0)
			return -1;

		dfd = get_service_fd(PROC_FD_OFF);
	}

	if (pid == PROC_GEN)
		/*
		 * Don't cache it, close_pid_proc() would
		 * close service descriptor otherwise.
		 */
		return dfd;

	if (pid == PROC_SELF)
		snprintf(path, sizeof(path), "self");
	else
		snprintf(path, sizeof(path), "%d", pid);

	fd = openat(dfd, path, O_PATH);
	if (fd < 0) {
		pr_perror("Can't open %s", path);
		set_cr_errno(ESRCH);
		return -1;
	}

	if (pid == PROC_SELF)
		fd = set_proc_self_fd(fd);
	else
		fd = set_proc_pid_fd(pid, fd);

	return fd;
}

int do_open_proc(pid_t pid, int flags, const char *fmt, ...)
{
	char path[128];
	va_list args;
	int dirfd;

	dirfd = open_pid_proc(pid);
	if (dirfd < 0)
		return -1;

	va_start(args, fmt);
	vsnprintf(path, sizeof(path), fmt, args);
	va_end(args);

	return openat(dirfd, path, flags);
}

int copy_file(int fd_in, int fd_out, size_t bytes)
{
	ssize_t written = 0;
	size_t chunk = bytes ? bytes : 4096;
	ssize_t ret;

	while (1) {
		/*
		 * When fd_out is a pipe, sendfile() returns -EINVAL, so we
		 * fallback to splice(). Not sure why.
		 */
		if (opts.stream)
			ret = splice(fd_in, NULL, fd_out, NULL, chunk, SPLICE_F_MOVE);
		else
			ret = sendfile(fd_out, fd_in, NULL, chunk);
		if (ret < 0) {
			pr_perror("Can't transfer data to ghost file from image");
			return -1;
		}

		if (ret == 0) {
			if (bytes && (written != bytes)) {
				pr_err("Ghost file size mismatch %zu/%zu\n", written, bytes);
				return -1;
			}
			break;
		}

		written += ret;
	}

	return 0;
}

int read_fd_link(int lfd, char *buf, size_t size)
{
	char t[32];
	ssize_t ret;

	snprintf(t, sizeof(t), "/proc/self/fd/%d", lfd);
	ret = readlink(t, buf, size);
	if (ret < 0) {
		pr_perror("Can't read link of fd %d", lfd);
		return -1;
	} else if ((size_t)ret >= size) {
		pr_err("Buffer for read link of fd %d is too small\n", lfd);
		return -1;
	}
	buf[ret] = 0;

	return ret;
}

int is_anon_link_type(char *link, char *type)
{
	char aux[32];

	snprintf(aux, sizeof(aux), "anon_inode:%s", type);
	return !strcmp(link, aux);
}

#define DUP_SAFE(fd, out)                                \
	({                                               \
		int ret__;                               \
		ret__ = dup(fd);                         \
		if (ret__ == -1) {                       \
			pr_perror("dup(%d) failed", fd); \
			goto out;                        \
		}                                        \
		ret__;                                   \
	})

/*
 * If "in" is negative, stdin will be closed.
 * If "out" or "err" are negative, a log file descriptor will be used.
 */
int cr_system(int in, int out, int err, char *cmd, char *const argv[], unsigned flags)
{
	return cr_system_userns(in, out, err, cmd, argv, flags, -1);
}

static int close_fds(int minfd)
{
	DIR *dir;
	struct dirent *de;
	int fd, ret, dfd;

	dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		pr_perror("Can't open /proc/self/fd");
		return -1;
	}
	dfd = dirfd(dir);

	while ((de = readdir(dir))) {
		if (dir_dots(de))
			continue;

		ret = sscanf(de->d_name, "%d", &fd);
		if (ret != 1) {
			pr_err("Can't parse %s\n", de->d_name);
			return -1;
		}
		if (dfd == fd)
			continue;
		if (fd < minfd)
			continue;
		/* coverity[double_close] */
		close(fd);
	}
	closedir(dir);

	return 0;
}

int cr_system_userns(int in, int out, int err, char *cmd, char *const argv[], unsigned flags, int userns_pid)
{
	sigset_t blockmask, oldmask;
	int ret = -1, status;
	pid_t pid;

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blockmask, &oldmask) == -1) {
		pr_perror("Cannot set mask of blocked signals");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		pr_perror("fork() failed");
		goto out;
	} else if (pid == 0) {
		sigemptyset(&blockmask);
		if (sigprocmask(SIG_SETMASK, &blockmask, NULL) == -1) {
			pr_perror("Cannot clear blocked signals");
			goto out_chld;
		}

		if (userns_pid > 0) {
			if (switch_ns(userns_pid, &user_ns_desc, NULL))
				goto out_chld;
			if (setuid(0) || setgid(0)) {
				pr_perror("Unable to set uid or gid");
				goto out_chld;
			}
		}

		if (out < 0)
			out = DUP_SAFE(log_get_fd(), out_chld);
		if (err < 0)
			err = DUP_SAFE(log_get_fd(), out_chld);

		/*
		 * out, err, in should be a separate fds,
		 * because reopen_fd_as() closes an old fd
		 */
		if (err == out || err == in)
			err = DUP_SAFE(err, out_chld);

		if (out == in)
			out = DUP_SAFE(out, out_chld);

		if (move_fd_from(&out, STDIN_FILENO) || move_fd_from(&err, STDIN_FILENO))
			goto out_chld;

		if (in < 0) {
			close(STDIN_FILENO);
		} else {
			if (reopen_fd_as_nocheck(STDIN_FILENO, in))
				goto out_chld;
		}

		if (move_fd_from(&err, STDOUT_FILENO))
			goto out_chld;

		if (reopen_fd_as_nocheck(STDOUT_FILENO, out))
			goto out_chld;

		if (reopen_fd_as_nocheck(STDERR_FILENO, err))
			goto out_chld;

		close_fds(STDERR_FILENO + 1);

		execvp(cmd, argv);

		/* We can't use pr_error() as log file fd is closed. */
		fprintf(stderr, "Error (%s:%d): " LOG_PREFIX "execvp(\"%s\", ...) failed: %s\n", __FILE__, __LINE__,
			cmd, strerror(errno));
	out_chld:
		_exit(1);
	}

	while (1) {
		ret = waitpid(pid, &status, 0);
		if (ret == -1) {
			pr_perror("waitpid() failed");
			goto out;
		}

		if (WIFEXITED(status)) {
			if (!(flags & CRS_CAN_FAIL) && WEXITSTATUS(status))
				pr_err("exited, status=%d\n", WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
			pr_err("killed by signal %d: %s\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
			break;
		} else if (WIFSTOPPED(status)) {
			pr_err("stopped by signal %d\n", WSTOPSIG(status));
		} else if (WIFCONTINUED(status)) {
			pr_err("continued\n");
		}
	}

	ret = status ? -1 : 0;
out:
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) == -1) {
		pr_perror("Can not unset mask of blocked signals");
		BUG();
	}

	return ret;
}

int status_ready(void)
{
	char c = 0;

	if (run_scripts(ACT_STATUS_READY))
		return -1;

	if (opts.status_fd < 0)
		return 0;

	if (write(opts.status_fd, &c, 1) != 1) {
		pr_perror("Unable to write into the status fd");
		return -1;
	}

	return close_safe(&opts.status_fd);
}

int cr_daemon(int nochdir, int noclose, int close_fd)
{
	int pid;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return -1;
	}

	if (pid > 0)
		return pid;

	setsid();
	if (!nochdir)
		if (chdir("/") == -1)
			pr_perror("Can't change directory");
	if (!noclose) {
		int fd;

		if (close_fd != -1)
			close(close_fd);

		fd = open("/dev/null", O_RDWR);
		if (fd < 0) {
			pr_perror("Can't open /dev/null");
			return -1;
		}
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}

	return 0;
}

int is_root_user(void)
{
	if (geteuid() != 0) {
		pr_err("You need to be root to run this command\n");
		return 0;
	}

	return 1;
}

/*
 * is_empty_dir will always close the FD dirfd: either implicitly
 * via closedir or explicitly in case fdopendir had failed
 *
 * return values:
 *   < 0 : open directory stream failed
 *     0 : directory is not empty
 *     1 : directory is empty
 */

int is_empty_dir(int dirfd)
{
	int ret = 0;
	DIR *fdir = NULL;
	struct dirent *de;

	fdir = fdopendir(dirfd);
	if (!fdir) {
		pr_perror("open directory stream by fd %d failed", dirfd);
		close_safe(&dirfd);
		return -1;
	}

	while ((de = readdir(fdir))) {
		if (dir_dots(de))
			continue;

		goto out;
	}

	ret = 1;
out:
	closedir(fdir);
	return ret;
}

/*
 * Get PFN from pagemap file for virtual address vaddr.
 * Optionally if fd >= 0, it's used as pagemap file descriptor
 * (may be other task's pagemap)
 */
int vaddr_to_pfn(int fd, unsigned long vaddr, u64 *pfn)
{
	int ret = -1;
	off_t off;
	bool close_fd = false;

	if (fd < 0) {
		fd = open_proc(PROC_SELF, "pagemap");
		if (fd < 0)
			return -1;
		close_fd = true;
	}

	off = (vaddr / page_size()) * sizeof(u64);
	ret = pread(fd, pfn, sizeof(*pfn), off);
	if (ret != sizeof(*pfn)) {
		pr_perror("Can't read pme for pid %d", getpid());
		ret = -1;
	} else {
		*pfn &= PME_PFRAME_MASK;
		ret = 0;
	}

	if (close_fd)
		close(fd);

	return ret;
}

/*
 * Note since VMA_AREA_NONE = 0 we can skip assignment
 * here and simply rely on xzalloc
 */
struct vma_area *alloc_vma_area(void)
{
	struct vma_area *p;

	p = xzalloc(sizeof(*p) + sizeof(VmaEntry));
	if (p) {
		p->e = (VmaEntry *)(p + 1);
		vma_entry__init(p->e);
		p->e->fd = -1;
	}

	return p;
}

int mkdirpat(int fd, const char *path, int mode)
{
	size_t i;
	char made_path[PATH_MAX], *pos;

	if (strlen(path) >= PATH_MAX) {
		pr_err("path %s is longer than PATH_MAX\n", path);
		return -ENOSPC;
	}

	strcpy(made_path, path);

	i = 0;
	if (made_path[0] == '/')
		i++;

	for (; i < strlen(made_path); i++) {
		pos = strchr(made_path + i, '/');
		if (pos)
			*pos = '\0';
		if (mkdirat(fd, made_path, mode) < 0 && errno != EEXIST) {
			int ret = -errno;
			pr_perror("couldn't mkdirpat directory %s", made_path);
			return ret;
		}
		if (pos) {
			*pos = '/';
			i = pos - made_path;
		} else
			break;
	}

	return 0;
}

bool is_path_prefix(const char *path, const char *prefix)
{
	if (strstartswith(path, prefix)) {
		size_t len = strlen(prefix);
		switch (path[len]) {
		case '\0':
		case '/':
			return true;
		}
	}

	return false;
}

FILE *fopenat(int dirfd, char *path, char *cflags)
{
	int tmp, flags = 0;
	char *iter;

	for (iter = cflags; *iter; iter++) {
		switch (*iter) {
		case 'r':
			flags |= O_RDONLY;
			break;
		case 'a':
			flags |= O_APPEND;
			break;
		case 'w':
			flags |= O_WRONLY | O_CREAT;
			break;
		case '+':
			flags = O_RDWR | O_CREAT;
			break;
		}
	}

	tmp = openat(dirfd, path, flags, S_IRUSR | S_IWUSR);
	if (tmp < 0)
		return NULL;

	return fdopen(tmp, cflags);
}

void split(char *str, char token, char ***out, int *n)
{
	int i;
	char *cur;

	*n = 0;
	for (cur = str; cur != NULL; cur = strchr(cur, token)) {
		(*n)++;
		cur++;
	}

	if (*n == 0) {
		/* This can only happen if str == NULL */
		*out = NULL;
		*n = -1;
		return;
	}

	*out = xmalloc((*n) * sizeof(char *));
	if (!*out) {
		*n = -1;
		return;
	}

	cur = str;
	i = 0;
	do {
		char *prev = cur;
		cur = strchr(cur, token);

		if (cur)
			*cur = '\0';
		(*out)[i] = xstrdup(prev);
		if (cur) {
			*cur = token;
			cur++;
		}

		if (!(*out)[i]) {
			int j;
			for (j = 0; j < i; j++)
				xfree((*out)[j]);
			xfree(*out);
			*out = NULL;
			*n = -1;
			return;
		}

		i++;
	} while (cur);
}

int fd_has_data(int lfd)
{
	struct pollfd pfd = { lfd, POLLIN, 0 };
	int ret;

	ret = poll(&pfd, 1, 0);
	if (ret < 0) {
		pr_perror("poll() failed");
	}

	return ret;
}

void fd_set_nonblocking(int fd, bool on)
{
	int flags = fcntl(fd, F_GETFL, NULL);

	if (flags < 0) {
		pr_perror("Failed to obtain flags from fd %d", fd);
		return;
	}

	if (on)
		flags |= O_NONBLOCK;
	else
		flags &= (~O_NONBLOCK);

	if (fcntl(fd, F_SETFL, flags) < 0)
		pr_perror("Failed to set flags for fd %d", fd);
}

int make_yard(char *path)
{
	if (mount("none", path, "tmpfs", 0, NULL)) {
		pr_perror("Unable to mount tmpfs in %s", path);
		return -1;
	}

	if (mount("none", path, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Unable to mark yard as private");
		return -1;
	}

	return 0;
}

const char *ns_to_string(unsigned int ns)
{
	switch (ns) {
	case CLONE_NEWIPC:
		return "ipc";
	case CLONE_NEWNS:
		return "mnt";
	case CLONE_NEWNET:
		return "net";
	case CLONE_NEWPID:
		return "pid";
	case CLONE_NEWUSER:
		return "user";
	case CLONE_NEWUTS:
		return "uts";
	case CLONE_NEWTIME:
		return "time";
	default:
		return NULL;
	}
}

void tcp_cork(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_CORK, &val, sizeof(val)))
		pr_perror("Unable to restore TCP_CORK (%d)", val);
}

void tcp_nodelay(int sk, bool on)
{
	int val = on ? 1 : 0;
	if (setsockopt(sk, SOL_TCP, TCP_NODELAY, &val, sizeof(val)))
		pr_perror("Unable to restore TCP_NODELAY (%d)", val);
}

static int get_sockaddr_in(struct sockaddr_storage *addr, char *host, unsigned short port)
{
	memset(addr, 0, sizeof(*addr));

	if (!host) {
		((struct sockaddr_in *)addr)->sin_addr.s_addr = INADDR_ANY;
		addr->ss_family = AF_INET;
	} else if (inet_pton(AF_INET, host, &((struct sockaddr_in *)addr)->sin_addr)) {
		addr->ss_family = AF_INET;
	} else if (inet_pton(AF_INET6, host, &((struct sockaddr_in6 *)addr)->sin6_addr)) {
		addr->ss_family = AF_INET6;
	} else {
		pr_err("Invalid server address \"%s\". "
		       "The address must be in IPv4 or IPv6 format.\n",
		       host);
		return -1;
	}

	if (addr->ss_family == AF_INET6) {
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
	} else if (addr->ss_family == AF_INET) {
		((struct sockaddr_in *)addr)->sin_port = htons(port);
	}

	return 0;
}

int setup_tcp_server(char *type, char *addr, unsigned short *port)
{
	int sk = -1;
	int sockopt = 1;
	struct sockaddr_storage saddr;
	socklen_t slen = sizeof(saddr);

	if (get_sockaddr_in(&saddr, addr, (*port))) {
		return -1;
	}

	pr_info("Starting %s server on port %u\n", type, *port);

	sk = socket(saddr.ss_family, SOCK_STREAM, IPPROTO_TCP);

	if (sk < 0) {
		pr_perror("Can't init %s server", type);
		return -1;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
		pr_perror("Unable to set SO_REUSEADDR");
		goto out;
	}

	if (bind(sk, (struct sockaddr *)&saddr, slen)) {
		pr_perror("Can't bind %s server", type);
		goto out;
	}

	if (listen(sk, 1)) {
		pr_perror("Can't listen on %s server socket", type);
		goto out;
	}

	/* Get socket port in case of autobind */
	if ((*port) == 0) {
		if (getsockname(sk, (struct sockaddr *)&saddr, &slen)) {
			pr_perror("Can't get %s server name", type);
			goto out;
		}

		if (saddr.ss_family == AF_INET6) {
			(*port) = ntohs(((struct sockaddr_in6 *)&saddr)->sin6_port);
		} else if (saddr.ss_family == AF_INET) {
			(*port) = ntohs(((struct sockaddr_in *)&saddr)->sin_port);
		}

		pr_info("Using %u port\n", (*port));
	}

	return sk;
out:
	close(sk);
	return -1;
}

int run_tcp_server(bool daemon_mode, int *ask, int cfd, int sk)
{
	int ret;
	struct sockaddr_in caddr;
	socklen_t clen = sizeof(caddr);

	if (daemon_mode) {
		ret = cr_daemon(1, 0, cfd);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			goto err;
		}
		if (ret > 0) { /* parent task, daemon started */
			close_safe(&sk);
			if (opts.pidfile) {
				if (write_pidfile(ret) == -1) {
					pr_perror("Can't write pidfile");
					kill(ret, SIGKILL);
					waitpid(ret, NULL, 0);
					return -1;
				}
			}

			return ret;
		}
	}

	if (status_ready())
		return -1;

	if (sk >= 0) {
		*ask = accept(sk, (struct sockaddr *)&caddr, &clen);
		if (*ask < 0) {
			pr_perror("Can't accept connection to server");
			goto err;
		} else
			pr_info("Accepted connection from %s:%u\n", inet_ntoa(caddr.sin_addr),
				(int)ntohs(caddr.sin_port));
		close(sk);
	}

	return 0;
err:
	close_safe(&sk);
	return -1;
}

int setup_tcp_client(char *hostname)
{
	struct sockaddr_storage saddr;
	struct addrinfo addr_criteria, *addr_list, *p;
	char ipstr[INET6_ADDRSTRLEN];
	int sk = -1;
	void *ip;

	memset(&addr_criteria, 0, sizeof(addr_criteria));
	addr_criteria.ai_family = AF_UNSPEC;
	addr_criteria.ai_socktype = SOCK_STREAM;
	addr_criteria.ai_protocol = IPPROTO_TCP;

	/*
	 * addr_list contains a list of addrinfo structures that corresponding
	 * to the criteria specified in hostname and addr_criteria.
	 */
	if (getaddrinfo(hostname, NULL, &addr_criteria, &addr_list)) {
		pr_perror("Failed to resolve hostname: %s", hostname);
		goto out;
	}

	/*
	 * Iterate through addr_list and try to connect. The loop stops if the
	 * connection is successful or we reach the end of the list.
	 */
	for (p = addr_list; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
			ip = &(ipv4->sin_addr);
		} else {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			ip = &(ipv6->sin6_addr);
		}

		inet_ntop(p->ai_family, ip, ipstr, sizeof(ipstr));
		pr_info("Connecting to server %s:%u\n", ipstr, opts.port);

		if (get_sockaddr_in(&saddr, ipstr, opts.port))
			goto out;

		sk = socket(saddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
		if (sk < 0) {
			pr_perror("Can't create socket");
			goto out;
		}

		if (connect(sk, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
			pr_info("Can't connect to server %s:%u\n", ipstr, opts.port);
			close(sk);
			sk = -1;
		} else {
			/* Connected successfully */
			break;
		}
	}

out:
	freeaddrinfo(addr_list);
	return sk;
}

int epoll_add_rfd(int epfd, struct epoll_rfd *rfd)
{
	struct epoll_event ev;

	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.ptr = rfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, rfd->fd, &ev) == -1) {
		pr_perror("epoll_ctl failed");
		return -1;
	}

	return 0;
}

int epoll_del_rfd(int epfd, struct epoll_rfd *rfd)
{
	if (epoll_ctl(epfd, EPOLL_CTL_DEL, rfd->fd, NULL) == -1) {
		pr_perror("epoll_ctl failed");
		return -1;
	}

	return 0;
}

static int epoll_hangup_event(int epollfd, struct epoll_rfd *rfd)
{
	int ret = 0;

	if (rfd->hangup_event) {
		ret = rfd->hangup_event(rfd);
		if (ret < 0)
			return ret;
	}

	if (epoll_del_rfd(epollfd, rfd))
		return -1;

	close_safe(&rfd->fd);

	return ret;
}

int epoll_run_rfds(int epollfd, struct epoll_event *evs, int nr_fds, int timeout)
{
	int ret, i, nr_events;
	bool have_a_break = false;

	while (1) {
		ret = epoll_wait(epollfd, evs, nr_fds, timeout);
		if (ret <= 0) {
			if (ret < 0)
				pr_perror("polling failed");
			break;
		}

		nr_events = ret;
		for (i = 0; i < nr_events; i++) {
			struct epoll_rfd *rfd;
			uint32_t events;

			rfd = (struct epoll_rfd *)evs[i].data.ptr;
			events = evs[i].events;

			if (events & EPOLLIN) {
				ret = rfd->read_event(rfd);
				if (ret < 0)
					goto out;
				if (ret > 0)
					have_a_break = true;
			}

			if (events & (EPOLLHUP | EPOLLRDHUP)) {
				ret = epoll_hangup_event(epollfd, rfd);
				if (ret < 0)
					goto out;
				if (ret > 0)
					have_a_break = true;
			}
		}

		if (have_a_break)
			return 1;
	}
out:
	return ret;
}

int epoll_prepare(int nr_fds, struct epoll_event **events)
{
	int epollfd;

	*events = xmalloc(sizeof(struct epoll_event) * nr_fds);
	if (!*events)
		return -1;

	epollfd = epoll_create(nr_fds);
	if (epollfd < 0) {
		pr_perror("epoll_create failed");
		goto free_events;
	}

	return epollfd;

free_events:
	xfree(*events);
	*events = NULL;
	return -1;
}

int call_in_child_process(int (*fn)(void *), void *arg)
{
	int status, ret = -1;
	pid_t pid;
	/*
	 * Parent freezes till child exit, so child may use the same stack.
	 * No SIGCHLD flag, so it's not need to block signal.
	 */
	pid = clone_noasan(fn, CLONE_VFORK | CLONE_VM | CLONE_FILES | CLONE_IO | CLONE_SIGHAND | CLONE_SYSVSEM, arg);
	if (pid == -1) {
		pr_perror("Can't clone");
		return -1;
	}
	errno = 0;
	if (waitpid(pid, &status, __WALL) != pid || !WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("Can't wait or bad status: errno=%d, status=%d\n", errno, status);
		goto out;
	}
	ret = 0;
	/*
	 * Child opened PROC_SELF for pid. If we create one more child
	 * with the same pid later, it will try to reuse this /proc/self.
	 */
out:
	close_pid_proc();
	return ret;
}

void rlimit_unlimit_nofile(void)
{
	struct rlimit new;

	new.rlim_cur = kdat.sysctl_nr_open;
	new.rlim_max = kdat.sysctl_nr_open;

	if (prlimit(getpid(), RLIMIT_NOFILE, &new, NULL)) {
		pr_perror("rlimit: Can't setup RLIMIT_NOFILE for self");
		return;
	} else
		pr_debug("rlimit: RLIMIT_NOFILE unlimited for self\n");

	service_fd_rlim_cur = kdat.sysctl_nr_open;
}

#ifdef __GLIBC__
#include <execinfo.h>
void print_stack_trace(pid_t pid)
{
	void *array[10];
	char **strings;
	size_t size, i;

	size = backtrace(array, 10);
	strings = backtrace_symbols(array, size);

	for (i = 0; i < size; i++)
		pr_err("stack %d#%zu: %s\n", pid, i, strings[i]);

	free(strings);
}
#endif

int mount_detached_fs(const char *fsname)
{
	int fsfd, fd;

	fsfd = sys_fsopen(fsname, 0);
	if (fsfd < 0) {
		pr_perror("Unable to open the %s file system", fsname);
		return -1;
	}

	if (sys_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0) {
		pr_perror("Unable to create the %s file system", fsname);
		close(fsfd);
		return -1;
	}

	fd = sys_fsmount(fsfd, 0, 0);
	if (fd < 0)
		pr_perror("Unable to mount the %s file system", fsname);
	close(fsfd);
	return fd;
}

int strip_deleted(char *name, int len)
{
	struct dcache_prepends {
		const char *str;
		size_t len;
	} static const prepends[] = { {
					      .str = " (deleted)",
					      .len = 10,
				      },
				      {
					      .str = "//deleted",
					      .len = 9,
				      } };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(prepends); i++) {
		size_t at;

		if (len <= prepends[i].len)
			continue;

		at = len - prepends[i].len;
		if (!strcmp(&name[at], prepends[i].str)) {
			pr_debug("Strip '%s' tag from '%s'\n", prepends[i].str, name);
			name[at] = '\0';
			len -= prepends[i].len;
			return 1;
		}
	}
	return 0;
}

/*
 * This function check if path ends with ending and cuts it from path.
 * Return 0 if path is cut. -1 otherwise, leaving path unchanged.
 * Example:
 *	path = "/foo/bar", ending = "bar"
 *	cut(path, ending)  -> path becomes "/foo"
 *
 * 1. Skip leading "./" in subpath.
 * 2. Respect root: ("/a/b", "b") -> "/a" but ("/a", "a") -> "/"
 * 3. Refuse to cut identical strings, e.g. ("abc", "abc") will result in -1
 * 4. Do not handle "..", "//", "./" (with exception "./" as leading symbols)
 */

int cut_path_ending(char *path, char *ending)
{
	int ending_pos;

	if (ending[0] == '.' && ending[1] == '/')
		ending = ending + 2;

	ending_pos = strlen(path) - strlen(ending);

	if (ending_pos < 1)
		return -1;

	if (strcmp(path + ending_pos, ending))
		return -1;

	if (path[ending_pos - 1] != '/')
		return -1;

	if (ending_pos == 1) {
		path[ending_pos] = 0;
		return 0;
	}

	path[ending_pos - 1] = 0;
	return 0;
}

static int is_iptables_nft(char *bin)
{
	int pfd[2] = { -1, -1 }, ret = -1;
	char *cmd[] = { bin, "-V", NULL };
	char buf[100];

	if (pipe(pfd) < 0) {
		pr_perror("Unable to create pipe");
		goto err;
	}

	ret = cr_system(-1, pfd[1], -1, cmd[0], cmd, 0);
	if (ret) {
		pr_err("%s -V failed\n", cmd[0]);
		goto err;
	}

	close_safe(&pfd[1]);

	ret = read(pfd[0], buf, sizeof(buf) - 1);
	if (ret < 0) {
		pr_perror("Unable to read %s -V output", cmd[0]);
		goto err;
	}

	buf[ret] = '\0';
	ret = 0;

	if (strstr(buf, "nf_tables")) {
		pr_info("iptables has nft backend: %s\n", buf);
		ret = 1;
	}

err:
	close_safe(&pfd[1]);
	close_safe(&pfd[0]);
	return ret;
}

char *get_legacy_iptables_bin(bool ipv6)
{
	static char iptables_bin[2][32];
	/* 0  - means we don't know yet,
	 * -1 - not present,
	 * 1  - present.
	 */
	static int iptables_present[2] = { 0, 0 };
	char bins[2][2][32] = { { "iptables-save", "iptables-legacy-save" },
				{ "ip6tables-save", "ip6tables-legacy-save" } };
	int ret;

	if (iptables_present[ipv6] == -1)
		return NULL;

	if (iptables_present[ipv6] == 1)
		return iptables_bin[ipv6];

	memcpy(iptables_bin[ipv6], bins[ipv6][0], strlen(bins[ipv6][0]) + 1);
	ret = is_iptables_nft(iptables_bin[ipv6]);

	/*
	 * iptables on host uses nft backend (or not installed),
	 * let's try iptables-legacy
	 */
	if (ret < 0 || ret == 1) {
		memcpy(iptables_bin[ipv6], bins[ipv6][1], strlen(bins[ipv6][1]) + 1);
		ret = is_iptables_nft(iptables_bin[ipv6]);
		if (ret < 0 || ret == 1) {
			iptables_present[ipv6] = -1;
			return NULL;
		}
	}

	/* we can come here with iptables-save or iptables-legacy-save */
	iptables_present[ipv6] = 1;

	return iptables_bin[ipv6];
}

/*
 * read_all() behaves like read() without the possibility of partial reads.
 * Use only with blocking I/O.
 */
ssize_t read_all(int fd, void *buf, size_t size)
{
	ssize_t n = 0;
	while (size > 0) {
		ssize_t ret = read(fd, buf, size);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			/*
			 * The caller should use standard read() for
			 * non-blocking I/O.
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				errno = EINVAL;
			return ret;
		}
		if (ret == 0)
			break;
		n += ret;
		buf = (char *)buf + ret;
		size -= ret;
	}
	return n;
}

/*
 * write_all() behaves like write() without the possibility of partial writes.
 * Use only with blocking I/O.
 */
ssize_t write_all(int fd, const void *buf, size_t size)
{
	ssize_t n = 0;
	while (size > 0) {
		ssize_t ret = write(fd, buf, size);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			/*
			 * The caller should use standard write() for
			 * non-blocking I/O.
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				errno = EINVAL;
			return ret;
		}
		n += ret;
		buf = (char *)buf + ret;
		size -= ret;
	}
	return n;
}

int rm_rf(char *target)
{
	int offset = strlen(target);
	DIR *dir = NULL;
	struct dirent *de;
	int ret = -1;

	dir = opendir(target);
	if (!dir) {
		pr_perror("unable to open %s", target);
		return -1;
	}

	while ((de = readdir(dir))) {
		int n;

		if (dir_dots(de))
			continue;

		n = snprintf(target + offset, PATH_MAX - offset, "/%s", de->d_name);
		if (n < 0 || n >= PATH_MAX) {
			pr_err("snprintf failed\n");
			goto out;
		}

		if (de->d_type == DT_DIR && rm_rf(target))
			goto out;

		if (remove(target) < 0) {
			pr_perror("unable to remove %s", target);
			goto out;
		}
	}

	ret = 0;
out:
	target[offset] = 0;
	return ret;
}

__attribute__((returns_twice)) static pid_t raw_legacy_clone(unsigned long flags, int *pidfd)
{
#if defined(__s390x__) || defined(__s390__) || defined(__CRIS__)
	/* On s390/s390x and cris the order of the first and second arguments
	 * of the system call is reversed.
	 */
	return syscall(__NR_clone, NULL, flags | SIGCHLD, pidfd);
#elif defined(__sparc__) && defined(__arch64__)
	{
		/*
		 * sparc64 always returns the other process id in %o0, and a
		 * boolean flag whether this is the child or the parent in %o1.
		 * Inline assembly is needed to get the flag returned in %o1.
		 */
		register long g1 asm("g1") = __NR_clone;
		register long o0 asm("o0") = flags | SIGCHLD;
		register long o1 asm("o1") = 0; /* is parent/child indicator */
		register long o2 asm("o2") = (unsigned long)pidfd;
		long is_error, retval, in_child;
		pid_t child_pid;

		asm volatile(
#if defined(__arch64__)
			"t 0x6d\n\t" /* 64-bit trap */
#else
			"t 0x10\n\t" /* 32-bit trap */
#endif
			/*
		     * catch errors: On sparc, the carry bit (csr) in the
		     * processor status register (psr) is used instead of a
		     * full register.
		     */
			"addx %%g0, 0, %%g1"
			: "=r"(g1), "=r"(o0), "=r"(o1), "=r"(o2) /* outputs */
			: "r"(g1), "r"(o0), "r"(o1), "r"(o2) /* inputs */
			: "%cc"); /* clobbers */

		is_error = g1;
		retval = o0;
		in_child = o1;

		if (is_error) {
			errno = retval;
			return -1;
		}

		if (in_child)
			return 0;

		child_pid = retval;
		return child_pid;
	}
#elif defined(__ia64__)
	/* On ia64 the stack and stack size are passed as separate arguments. */
	return syscall(__NR_clone, flags | SIGCHLD, NULL, 0, pidfd);
#else
	return syscall(__NR_clone, flags | SIGCHLD, NULL, pidfd);
#endif
}

__attribute__((returns_twice)) static pid_t raw_clone(unsigned long flags, int *pidfd)
{
	pid_t pid;
	struct _clone_args args = {
		.flags = flags,
		.pidfd = ptr_to_u64(pidfd),
	};

	if (flags & (CLONE_VM | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | CLONE_SETTLS))
		return -EINVAL;

	/* On CLONE_PARENT we inherit the parent's exit signal. */
	if (!(flags & CLONE_PARENT))
		args.exit_signal = SIGCHLD;

	pid = syscall(__NR_clone3, &args, sizeof(args));
	if (pid < 0 && errno == ENOSYS)
		return raw_legacy_clone(flags, pidfd);

	return pid;
}

static int wait_for_pid(pid_t pid)
{
	int status, ret;

again:
	ret = waitpid(pid, &status, 0);
	if (ret == -1) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (ret != pid)
		goto again;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -1;

	return 0;
}

int run_command(char *buf, size_t buf_size, int (*child_fn)(void *), void *args)
{
	pid_t child;
	int ret, fret, pipefd[2];
	ssize_t bytes;

	/* Make sure our callers do not receive uninitialized memory. */
	if (buf_size > 0 && buf)
		buf[0] = '\0';

	if (pipe(pipefd) < 0)
		return -1;

	child = raw_clone(0, NULL);
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (child == 0) {
		/* Close the read-end of the pipe. */
		close(pipefd[0]);

		/* Redirect std{err,out} to write-end of the
		 * pipe.
		 */
		ret = dup2(pipefd[1], STDOUT_FILENO);
		if (ret >= 0)
			ret = dup2(pipefd[1], STDERR_FILENO);

		/* Close the write-end of the pipe. */
		close(pipefd[1]);

		if (ret < 0)
			_exit(EXIT_FAILURE);

		/* Does not return. */
		child_fn(args);
		_exit(EXIT_FAILURE);
	}

	/* close the write-end of the pipe */
	close(pipefd[1]);

	if (buf && buf_size > 0) {
		bytes = read_all(pipefd[0], buf, buf_size - 1);
		if (bytes > 0)
			buf[bytes - 1] = '\0';
	}

	fret = wait_for_pid(child);

	/* close the read-end of the pipe */
	close(pipefd[0]);

	return fret;
}
