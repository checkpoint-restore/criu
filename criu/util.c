#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <ctype.h>

#include "compiler.h"
#include "asm/types.h"
#include "list.h"
#include "util.h"
#include "rst-malloc.h"
#include "image.h"
#include "vma.h"
#include "mem.h"
#include "namespaces.h"
#include "log.h"

#include "cr_options.h"
#include "servicefd.h"
#include "cr-service.h"
#include "files.h"

#include "cr-errno.h"

#define VMA_OPT_LEN	128

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
		ret = -ENOMEM;
		new = xrealloc(str, offset + delta);
		if (new) {
			va_copy(tmp, args);
			ret = vsnprintf(new + offset, delta, fmt, tmp);
			va_end(tmp);
			if (ret >= delta) {
				/* NOTE: vsnprintf returns the amount of bytes
				 * to allocate. */
				delta = ret +1;
				str = new;
				ret = 0;
			}
		}
	} while (ret == 0);

	if (ret == -ENOMEM) {
		/* realloc failed. We must release former string */
		pr_err("Failed to allocate string\n");
		xfree(str);
	} else if (ret < 0) {
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

#define opt2s(_o, _s)	do {				\
		if (v->e->status & _o)			\
			p += sprintf(opt + p, _s " ");	\
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

void pr_vma(unsigned int loglevel, const struct vma_area *vma_area)
{
	char opt[VMA_OPT_LEN];
	memset(opt, 0, VMA_OPT_LEN);

	if (!vma_area)
		return;

	vma_opt_str(vma_area, opt);
	print_on_level(loglevel, "%#"PRIx64"-%#"PRIx64" (%"PRIi64"K) prot %#x flags %#x st %#x off %#"PRIx64" "
			"%s shmid: %#"PRIx64"\n",
			vma_area->e->start, vma_area->e->end,
			KBYTES(vma_area_len(vma_area)),
			vma_area->e->prot,
			vma_area->e->flags,
			vma_area->e->status,
			vma_area->e->pgoff,
			opt, vma_area->e->shmid);
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
		/* make sure we won't clash with an inherit fd */
		if (inherit_fd_resolve_clash(new_fd) < 0)
			return -1;

		if (!allow_reuse_fd) {
			if (fcntl(new_fd, F_GETFD) != -1 || errno != EBADF) {
				pr_err("fd %d already in use (called at %s:%d)\n",
					new_fd, file, line);
				return -1;
			}
		}

		tmp = dup2(old_fd, new_fd);
		if (tmp < 0) {
			pr_perror("Dup %d -> %d failed (called at %s:%d)",
				  old_fd, new_fd, file, line);
			return tmp;
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
static int open_proc_fd = -1;
static pid_t open_proc_self_pid;
static int open_proc_self_fd = -1;

static inline void set_proc_self_fd(int fd)
{
	if (open_proc_self_fd >= 0)
		close(open_proc_self_fd);

	open_proc_self_fd = fd;
	open_proc_self_pid = getpid();
}

static inline void set_proc_pid_fd(int pid, int fd)
{
	if (open_proc_fd >= 0)
		close(open_proc_fd);

	open_proc_pid = pid;
	open_proc_fd = fd;
}

static inline int get_proc_fd(int pid)
{
	if (pid == PROC_SELF) {
		if (open_proc_self_fd != -1 && open_proc_self_pid != getpid()) {
			close(open_proc_self_fd);
			open_proc_self_fd = -1;
		}
		return open_proc_self_fd;
	} else if (pid == open_proc_pid)
		return open_proc_fd;
	else
		return -1;
}

int close_pid_proc(void)
{
	set_proc_self_fd(-1);
	set_proc_pid_fd(PROC_NONE, -1);
	return 0;
}

void close_proc()
{
	close_pid_proc();
	close_service_fd(PROC_FD_OFF);
}

int set_proc_fd(int fd)
{
	if (install_service_fd(PROC_FD_OFF, fd) < 0)
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
	close(fd);
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
		set_proc_self_fd(fd);
	else
		set_proc_pid_fd(pid, fd);

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

static int service_fd_rlim_cur;
static int service_fd_id = 0;

int init_service_fd(void)
{
	struct rlimit64 rlimit;

	/*
	 * Service FDs are those that most likely won't
	 * conflict with any 'real-life' ones
	 */

	if (syscall(__NR_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &rlimit)) {
		pr_perror("Can't get rlimit");
		return -1;
	}

	service_fd_rlim_cur = (int)rlimit.rlim_cur;
	BUG_ON(service_fd_rlim_cur < SERVICE_FD_MAX);

	return 0;
}

static int __get_service_fd(enum sfd_type type, int service_fd_id)
{
	return service_fd_rlim_cur - type - SERVICE_FD_MAX * service_fd_id;
}

int service_fd_min_fd(void)
{
	return service_fd_rlim_cur - (SERVICE_FD_MAX - 1) - SERVICE_FD_MAX * service_fd_id;
}

static DECLARE_BITMAP(sfd_map, SERVICE_FD_MAX);

int reserve_service_fd(enum sfd_type type)
{
	int sfd = __get_service_fd(type, service_fd_id);

	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	set_bit(type, sfd_map);
	return sfd;
}

int install_service_fd(enum sfd_type type, int fd)
{
	int sfd = __get_service_fd(type, service_fd_id);

	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	if (dup3(fd, sfd, O_CLOEXEC) != sfd) {
		pr_perror("Dup %d -> %d failed", fd, sfd);
		return -1;
	}

	set_bit(type, sfd_map);
	return sfd;
}

int get_service_fd(enum sfd_type type)
{
	BUG_ON((int)type <= SERVICE_FD_MIN || (int)type >= SERVICE_FD_MAX);

	if (!test_bit(type, sfd_map))
		return -1;

	return __get_service_fd(type, service_fd_id);
}

int criu_get_image_dir(void)
{
	return get_service_fd(IMG_FD_OFF);
}

int close_service_fd(enum sfd_type type)
{
	int fd;

	fd = get_service_fd(type);
	if (fd < 0)
		return 0;

	if (close_safe(&fd))
		return -1;

	clear_bit(type, sfd_map);
	return 0;
}

int clone_service_fd(int id)
{
	int ret = -1, i;

	if (service_fd_id == id)
		return 0;

	for (i = SERVICE_FD_MIN + 1; i < SERVICE_FD_MAX; i++) {
		int old = __get_service_fd(i, service_fd_id);
		int new = __get_service_fd(i, id);

		ret = dup2(old, new);
		if (ret == -1) {
			if (errno == EBADF)
				continue;
			pr_perror("Unable to clone %d->%d", old, new);
		}
	}

	service_fd_id = id;
	ret = 0;

	return ret;
}

bool is_any_service_fd(int fd)
{
	return fd > __get_service_fd(SERVICE_FD_MAX, service_fd_id) &&
		fd < __get_service_fd(SERVICE_FD_MIN, service_fd_id);
}

bool is_service_fd(int fd, enum sfd_type type)
{
	return fd == get_service_fd(type);
}

int copy_file(int fd_in, int fd_out, size_t bytes)
{
	ssize_t written = 0;
	size_t chunk = bytes ? bytes : 4096;

	while (1) {
		ssize_t ret;

		ret = sendfile(fd_out, fd_in, NULL, chunk);
		if (ret < 0) {
			pr_perror("Can't send data to ghost file");
			return -1;
		}

		if (ret == 0) {
			if (bytes && (written != bytes)) {
				pr_err("Ghost file size mismatch %zu/%zu\n",
						written, bytes);
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

#define DUP_SAFE(fd, out)						\
	({							\
		int ret__;					\
		ret__ = dup(fd);				\
		if (ret__ == -1) {				\
			pr_perror("dup(%d) failed", fd);	\
			goto out;				\
		}						\
		ret__;						\
	})

/*
 * If "in" is negative, stdin will be closed.
 * If "out" or "err" are negative, a log file descriptor will be used.
 */
int cr_system(int in, int out, int err, char *cmd, char *const argv[], unsigned flags)
{
	return cr_system_userns(in, out, err, cmd, argv, flags, -1);
}

int cr_system_userns(int in, int out, int err, char *cmd,
			char *const argv[], unsigned flags, int userns_pid)
{
	sigset_t blockmask, oldmask;
	int ret = -1, status;
	pid_t pid;

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &blockmask, &oldmask) == -1) {
		pr_perror("Can not set mask of blocked signals");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		pr_perror("fork() failed");
		goto out;
	} else if (pid == 0) {
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

		if (move_fd_from(&out, STDIN_FILENO) ||
		    move_fd_from(&err, STDIN_FILENO))
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

		execvp(cmd, argv);

		pr_perror("exec failed");
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
			pr_err("killed by signal %d: %s\n", WTERMSIG(status),
				strsignal(WTERMSIG(status)));
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

int cr_daemon(int nochdir, int noclose, int *keep_fd, int close_fd)
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

		if (*keep_fd != -1)
			*keep_fd = dup2(*keep_fd, 3);

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

int is_root_user()
{
	if (geteuid() != 0) {
		pr_err("You need to be root to run this command\n");
		return 0;
	}

	return 1;
}

int is_empty_dir(int dirfd)
{
	int ret = 0;
	DIR *fdir = NULL;
	struct dirent *de;

	fdir = fdopendir(dirfd);
	if (!fdir)
		return -1;

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

int vaddr_to_pfn(unsigned long vaddr, u64 *pfn)
{
	int fd, ret = -1;
	off_t off;

	fd = open_proc(getpid(), "pagemap");
	if (fd < 0)
		return -1;

	off = (vaddr / page_size()) * sizeof(u64);
	ret = pread(fd, pfn, sizeof(*pfn), off);
	if (ret != sizeof(*pfn)) {
		pr_perror("Can't read pme for pid %d", getpid());
		ret = -1;
	} else {
		*pfn &= PME_PFRAME_MASK;
		ret = 0;
	}

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

int mkdirpat(int fd, const char *path)
{
	size_t i;
	char made_path[PATH_MAX], *pos;

	if (strlen(path) >= PATH_MAX) {
		pr_err("path %s is longer than PATH_MAX\n", path);
		return -1;
	}

	strcpy(made_path, path);

	i = 0;
	if (made_path[0] == '/')
		i++;

	for (; i < strlen(made_path); i++) {
		pos = strchr(made_path + i, '/');
		if (pos)
			*pos = '\0';
		if (mkdirat(fd, made_path, 0755) < 0 && errno != EEXIST) {
			pr_perror("couldn't mkdirpat directory %s", made_path);
			return -1;
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
	} while(cur);
}

int fd_has_data(int lfd)
{
	struct pollfd pfd = {lfd, POLLIN, 0};
	int ret;

	ret = poll(&pfd, 1, 0);
	if (ret < 0) {
		pr_perror("poll() failed");
	}

	return ret;
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
	default:
		return NULL;
	}
}

void tcp_cork(int sk, bool on)
{
	int val = on ? 1 : 0;
	setsockopt(sk, SOL_TCP, TCP_CORK, &val, sizeof(val));
}

void tcp_nodelay(int sk, bool on)
{
	int val = on ? 1 : 0;
	setsockopt(sk, SOL_TCP, TCP_NODELAY, &val, sizeof(val));
}

static inline void pr_xsym(unsigned char *data, size_t len, int pos)
{
	char sym;

	if (pos < len)
		sym = data[pos];
	else
		sym = ' ';

	pr_msg("%c", isprint(sym) ? sym : '.');
}

static inline void pr_xdigi(unsigned char *data, size_t len, int pos)
{
	if (pos < len)
		pr_msg("%02x ", data[pos]);
	else
		pr_msg("   ");
}

static int nice_width_for(unsigned long addr)
{
	int ret = 3;

	while (addr) {
		addr >>= 4;
		ret++;
	}

	return ret;
}

void print_data(unsigned long addr, unsigned char *data, size_t size)
{
	int i, j, addr_len;
	unsigned zero_line = 0;

	addr_len = nice_width_for(addr + size);

	for (i = 0; i < size; i += 16) {
		if (*(u64 *)(data + i) == 0 && *(u64 *)(data + i + 8) == 0) {
			if (zero_line == 0)
				zero_line = 1;
			else {
				if (zero_line == 1) {
					pr_msg("*\n");
					zero_line = 2;
				}

				continue;
			}
		} else
			zero_line = 0;

		pr_msg("%#0*lx: ", addr_len, addr + i);
		for (j = 0; j < 8; j++)
			pr_xdigi(data, size, i + j);
		pr_msg(" ");
		for (j = 8; j < 16; j++)
			pr_xdigi(data, size, i + j);

		pr_msg(" |");
		for (j = 0; j < 8; j++)
			pr_xsym(data, size, i + j);
		pr_msg(" ");
		for (j = 8; j < 16; j++)
			pr_xsym(data, size, i + j);

		pr_msg("|\n");
	}
}

static int get_sockaddr_in(struct sockaddr_in *addr, char *host)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;

	if (!host)
		addr->sin_addr.s_addr = INADDR_ANY;
	else if (!inet_aton(host, &addr->sin_addr)) {
		pr_perror("Bad server address");
		return -1;
	}

	addr->sin_port = opts.port;
	return 0;
}

int setup_tcp_server(char *type)
{
	int sk = -1;
	struct sockaddr_in saddr;
	socklen_t slen = sizeof(saddr);

	pr_info("Starting %s server on port %u\n", type, (int)ntohs(opts.port));

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't init %s server", type);
		return -1;
	}

	if (get_sockaddr_in(&saddr, opts.addr))
		goto out;

	if (bind(sk, (struct sockaddr *)&saddr, slen)) {
		pr_perror("Can't bind %s server", type);
		goto out;
	}

	if (listen(sk, 1)) {
		pr_perror("Can't listen on %s server socket", type);
		goto out;
	}

	/* Get socket port in case of autobind */
	if (opts.port == 0) {
		if (getsockname(sk, (struct sockaddr *)&saddr, &slen)) {
			pr_perror("Can't get %s server name", type);
			goto out;
		}

		opts.port = ntohs(saddr.sin_port);
		pr_info("Using %u port\n", opts.port);
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
		ret = cr_daemon(1, 0, ask, cfd);
		if (ret == -1) {
			pr_err("Can't run in the background\n");
			goto out;
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

	if (sk >= 0) {
		ret = *ask = accept(sk, (struct sockaddr *)&caddr, &clen);
		if (*ask < 0)
			pr_perror("Can't accept connection to server");
		else
			pr_info("Accepted connection from %s:%u\n",
					inet_ntoa(caddr.sin_addr),
					(int)ntohs(caddr.sin_port));
		close(sk);
	}

	return 0;
out:
	close(sk);
	return -1;
}

int setup_tcp_client(char *addr)
{
	struct sockaddr_in saddr;
	int sk;

	pr_info("Connecting to server %s:%u\n", addr, (int)ntohs(opts.port));

	if (get_sockaddr_in(&saddr, addr))
		return -1;

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	if (connect(sk, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		pr_perror("Can't connect to server");
		close(sk);
		return -1;
	}

	return sk;
}
