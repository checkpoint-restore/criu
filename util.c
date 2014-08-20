#define _XOPEN_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/sendfile.h>
#include <fcntl.h>

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

#include "compiler.h"
#include "asm/types.h"
#include "list.h"
#include "util.h"
#include "rst-malloc.h"
#include "image.h"
#include "vma.h"
#include "mem.h"

#include "cr_options.h"
#include "servicefd.h"
#include "cr-service.h"

#define VMA_OPT_LEN	128

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
	opt2s(VMA_FORCE_READ, "frd");
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
	print_on_level(loglevel, "%#"PRIx64"-%#"PRIx64" (%"PRIi64"K) prot %#x flags %#x off %#"PRIx64" "
			"%s shmid: %#"PRIx64"\n",
			vma_area->e->start, vma_area->e->end,
			KBYTES(vma_area_len(vma_area)),
			vma_area->e->prot,
			vma_area->e->flags,
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

		if (!allow_reuse_fd) {
			if (fcntl(new_fd, F_GETFD) != -1 || errno != EBADF) {
				if (new_fd < 3) {
					/*
					 * Standard descriptors.
					 */
					pr_warn("fd %d already in use (called at %s:%d)\n",
						new_fd, file, line);
				} else {
					pr_err("fd %d already in use (called at %s:%d)\n",
						new_fd, file, line);
					return -1;
				}
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

int move_img_fd(int *img_fd, int want_fd)
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

static pid_t open_proc_pid = PROC_NONE;
static int open_proc_fd = -1;

int close_pid_proc(void)
{
	int ret = 0;

	if (open_proc_fd >= 0)
		ret = close(open_proc_fd);

	open_proc_fd = -1;
	open_proc_pid = PROC_NONE;

	return ret;
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

	fd = open(path, O_DIRECTORY | O_RDONLY);
	if (fd == -1) {
		pr_err("Can't open %s\n", path);
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

	if (pid == open_proc_pid)
		return open_proc_fd;

	close_pid_proc();

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

	fd = openat(dfd, path, O_RDONLY);
	if (fd < 0)
		pr_perror("Can't open %s", path);
	else {
		open_proc_fd = fd;
		open_proc_pid = pid;
	}

	return fd;
}

int do_open_proc(pid_t pid, int flags, const char *fmt, ...)
{
	char path[128];
	va_list args;
	int dirfd = open_pid_proc(pid);

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
	struct rlimit rlimit;

	/*
	 * Service FDs are those that most likely won't
	 * conflict with any 'real-life' ones
	 */

	if (getrlimit(RLIMIT_NOFILE, &rlimit)) {
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
	} else if ((size_t)ret == size) {
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

void *shmalloc(size_t bytes)
{
	return rst_mem_alloc(bytes, RM_SHARED);
}

/* Only last chunk can be released */
void shfree_last(void *ptr)
{
	rst_mem_free_last(RM_SHARED);
}

int run_scripts(char *action)
{
	struct script *script;
	int ret = 0;
	char image_dir[PATH_MAX];

	pr_debug("Running %s scripts\n", action);

	if (setenv("CRTOOLS_SCRIPT_ACTION", action, 1)) {
		pr_perror("Can't set CRTOOLS_SCRIPT_ACTION=%s", action);
		return -1;
	}

	sprintf(image_dir, "/proc/%ld/fd/%d", (long) getpid(), get_service_fd(IMG_FD_OFF));
	if (setenv("CRTOOLS_IMAGE_DIR", image_dir, 1)) {
		pr_perror("Can't set CRTOOLS_IMAGE_DIR=%s", image_dir);
		return -1;
	}

	list_for_each_entry(script, &opts.scripts, node) {
		if (script->path == SCRIPT_RPC_NOTIFY) {
			pr_debug("\tRPC\n");
			ret |= send_criu_rpc_script(action, script->arg);
		} else {
			pr_debug("\t[%s]\n", script->path);
			ret |= system(script->path);
		}
	}

	unsetenv("CRTOOLS_SCRIPT_ACTION");
	return ret;
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
int cr_system(int in, int out, int err, char *cmd, char *const argv[])
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
		if (out < 0)
			out = log_get_fd();
		if (err < 0)
			err = log_get_fd();

		/*
		 * out, err, in should be a separate fds,
		 * because reopen_fd_as() closes an old fd
		 */
		if (err == out || err == in)
			err = DUP_SAFE(err, out_chld);

		if (out == in)
			out = DUP_SAFE(out, out_chld);

		if (move_img_fd(&out, STDIN_FILENO) ||
		    move_img_fd(&err, STDIN_FILENO))
			goto out_chld;

		if (in < 0) {
			close(STDIN_FILENO);
		} else {
			if (reopen_fd_as_nocheck(STDIN_FILENO, in))
				goto out_chld;
		}

		if (move_img_fd(&err, STDOUT_FILENO))
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
			if (WEXITSTATUS(status))
				pr_err("exited, status=%d\n", WEXITSTATUS(status));
			break;
		} else if (WIFSIGNALED(status)) {
			pr_err("killed by signal %d\n", WTERMSIG(status));
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

int cr_daemon(int nochdir, int noclose)
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

int vaddr_to_pfn(unsigned long vaddr, u64 *pfn)
{
	int fd, ret = -1;
	off_t off;

	fd = open_proc(getpid(), "pagemap");
	if (fd < 0)
		return -1;

	off = (vaddr / PAGE_SIZE) * sizeof(u64);
	if (lseek(fd, off, SEEK_SET) != off) {
		pr_perror("Failed to seek address %lx", vaddr);
		goto out;
	}

	ret = read(fd, pfn, sizeof(*pfn));
	if (ret != sizeof(*pfn)) {
		pr_perror("Can't read pme for pid %d", getpid());
		ret = -1;
	} else {
		*pfn &= PME_PFRAME_MASK;
		ret = 0;
	}
out:
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
		p->vm_file_fd = -1;
		p->e->fd = -1;
	}

	return p;
}

int mkdirp(const char *path)
{
	size_t i;
	char made_path[PATH_MAX], *pos;

	if (strlen(path) >= PATH_MAX) {
		pr_err("path %s is longer than PATH_MAX", path);
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
		if (mkdir(made_path, 0755) < 0 && errno != EEXIST) {
			pr_perror("couldn't mkdirpat directory");
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
