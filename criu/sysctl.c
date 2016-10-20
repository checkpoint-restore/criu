#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>

#include "namespaces.h"
#include "sysctl.h"
#include "util.h"

/* These are the namespaces we know how to restore in various ways.
 */
#define KNOWN_NS_MASK (CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWIPC)

struct sysctl_userns_req {
	int			op;
	unsigned int		ns;
	size_t			nr_req;
	struct sysctl_req	*reqs;
};

#define __SYSCTL_OP(__ret, __fd, __req, __type, __nr, __op)		\
do {									\
	if (__op == CTL_READ)						\
		__ret = sysctl_read_##__type(__fd, __req,		\
					     (__type *)(__req)->arg,	\
					     __nr);			\
	else if (__op == CTL_WRITE)					\
		__ret = sysctl_write_##__type(__fd, __req,		\
					      (__type *)(__req)->arg,	\
					      __nr);			\
	else								\
		__ret = -1;						\
} while (0)

#define GEN_SYSCTL_READ_FUNC(__type, __conv)				\
static int sysctl_read_##__type(int fd,					\
				struct sysctl_req *req,			\
				__type *arg,				\
				int nr)					\
{									\
	char buf[1024] = {0};						\
	int i, ret = -1;						\
	char *p = buf;							\
									\
	ret = read(fd, buf, sizeof(buf));				\
	if (ret < 0) {							\
		pr_perror("Can't read %s", req->name);			\
		ret = -1;						\
		goto err;						\
	}								\
									\
	for (i = 0; i < nr && p < buf + sizeof(buf); p++, i++)		\
		((__type *)arg)[i] = __conv(p, &p, 10);			\
									\
	if (i != nr) {							\
		pr_err("Not enough params for %s (%d != %d)\n",		\
			req->name, i, nr);				\
		goto err;						\
	}								\
									\
	ret = 0;							\
									\
err:									\
	return ret;							\
}

#define GEN_SYSCTL_WRITE_FUNC(__type, __fmt)				\
static int sysctl_write_##__type(int fd,				\
				 struct sysctl_req *req,		\
				 __type *arg,				\
				 int nr)				\
{									\
	char buf[1024];							\
	int i, ret = -1;						\
	int off = 0;							\
									\
	for (i = 0; i < nr && off < sizeof(buf) - 1; i++) {		\
		snprintf(&buf[off], sizeof(buf) - off, __fmt, arg[i]);	\
		off += strlen(&buf[off]);				\
	}								\
									\
	if (i != nr) {							\
		pr_err("Not enough space for %s (%d != %d)\n",		\
			req->name, i, nr);				\
		goto err;						\
	}								\
									\
	/* trailing spaces in format */					\
	while (off > 0 && isspace(buf[off - 1]))			\
		off--;							\
	buf[off + 0] = '\n';						\
	ret = write(fd, buf, off + 1);					\
	if (ret < 0) {							\
		pr_perror("Can't write %s", req->name);			\
		ret = -1;						\
		goto err;						\
	}								\
									\
	ret = 0;							\
err:									\
	return ret;							\
}

GEN_SYSCTL_READ_FUNC(u32, strtoul);
GEN_SYSCTL_READ_FUNC(u64, strtoull);
GEN_SYSCTL_READ_FUNC(s32, strtol);

GEN_SYSCTL_WRITE_FUNC(u32, "%u ");
GEN_SYSCTL_WRITE_FUNC(u64, "%"PRIu64" ");
GEN_SYSCTL_WRITE_FUNC(s32, "%d ");

static int
sysctl_write_char(int fd, struct sysctl_req *req, char *arg, int nr)
{
	pr_debug("%s nr %d\n", req->name, nr);
	if (dprintf(fd, "%s\n", arg) < 0)
		return -1;

	return 0;
}

static int
sysctl_read_char(int fd, struct sysctl_req *req, char *arg, int nr)
{
	int ret = -1;

	pr_debug("%s nr %d\n", req->name, nr);
	ret = read(fd, arg, nr - 1);
	if (ret < 0) {
		if (errno != EIO ||  !(req->flags & CTL_FLAGS_READ_EIO_SKIP))
			pr_perror("Can't read %s", req->name);
		goto err;
	}
	arg[ret]='\0';
	ret = 0;

err:
	return ret;
}

static int sysctl_userns_arg_size(int type)
{
	switch(CTL_TYPE(type)) {
	case __CTL_U32A:
		return sizeof(u32) * CTL_LEN(type);
	case CTL_U32:
		return sizeof(u32);
	case CTL_32:
		return sizeof(s32);
	case __CTL_U64A:
		return sizeof(u64) * CTL_LEN(type);
	case CTL_U64:
		return sizeof(u64);
	case __CTL_STR:
		return sizeof(char) * CTL_LEN(type) + 1;
	default:
		pr_err("unknown arg type %d\n", type);

		/* Ensure overflow to cause an error */
		return MAX_UNSFD_MSG_SIZE;
	}
}

static int do_sysctl_op(int fd, struct sysctl_req *req, int op)
{
	int ret = -1, nr = 1;

	switch (CTL_TYPE(req->type)) {
	case __CTL_U32A:
		nr = CTL_LEN(req->type);
		/* fallthrough */
	case CTL_U32:
		__SYSCTL_OP(ret, fd, req, u32, nr, op);
		break;
	case CTL_32:
		__SYSCTL_OP(ret, fd, req, s32, nr, op);
		break;
	case __CTL_U64A:
		nr = CTL_LEN(req->type);
		/* fallthrough */
	case CTL_U64:
		__SYSCTL_OP(ret, fd, req, u64, nr, op);
		break;
	case __CTL_STR:
		nr = CTL_LEN(req->type);
		__SYSCTL_OP(ret, fd, req, char, nr, op);
		break;
	}

	return ret;
}

static int __userns_sysctl_op(void *arg, int proc_fd, pid_t pid)
{
	int fd, ret = -1, dir, i, status, *fds = NULL;
	struct sysctl_userns_req *userns_req = arg;
	int op = userns_req->op;
	struct sysctl_req *req, **reqs = NULL;
	sigset_t blockmask, oldmask;
	pid_t worker;

	// fix up the pointer
	req = userns_req->reqs = (struct sysctl_req *) &userns_req[1];

	/* For files in the IPC/UTS namespaces, restoring is more complicated
	 * than for net. Unprivileged users cannot even open these files, so
	 * they must be opened by usernsd. However, the value in the kernel is
	 * changed for the IPC/UTS namespace that write()s to the open sysctl
	 * file (not who opened it). So, we must set the value from inside the
	 * usernsd caller's namespace. We:
	 *
	 * 1. unsd opens the sysctl files
	 * 2. forks a task
	 * 3. setns()es to the UTS/IPC namespace of the caller
	 * 4. write()s to the files and exits
	 */
	dir = open("/proc/sys", O_RDONLY, O_DIRECTORY);
	if (dir < 0) {
		pr_perror("Can't open sysctl dir");
		return -1;
	}

	fds = xmalloc(sizeof(int) * userns_req->nr_req);
	if (!fds)
		goto out;

	reqs = xmalloc(sizeof(struct sysctl_req *) * userns_req->nr_req);
	if (!reqs)
		goto out;

	memset(fds, -1, sizeof(int) * userns_req->nr_req);

	for (i = 0; i < userns_req->nr_req; i++)  {
		int arg_len = sysctl_userns_arg_size(req->type);
		int name_len = strlen((char *) &req[1]) + 1;
		int total_len = sizeof(*req) + arg_len + name_len;
		int flags;

		/* fix up the pointers */
		req->name = (char *) &req[1];
		req->arg = req->name + name_len;

		if (((char *) req) + total_len >= ((char *) userns_req) + MAX_UNSFD_MSG_SIZE) {
			pr_err("bad sysctl req %s, too big: %d\n", req->name, total_len);
			goto out;
		}

		if (op == CTL_READ)
			flags = O_RDONLY;
		else
			flags = O_WRONLY;

		fd = openat(dir, req->name, flags);
		if (fd < 0) {
			if (errno == ENOENT && (req->flags & CTL_FLAGS_OPTIONAL))
				continue;
			pr_perror("Can't open sysctl %s", req->name);
			goto out;
		}

		/* save a pointer to the req, so we don't need to recompute its
		 * location
		 */
		reqs[i] = req;
		fds[i] = fd;

		req = (struct sysctl_req *) (((char *) req) + total_len);
	}

	/*
	 * Don't let the sigchld_handler() mess with us
	 * calling waitpid() on the exited worker. The
	 * same is done in cr_system().
	 */

	sigemptyset(&blockmask);
	sigaddset(&blockmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

	worker = fork();
	if (worker < 0)
		goto out;

	if (!worker) {
		int nsfd;
		const char *nsname = ns_to_string(userns_req->ns);

		BUG_ON(!nsname);
		nsfd = openat(proc_fd, nsname, O_RDONLY);
		if (nsfd < 0) {
			pr_perror("failed to open pid %d's ns %s", pid, nsname);
			exit(1);
		}

		if (setns(nsfd, 0) < 0) {
			pr_perror("failed to setns to %d's ns %s", pid, nsname);
			exit(1);
		}

		close(nsfd);

		for (i = 0; i < userns_req->nr_req; i++) {
			if (do_sysctl_op(fds[i], reqs[i], op) < 0) {
				if (op != CTL_READ || errno != EIO || !(req->flags & CTL_FLAGS_READ_EIO_SKIP))
					exit(1);
			} else {
				/* mark sysctl in question exists */
				req->flags |= CTL_FLAGS_HAS;
			}
		}

		exit(0);
	}

	if (waitpid(worker, &status, 0) != worker) {
		pr_perror("worker didn't die?");
		kill(worker, SIGKILL);
		goto out;
	}
	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		pr_err("worker failed: %d\n", status);
		goto out;
	}

	ret = 0;

out:
	if (fds) {
		for (i = 0; i < userns_req->nr_req; i++) {
			if (fds[i] < 0)
				break;
			close_safe(&fds[i]);
		}

		xfree(fds);
	}

	if (reqs)
		xfree(reqs);

	close_safe(&dir);

	return ret;
}

static int __nonuserns_sysctl_op(struct sysctl_req *req, size_t nr_req, int op)
{
	int dir, ret, exit_code = -1;;

	dir = open("/proc/sys", O_RDONLY, O_DIRECTORY);
	if (dir < 0) {
		pr_perror("Can't open sysctl dir");
		return -1;
	}

	while (nr_req--) {
		int fd, flags;

		if (op == CTL_READ)
			flags = O_RDONLY;
		else
			flags = O_WRONLY;

		fd = openat(dir, req->name, flags);
		if (fd < 0) {
			if (errno == ENOENT && (req->flags & CTL_FLAGS_OPTIONAL)) {
				req++;
				continue;
			}
			pr_perror("Can't open sysctl %s", req->name);
			goto out;
		}

		ret = do_sysctl_op(fd, req, op);
		if (ret) {
			if (op != CTL_READ || errno != EIO || !(req->flags & CTL_FLAGS_READ_EIO_SKIP)) {
				close(fd);
				goto out;
			}
		} else {
			/* mark sysctl in question exists */
			req->flags |= CTL_FLAGS_HAS;
		}

		close(fd);
		req++;
	}

	exit_code = 0;
out:
	close(dir);
	return exit_code;
}

int sysctl_op(struct sysctl_req *req, size_t nr_req, int op, unsigned int ns)
{
	int i, fd, ret;
	struct sysctl_userns_req *userns_req;
	struct sysctl_req *cur;

	if (nr_req == 0)
		return 0;

	if (ns & ~KNOWN_NS_MASK) {
		pr_err("don't know how to restore some namespaces in %u\n", ns);
		return -1;
	}

	/* The way sysctl files behave on open/write depends on the namespace
	 * they correspond to. If we don't want to interact with something in a
	 * namespace (e.g. kernel/cap_last_cap is global), we can do this from
	 * the current process. Similarly, if we're accessing net namespaces,
	 * we can just do the operation from our current process, since
	 * anything with CAP_NET_ADMIN can write to the net/ sysctls, and we
	 * still have that even when restoring in a user ns.
	 *
	 * For IPC/UTS, we restore them as described above.
	 *
	 * For read operations, we need to copy the values back to return.
	 * Fortunately, we only do read on dump (or global reads on restore),
	 * so we can do those in process as well.
	 */
	if (!ns || ns & CLONE_NEWNET || op == CTL_READ)
		return __nonuserns_sysctl_op(req, nr_req, op);

	/*
	 * In order to avoid lots of opening of /proc/sys for each struct sysctl_req,
	 * we encode each array of sysctl_reqs into one contiguous region of memory so
	 * it can be passed via userns_call if necessary. It looks like this:
	 *
	 *  struct sysctl_userns_req    struct sysctl_req       name        arg
	 * ---------------------------------------------------------------------------
	 * |  op  |  nr_req  |  reqs  | <fields> | name | arg | "the name" | "the arg" ...
	 * ---------------------------------------------------------------------------
	 *                       |____^             |______|__^            ^
	 *                                                 |_______________|
	 */
	userns_req = alloca(MAX_UNSFD_MSG_SIZE);
	userns_req->op = op;
	userns_req->nr_req = nr_req;
	userns_req->ns = ns;
	userns_req->reqs = (struct sysctl_req *) (&userns_req[1]);

	cur = userns_req->reqs;
	for (i = 0; i < nr_req; i++) {
		int arg_len = sysctl_userns_arg_size(req[i].type);
		int name_len = strlen(req[i].name) + 1;
		int total_len = sizeof(*cur) + arg_len + name_len;

		if (((char *) cur) + total_len >= ((char *) userns_req) + MAX_UNSFD_MSG_SIZE) {
			pr_err("sysctl msg %s too big: %d\n", req[i].name, total_len);
			return -1;
		}

		/* copy over the non-pointer fields */
		cur->type = req[i].type;
		cur->flags = req[i].flags;

		cur->name = (char *) &cur[1];
		strcpy(cur->name, req[i].name);

		cur->arg = cur->name + name_len;
		memcpy(cur->arg, req[i].arg, arg_len);

		cur = (struct sysctl_req *) (((char *) cur) + total_len);
	}

	fd = open_proc(PROC_SELF, "ns");
	if (fd < 0)
		return -1;

	ret = userns_call(__userns_sysctl_op, 0, userns_req, MAX_UNSFD_MSG_SIZE, fd);
	close(fd);
	return ret;
}
