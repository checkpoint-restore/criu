#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <signal.h>

#include <bits/signum.h>

#include <sys/wait.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <linux/auto_fs4.h>
#include <linux/magic.h>

#include "zdtmtst.h"
#include "auto_dev-ioctl.h"

const char *test_doc = "Autofs (v5) migration test";
const char *test_author	= "Stanislav Kinsburskii <stanislav.kinsburskiy@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

#define AUTOFS_DEV			"/dev/autofs"

#define INDIRECT_MNT_DIR		"mnt"

int autofs_dev;
task_waiter_t t;

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
		new = realloc(str, offset + delta);
		if (new) {
			va_copy(tmp, args);
			ret = vsnprintf(new + offset, delta, fmt, tmp);
			if (ret >= delta) {
				/* NOTE: vsnprintf returns the amount of bytes
				 *                                  * to allocate. */
				delta = ret +1;
				str = new;
				ret = 0;
			}
		}
	} while (ret == 0);

	if (ret == -ENOMEM) {
		/* realloc failed. We must release former string */
		pr_err("Failed to allocate string\n");
		free(str);
	} else if (ret < 0) {
		/* vsnprintf failed */
		pr_err("Failed to print string\n");
		free(new);
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

struct autofs_params {
	const char *mountpoint;
	int (*create)(struct autofs_params *p);
	int (*setup)(struct autofs_params *p);
	int (*check)(struct autofs_params *p);
	int (*reap)(struct autofs_params *p);
	const unsigned type;
	int fd;
	struct stat fd_stat;
	void (*onexit)(void);
	const int close_pipe;
	pid_t pid;
};

struct autofs_params *my_type;

static int stop;

static int setup_direct(struct autofs_params *p)
{
	char *path;

	path = xsprintf("%s/%s/direct_file", dirname, p->mountpoint);
	if (!path) {
		pr_err("failed to allocate path\n");
		return -ENOMEM;
	}
	p->fd = open(path, O_CREAT | O_EXCL, 0600);
	if (p->fd < 0) {
		pr_perror("%d: failed to open file %s", getpid(), path);
		return -errno;
	}
	if (fstat(p->fd, &p->fd_stat)) {
		pr_perror("%d: failed to stat %s", getpid(), path);
		return -errno;
	}
	free(path);
	return 0;
}

static int setup_indirect(struct autofs_params *p)
{
	char *path;

	path = xsprintf("%s/%s/%s/indirect_file", dirname, p->mountpoint, INDIRECT_MNT_DIR);
	if (!path) {
		pr_err("failed to allocate path\n");
		return -ENOMEM;
	}
	p->fd = open(path, O_CREAT | O_EXCL, 0600);
	if (p->fd < 0) {
		pr_perror("%d: failed to open file %s", getpid(), path);
		return -errno;
	}
	if (fstat(p->fd, &p->fd_stat)) {
		pr_perror("%d: failed to stat %s", getpid(), path);
		return -errno;
	}
	free(path);
	return 0;
}

static int umount_fs(const char *mountpoint, int magic)
{
	struct statfs buf;

	if (statfs(mountpoint, &buf)) {
		pr_perror("%s: failed to statfs", mountpoint);
		return -errno;
	}
	if (buf.f_type == magic) {
		if (umount(mountpoint) < 0) {
			pr_perror("failed to umount %s tmpfs", mountpoint);
			return -errno;
		}
	}
	return 0;
}

static int check_fd(struct autofs_params *p)
{
	struct stat st;
	int ret = 0;

	if (fstat(p->fd, &st)) {
		pr_perror("failed to stat fd %d", p->fd);
		return -errno;
	}

	if (st.st_dev != p->fd_stat.st_dev) {
		skip("%s: st_dev differs: %llu != %llu "
		     "(waiting for \"device namespaces\")", p->mountpoint,
				(long long unsigned)st.st_dev,
				(long long unsigned)p->fd_stat.st_dev);
//		ret++;
	}
	if (st.st_mode != p->fd_stat.st_mode) {
		pr_err("%s: st_mode differs: 0%o != 0%o\n", p->mountpoint,
				st.st_mode, p->fd_stat.st_mode);
		ret++;
	}
	if (st.st_nlink != p->fd_stat.st_nlink) {
		pr_err("%s: st_nlink differs: %ld != %ld\n", p->mountpoint,
				(long)st.st_nlink, (long)p->fd_stat.st_nlink);
		ret++;
	}
	if (st.st_uid != p->fd_stat.st_uid) {
		pr_err("%s: st_uid differs: %u != %u\n", p->mountpoint,
				st.st_uid, p->fd_stat.st_uid);
		ret++;
	}
	if (st.st_gid != p->fd_stat.st_gid) {
		pr_err("%s: st_gid differs: %u != %u\n", p->mountpoint,
				st.st_gid, p->fd_stat.st_gid);
		ret++;
	}
	if (st.st_rdev != p->fd_stat.st_rdev) {
		pr_err("%s: st_rdev differs: %lld != %lld\n", p->mountpoint,
				(long long)st.st_rdev,
				(long long)p->fd_stat.st_rdev);
		ret++;
	}
	if (st.st_size != p->fd_stat.st_size) {
		pr_err("%s: st_size differs: %lld != %lld\n", p->mountpoint,
				(long long)st.st_size,
				(long long)p->fd_stat.st_size);
		ret++;
	}
	if (st.st_blksize != p->fd_stat.st_blksize) {
		pr_err("%s: st_blksize differs %lld != %lld:\n", p->mountpoint,
				(long long)st.st_blksize,
				(long long)p->fd_stat.st_blksize);
		ret++;
	}
	if (st.st_blocks != p->fd_stat.st_blocks) {
		pr_err("%s: st_blocks differs: %lld != %lld\n", p->mountpoint,
				(long long)st.st_blocks,
				(long long)p->fd_stat.st_blocks);
		ret++;
	}

	return ret;
}

static int check_automount(struct autofs_params *p)
{
	int err;
	char *mountpoint;

	err = check_fd(p);
	if (err) {
		pr_err("%s: opened file descriptor wasn't migrated properly\n",
				p->mountpoint);
		return err;
	}

	if (p->type == AUTOFS_TYPE_DIRECT)
		mountpoint = xsprintf("%s/%s", dirname, p->mountpoint);
	else if (p->type == AUTOFS_TYPE_INDIRECT)
		mountpoint = xsprintf("%s/%s/%s", dirname, p->mountpoint, INDIRECT_MNT_DIR);
	else {
		pr_err("Unknown autofs type: %d\n", p->type);
		return -EINVAL;
	}
	if (!mountpoint) {
		pr_err("failed to allocate string\n");
		return -ENOMEM;
	}

	if (close(p->fd)) {
		pr_err("%s: failed to close fd %d\n", p->mountpoint, p->fd);
		return -errno;
	}

	err = umount_fs(mountpoint, TMPFS_MAGIC);
	if (err)
		return err;

	free(mountpoint);

	err = p->setup(p);
	if (err) {
		pr_err("autofs doesn't workafter restore\n");
		return err;
	}

	if (close(p->fd)) {
		pr_perror("%s: failed to close fd %d", mountpoint,
				p->fd);
		return -errno;
	}

	return 0;
}

static int autofs_dev_open(void)
{
	int fd;

	if (access(AUTOFS_DEV, R_OK | W_OK)) {
		pr_perror("Device /dev/autofs is not accessible");
		return -1;
	}

	fd = open(AUTOFS_DEV, O_RDONLY);
	if (fd == -1) {
		pr_perror("failed to open /dev/autofs");
		return -errno;
	}
	return fd;
}

static int autofs_open_mount(int devid, const char *mountpoint)
{
	struct autofs_dev_ioctl *param;
	size_t size;
	int fd;

	size = sizeof(struct autofs_dev_ioctl) + strlen(mountpoint) + 1;
	param = malloc(size);

	init_autofs_dev_ioctl(param);
	param->size = size;
	param->ioctlfd = -1;
	param->openmount.devid = devid;
	strcpy(param->path, mountpoint);

	if (ioctl(autofs_dev, AUTOFS_DEV_IOCTL_OPENMOUNT, param) < 0) {
		pr_perror("failed to open autofs mount %s", mountpoint);
		return -errno;
	}

	fd = param->ioctlfd;
	free(param);

	return fd;
}

static int autofs_report_result(int token, int devid, const char *mountpoint,
				int result)
{
	int ioctl_fd;
        struct autofs_dev_ioctl param;
	int err;

	ioctl_fd = autofs_open_mount(devid, mountpoint);
	if (ioctl_fd < 0) {
		pr_err("failed to open autofs mountpoint %s\n", mountpoint);
		return ioctl_fd;
	}

	init_autofs_dev_ioctl(&param);
	param.ioctlfd = ioctl_fd;

	if (result) {
		param.fail.token = token;
		param.fail.status = result;
	} else
		param.ready.token = token;

	err = ioctl(autofs_dev, result ? AUTOFS_DEV_IOCTL_FAIL : AUTOFS_DEV_IOCTL_READY, &param);
	if (err) {
		pr_perror("failed to report result to autofs mountpoint %s", mountpoint);
		err = -errno;
	}
	close(ioctl_fd);
	return err;
}

static int mount_tmpfs(const char *mountpoint)
{
	struct statfs buf;

	if (statfs(mountpoint, &buf)) {
		pr_perror("failed to statfs %s", mountpoint);
		return -errno;
	}
	if (buf.f_type == TMPFS_MAGIC)
		return 0;

	if (mount("autofs_test", mountpoint, "tmpfs", 0, "size=1M") < 0) {
		pr_perror("failed to mount tmpfs to %s",
				mountpoint);
		return -errno;
	}
	return 0;
}

static int autofs_mount_direct(const char *mountpoint,
			       const struct autofs_v5_packet *packet)
{
	int err;
	const char *direct_mnt = mountpoint;

	err = mount_tmpfs(direct_mnt);
	if (err)
		pr_err("%d: failed to mount direct autofs mountpoint\n",
				getpid());
	return err;
}

static int autofs_mount_indirect(const char *mountpoint,
				 const struct autofs_v5_packet *packet)
{
	char *indirect_mnt;
	int err;

	indirect_mnt = xsprintf("%s/%s", mountpoint, packet->name);
	if (!indirect_mnt) {
		pr_err("failed to allocate indirect mount path\n");
		return -ENOMEM;
	}

	if ((mkdir(indirect_mnt, 0755) < 0) && (errno != EEXIST)) {
		pr_perror("failed to create %s directory", indirect_mnt);
		return -errno;
	}

	err = mount_tmpfs(indirect_mnt);
	if (err)
		pr_err("%d: failed to mount indirect autofs mountpoint\n",
				getpid());
	return err;

}

static int automountd_serve(const char *mountpoint, struct autofs_params *p,
			    const union autofs_v5_packet_union *packet)
{
	const struct autofs_v5_packet *v5_packet = &packet->v5_packet;
	int err, res;

	switch (packet->hdr.type) {
		case autofs_ptype_missing_indirect:
			res = autofs_mount_indirect(mountpoint, v5_packet);
			break;
		case autofs_ptype_missing_direct:
			res = autofs_mount_direct(mountpoint, v5_packet);
			break;
		case autofs_ptype_expire_indirect:
			pr_err("%d: expire request for indirect mount %s?",
					getpid(), v5_packet->name);
			return -EINVAL;
		case autofs_ptype_expire_direct:
			pr_err("%d: expire request for direct mount?",
					getpid());
			return -EINVAL;
		default:
			pr_err("unknown request type: %d\n", packet->hdr.type);
			return -EINVAL;
	}

	err = autofs_report_result(v5_packet->wait_queue_token, v5_packet->dev,
				   mountpoint, res);
	if (err)
		return err;
	return res;
}

static int automountd_loop(int pipe, const char *mountpoint, struct autofs_params *param)
{
	union autofs_v5_packet_union *packet;
	ssize_t bytes;
	size_t psize = sizeof(*packet);
	int err = 0;

	packet = malloc(psize);
	if (!packet) {
		pr_err("failed to allocate autofs packet\n");
		return -ENOMEM;
	}

	/* Allow SIGUSR2 to interrupt system call */
	siginterrupt(SIGUSR2, 1);

	while (!stop && !err) {
		memset(packet, 0, psize);

		bytes = read(pipe, packet, psize);
		if (bytes < 0) {
			if (errno != EINTR) {
				pr_perror("failed to read packet");
				return -errno;
			}
			continue;
		}
		if (bytes != psize) {
			pr_err("read less than expected: %zd < %zd\n",
					bytes, psize);
			return -EINVAL;
		}
		err = automountd_serve(mountpoint, param, packet);
		if (err)
			pr_err("request to autofs failed: %d\n", err);
	}
	return err;
}

static int automountd(struct autofs_params *p, int control_fd)
{
	int pipes[2];
	char *autofs_path;
	char *options;
	int ret = -1;
	char *type;

	my_type = p;

	if (p->onexit)
		atexit(p->onexit);

	autofs_path = xsprintf("%s/%s", dirname, p->mountpoint);
	if (!autofs_path) {
		pr_err("failed to allocate autofs path");
		goto err;
	}

	if (pipe(pipes) < 0) {
		pr_perror("%d: failed to create pipe", getpid());
		goto err;
	}

	if (setpgrp() < 0) {
		pr_perror("failed to become a process group leader");
		goto err;
	}

	switch (p->type) {
		case AUTOFS_TYPE_DIRECT:
			type = "direct";
			break;
		case AUTOFS_TYPE_INDIRECT:
			type = "indirect";
			break;
		case AUTOFS_TYPE_OFFSET:
			type = "offset";
			break;
		default:
			pr_err("unknown autofs type: %d\n", p->type);
			return -EINVAL;
	}

	options = xsprintf("fd=%d,pgrp=%d,minproto=5,maxproto=5,%s",
				pipes[1], getpgrp(), type);
	if (!options) {
		pr_err("failed to allocate autofs options\n");
		goto err;
	}

	if (mkdir(autofs_path, 0600) < 0) {
		pr_perror("failed to create %s", autofs_path);
		test_msg("cwd: %s\n", get_current_dir_name());
		goto err;
	}

	if (mount("autofs_test", autofs_path, "autofs", 0, options) < 0) {
		pr_perror("failed to mount autofs with options \"%s\"",
				options);
		goto err;
	}

	if (p->close_pipe)
		close(pipes[1]);

	ret = 0;
	if (write(control_fd, &ret, sizeof(ret)) != sizeof(ret)) {
		pr_perror("failed to send result");
		goto err;
	}
	close(control_fd);
	task_waiter_complete(&t, getpid());
	return automountd_loop(pipes[0], autofs_path, p);

err:
	if (write(control_fd, &ret, sizeof(ret) != sizeof(ret))) {
		pr_perror("failed to send result");
		return -errno;
	}
	return ret;
}

static int start_automounter(struct autofs_params *p)
{
	int pid;
	int control_fd[2];
	ssize_t bytes;
	int ret;

	if (pipe(control_fd) < 0) {
		pr_perror("failed to create control_fd pipe");
		return -errno;
	}

	pid = test_fork();
	switch (pid) {
		case -1:
			pr_perror("failed to fork");
			return -1;
		case 0:
			close(control_fd[0]);
			exit(automountd(p, control_fd[1]));
	}
	task_waiter_wait4(&t, pid);
	p->pid = pid;

	close(control_fd[1]);
	bytes = read(control_fd[0], &ret, sizeof(ret));
	close(control_fd[0]);

	if (bytes < 0) {
		pr_perror("failed to get start result");
		return -errno;
	}
	if (bytes != sizeof(ret)) {
		pr_err("received less than expected: %zu. Child %d died?\n",
				bytes, p->pid);
		return -EINVAL;
	}
	return ret;
}

static void do_stop(int sig)
{
	stop = 1;
}

static int reap_child(struct autofs_params *p)
{
	int status;
	int pid = p->pid;

	if (kill(pid, SIGUSR2)) {
		pr_perror("failed to kill child %d", pid);
		return -errno;
	}

	if (waitpid(pid, &status, 0) == -1) {
		pr_perror("failed to collect child %d", pid);
		return -errno;
	}

	if (WIFSIGNALED(status)) {
		pr_err("Child was killed by %d\n", WTERMSIG(status));
		return -1;
	}

	return WEXITSTATUS(status);
}

static int reap_catatonic(struct autofs_params *p)
{
	char *mountpoint;
	int err;

	mountpoint = xsprintf("%s/%s", dirname, p->mountpoint);
	if (!mountpoint) {
		pr_err("failed to allocate string\n");
		return -ENOMEM;
	}

	err = umount_fs(mountpoint, AUTOFS_SUPER_MAGIC);
	if (!err) {
		if (rmdir(mountpoint) < 0) {
			skip("failed to remove %s directory: %s\n", mountpoint,
					strerror(errno));
			err = -errno;
		}
	}
	return err;
}

static int setup_catatonic(struct autofs_params *p)
{
	char *path;

	path = xsprintf("%s/%s/file", dirname, p->mountpoint);
	if (!path) {
		pr_err("failed to allocate path\n");
		return -ENOMEM;
	}

	p->fd = open(path, O_CREAT | O_EXCL, 0600);
	if (p->fd >= 0) {
		pr_perror("%d: was able to open file %s on catatonic mount", getpid(), path);
		return -EINVAL;
	}
	free(path);
	return 0;
}

static int check_catatonic(struct autofs_params *p)
{
	char *mountpoint;
	struct statfs buf;

	mountpoint = xsprintf("%s/%s", dirname, p->mountpoint);
	if (!mountpoint) {
		pr_err("failed to allocate path\n");
		return -ENOMEM;
	}

	if (statfs(mountpoint, &buf)) {
		pr_perror("%s: failed to statfs", mountpoint);
		return -errno;
	}
	if (buf.f_type != AUTOFS_SUPER_MAGIC) {
		pr_err("Non-autofs mount on path %s\n", mountpoint);
		return -EINVAL;
	}

	return setup_catatonic(p);
}

static int create_catatonic(struct autofs_params *p)
{
	int err;
	int status;

	err = start_automounter(p);
	if (err)
		return err;

	if (kill(p->pid, SIGKILL)) {
		pr_perror("failed to kill child %d", p->pid);
		return -errno;
	}

	if (waitpid(p->pid, &status, 0) == -1) {
		pr_perror("failed to collect child %d", p->pid);
		return -errno;
	}

	return 0;
}

static void test_exit(void)
{
	if (rmdir(dirname) < 0)
		skip("failed to remove %s directory: %s\n", dirname,
				strerror(errno));
}

typedef enum {
	AUTOFS_START,
	AUTOFS_SETUP,
	AUTOFS_CHECK,
	AUTOFS_STOP
} autfs_test_action;

static int test_action(autfs_test_action act, struct autofs_params *p)
{
	int ret = 0;

	while(p->mountpoint) {
		int (*action)(struct autofs_params *p);

		switch (act) {
			case AUTOFS_START:
				action = p->create;
				break;
			case AUTOFS_SETUP:
				action = p->setup;
				break;
			case AUTOFS_CHECK:
				action = p->check;
				break;
			case AUTOFS_STOP:
				action = p->reap;
				break;
			default:
				pr_err("unknown action: %d\n", act);
				return -1;
		}

		if (action && action(p))
			ret++;

		p++;
	}
	return ret;
}

static void direct_exit(void)
{
	struct autofs_params *p = my_type;
	char *mountpoint;

	mountpoint = xsprintf("%s/%s", dirname, p->mountpoint);
	if (!mountpoint) {
		pr_err("failed to allocate string\n");
		return;
	}

	if (umount_fs(mountpoint, TMPFS_MAGIC))
		return;
	if (umount_fs(mountpoint, AUTOFS_SUPER_MAGIC))
		return;

	if (rmdir(mountpoint) < 0)
		skip("failed to remove %s directory: %s\n", mountpoint,
				strerror(errno));
}

static void indirect_exit(void)
{
	struct autofs_params *p = my_type;
	char *mountpoint, *tmpfs;

	mountpoint = xsprintf("%s/%s", dirname, p->mountpoint);
	if (!mountpoint) {
		pr_err("failed to allocate string\n");
		return;
	}

	tmpfs = xsprintf("%s/%s/%s", dirname, p->mountpoint, INDIRECT_MNT_DIR);
	if (!tmpfs) {
		pr_err("failed to allocate string\n");
		return;
	}

	if (!access(tmpfs, F_OK)) {
		if (umount_fs(tmpfs, TMPFS_MAGIC))
			return;
	}
	if (umount_fs(mountpoint, AUTOFS_SUPER_MAGIC))
		return;

	if (rmdir(mountpoint) < 0)
		skip("failed to remove %s directory: %s\n", mountpoint,
				strerror(errno));
}

enum autofs_tests {
	AUTOFS_DIRECT,
	AUTOFS_INDIRECT,
	AUTOFS_CATATONIC,
};

struct autofs_params autofs_types[] = {
	[AUTOFS_DIRECT] = {
		.mountpoint = "direct",
		.create = start_automounter,
		.setup = setup_direct,
		.check = check_automount,
		.reap = reap_child,
		.type = AUTOFS_TYPE_DIRECT,
		.fd = -1,
		.onexit = direct_exit,
		.close_pipe = 1,
	},
	[AUTOFS_INDIRECT] = {
		.mountpoint = "indirect",
		.create = start_automounter,
		.setup = setup_indirect,
		.check = check_automount,
		.reap = reap_child,
		.type = AUTOFS_TYPE_INDIRECT,
		.fd = -1,
		.onexit = indirect_exit,
		.close_pipe = 0,
	},
	[AUTOFS_CATATONIC] = {
		.mountpoint = "catatonic",
		.create = create_catatonic,
		.setup = setup_catatonic,
		.check = check_catatonic,
		.reap = reap_catatonic,
		.type = AUTOFS_TYPE_DIRECT,
		.onexit = NULL,
		.fd = -1,
		.close_pipe = 1,
	},
	{ NULL, NULL, NULL, NULL }
};

int main(int argc, char **argv)
{
	int ret = 0;

	test_init(argc, argv);

	task_waiter_init(&t);

	if (mkdir(dirname, 0777) < 0) {
		pr_perror("failed to create %s directory", dirname);
		return -1;
	}

	autofs_dev = autofs_dev_open();
	if (autofs_dev < 0)
		return -1;

	if (signal(SIGUSR2, do_stop) == SIG_ERR) {
		pr_perror("Failed to set SIGUSR2 handler");
		return -1;
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		pr_perror("Failed to set SIGPIPE handler");
		return -1;
	}

	if (test_action(AUTOFS_START, autofs_types)) {
		pr_err("AUTOFS_START action failed\n");
		ret++;
		goto err;
	}

	close(autofs_dev);

	atexit(test_exit);

	if (test_action(AUTOFS_SETUP, autofs_types)) {
		pr_err("AUTOFS_SETUP action failed\n");
		ret++;
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (test_action(AUTOFS_CHECK, autofs_types)) {
		pr_err("AUTOFS_CHECK action failed\n");
		ret++;
	}
err:
	if (test_action(AUTOFS_STOP, autofs_types)) {
		pr_err("AUTOFS_STOP action failed\n");
		ret++;
	}

	if (ret) {
		fail();
		return ret;
	}

	pass();
	return 0;
}

