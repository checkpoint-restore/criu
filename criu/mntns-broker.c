#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mount.h>

#include "common/scm.h"
#include "log.h"
#include "mntns-broker.h"
#include "namespaces.h"
#include "userns-broker.h"
#include "util.h"

#undef LOG_PREFIX
#define LOG_PREFIX "mntns-bkr: "

#define MNT_BROKER_PATH_MAX 4096

enum {
	MNT_BROKER_OP_MOUNT = 1,
};

struct mount_broker_msg {
	int ret;
	int err;
};

struct mount_broker_args {
	int op;
	unsigned long mount_flags;
	char src[MNT_BROKER_PATH_MAX];
	char target[MNT_BROKER_PATH_MAX];
	char fstype[64];
	char data[MNT_BROKER_PATH_MAX];
};

static int copy_mount_string(char *dst, size_t dst_len, const char *src)
{
	if (!src) {
		dst[0] = '\0';
		return 0;
	}

	if (strlen(src) >= dst_len) {
		pr_err("mntns broker: mount path too long\n");
		return -1;
	}

	strcpy(dst, src);
	return 0;
}

static int mntns_broker_enter(int pid, const char *op_name)
{
	int mntns_fd;

	if (userns_broker_enter(pid, op_name))
		return -1;

	mntns_fd = do_open_proc(pid, O_RDONLY, "ns/mnt");
	if (mntns_fd < 0) {
		pr_perror("mntns broker %s: open proc %d ns/mnt", op_name, pid);
		return -1;
	}

	if (setns(mntns_fd, CLONE_NEWNS)) {
		if (errno == EINVAL)
			pr_info("mntns broker %s: already in target mntns\n", op_name);
		else {
			pr_perror("mntns broker %s: setns mntns %d", op_name, pid);
			close(mntns_fd);
			return -1;
		}
	}
	close(mntns_fd);

	return 0;
}

static int mntns_broker_run(int pid, struct mount_broker_args *args,
			    const char *op_name)
{
	int sk[2], child_pid, status;
	struct mount_broker_msg msg = {};

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sk) < 0) {
		pr_perror("mntns broker %s: socketpair", op_name);
		return -1;
	}

	child_pid = fork();
	if (child_pid < 0) {
		pr_perror("mntns broker %s: fork", op_name);
		close(sk[0]);
		close(sk[1]);
		return -1;
	}

	if (child_pid == 0) {
		int ret = 0;

		close(sk[0]);

		if (mntns_broker_enter(pid, op_name))
			goto child_err;

		if (args->op == MNT_BROKER_OP_MOUNT) {
			ret = mount(args->src[0] ? args->src : NULL, args->target,
				    args->fstype[0] ? args->fstype : NULL, args->mount_flags,
				    args->data[0] ? args->data : NULL);
		} else {
			errno = EINVAL;
			ret = -1;
		}

		msg.ret = ret;
		msg.err = errno;

		if (send_fds(sk[1], NULL, 0, NULL, 0, &msg, sizeof(msg)))
			goto child_err;

		close(sk[1]);
		_exit(ret ? 1 : 0);

child_err:
		msg.ret = -1;
		msg.err = errno;
		send_fds(sk[1], NULL, 0, NULL, 0, &msg, sizeof(msg));
		close(sk[1]);
		_exit(1);
	}

	close(sk[1]);

	if (recv_fds(sk[0], NULL, 0, &msg, sizeof(msg)) < 0) {
		pr_perror("mntns broker %s: recv msg", op_name);
		close(sk[0]);
		waitpid(child_pid, &status, 0);
		return -1;
	}

	close(sk[0]);

	if (waitpid(child_pid, &status, 0) < 0) {
		pr_perror("mntns broker %s: waitpid", op_name);
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || msg.ret) {
		errno = msg.err ? msg.err : EIO;
		return -1;
	}

	return 0;
}

int mntns_broker_mount(int pid, const char *src, const char *target,
		       const char *fstype, unsigned long flags, const char *data)
{
	struct mount_broker_args args = {
		.op = MNT_BROKER_OP_MOUNT,
		.mount_flags = flags,
	};

	if (!target) {
		pr_err("mntns broker: missing target\n");
		return -1;
	}

	if (copy_mount_string(args.src, sizeof(args.src), src))
		return -1;
	if (copy_mount_string(args.target, sizeof(args.target), target))
		return -1;
	if (copy_mount_string(args.fstype, sizeof(args.fstype), fstype))
		return -1;
	if (copy_mount_string(args.data, sizeof(args.data), data))
		return -1;

	if (mntns_broker_run(pid, &args, "mount")) {
		pr_perror("mntns broker: mount %s -> %s failed",
			  src ? src : "(null)", target);
		return -1;
	}

	return 0;
}
