#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/scm.h"
#include "log.h"
#include "namespaces.h"
#include "userns-broker.h"
#include "utsns-broker.h"
#include "util.h"

#undef LOG_PREFIX
#define LOG_PREFIX "utsns-bkr: "

struct uts_broker_msg {
	int ret;
	int err;
};

static int utsns_broker_enter(int pid, const char *op_name)
{
	int utsns_fd;

	if (userns_broker_enter(pid, op_name))
		return -1;

	utsns_fd = do_open_proc(pid, O_RDONLY, "ns/uts");
	if (utsns_fd < 0) {
		pr_perror("utsns broker %s: open proc %d ns/uts", op_name, pid);
		return -1;
	}

	if (setns(utsns_fd, CLONE_NEWUTS)) {
		if (errno == EINVAL)
			pr_info("utsns broker %s: already in target utsns\n", op_name);
		else {
			pr_perror("utsns broker %s: setns utsns %d", op_name, pid);
			close(utsns_fd);
			return -1;
		}
	}
	close(utsns_fd);

	return 0;
}

static int utsns_broker_run(int pid, const char *nodename,
			    const char *domainname, const char *op_name)
{
	int sk[2], child_pid, status;
	struct uts_broker_msg msg = {};

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sk) < 0) {
		pr_perror("utsns broker %s: socketpair", op_name);
		return -1;
	}

	child_pid = fork();
	if (child_pid < 0) {
		pr_perror("utsns broker %s: fork", op_name);
		close(sk[0]);
		close(sk[1]);
		return -1;
	}

	if (child_pid == 0) {
		int ret = 0;

		close(sk[0]);

		if (utsns_broker_enter(pid, op_name))
			goto child_err;

		if (sethostname(nodename, strlen(nodename))) {
			pr_perror("utsns broker: sethostname");
			ret = -1;
		}

		if (ret == 0 && setdomainname(domainname, strlen(domainname))) {
			pr_perror("utsns broker: setdomainname");
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
		pr_perror("utsns broker %s: recv msg", op_name);
		close(sk[0]);
		waitpid(child_pid, &status, 0);
		return -1;
	}

	close(sk[0]);

	if (waitpid(child_pid, &status, 0) < 0) {
		pr_perror("utsns broker %s: waitpid", op_name);
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || msg.ret) {
		errno = msg.err ? msg.err : EIO;
		return -1;
	}

	return 0;
}

int utsns_broker_set_hostname(int pid, const char *nodename,
			      const char *domainname)
{
	if (utsns_broker_run(pid, nodename, domainname, "sethostname")) {
		pr_perror("utsns broker: failed to set hostname/domainname for pid %d",
			  pid);
		return -1;
	}

	return 0;
}
