#include "log.h"
#include "common/bug.h"
#include "common/lock.h"

#include "uapi/compel/plugins/std/fds.h"

#include "infect-rpc.h"
#include "infect-util.h"

uint64_t compel_run_id;

int compel_util_send_fd(struct parasite_ctl *ctl, int fd)
{
	int sk;

	sk = compel_rpc_sock(ctl);
	if (send_fd(sk, NULL, 0, fd) < 0) {
		pr_perror("Can't send file descriptor");
		return -1;
	}
	return 0;
}

int compel_util_recv_fd(struct parasite_ctl *ctl, int *pfd)
{
	int sk;

	sk = compel_rpc_sock(ctl);
	if ((*pfd = recv_fd(sk)) < 0) {
		pr_perror("Can't send file descriptor");
		return -1;
	}
	return 0;
}
