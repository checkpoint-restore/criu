#include "log.h"
#include "common/bug.h"
#include "common/xmalloc.h"
#include "common/lock.h"

#include "infect.h"
#include "infect-priv.h"
#include "infect-rpc.h"
#include "rpc-pie-priv.h"

static int __parasite_send_cmd(int sockfd, struct ctl_msg *m)
{
	int ret;

	BUILD_BUG_ON(PARASITE_USER_CMDS < __PARASITE_END_CMDS);

	ret = send(sockfd, m, sizeof(*m), 0);
	if (ret == -1) {
		pr_perror("Failed to send command %d to daemon", m->cmd);
		return -1;
	} else if (ret != sizeof(*m)) {
		pr_err("Message to daemon is trimmed (%d/%d)\n", (int)sizeof(*m), ret);
		return -1;
	}

	pr_debug("Sent msg to daemon %d %d %d\n", m->cmd, m->ack, m->err);
	return 0;
}

int parasite_wait_ack(int sockfd, unsigned int cmd, struct ctl_msg *m)
{
	int ret;

	pr_debug("Wait for ack %d on daemon socket\n", cmd);

	while (1) {
		memzero(m, sizeof(*m));

		ret = recv(sockfd, m, sizeof(*m), MSG_WAITALL);
		if (ret == -1) {
			pr_perror("Failed to read ack");
			return -1;
		} else if (ret != sizeof(*m)) {
			pr_err("Message reply from daemon is trimmed (%d/%d)\n", (int)sizeof(*m), ret);
			return -1;
		}
		pr_debug("Fetched ack: %d %d %d\n", m->cmd, m->ack, m->err);

		if (m->cmd != cmd || m->ack != cmd) {
			pr_err("Communication error, this is not "
			       "the ack we expected\n");
			return -1;
		}
		return 0;
	}

	return -1;
}

int compel_rpc_sync(unsigned int cmd, struct parasite_ctl *ctl)
{
	struct ctl_msg m;

	if (parasite_wait_ack(ctl->tsock, cmd, &m))
		return -1;

	if (m.err != 0) {
		pr_err("Command %d for daemon failed with %d\n", cmd, m.err);
		return -1;
	}

	return 0;
}

int compel_rpc_call(unsigned int cmd, struct parasite_ctl *ctl)
{
	struct ctl_msg m;

	m = ctl_msg_cmd(cmd);
	return __parasite_send_cmd(ctl->tsock, &m);
}

int compel_rpc_call_sync(unsigned int cmd, struct parasite_ctl *ctl)
{
	int ret;

	ret = compel_rpc_call(cmd, ctl);
	if (!ret)
		ret = compel_rpc_sync(cmd, ctl);

	return ret;
}

int compel_rpc_sock(struct parasite_ctl *ctl)
{
	return ctl->tsock;
}
