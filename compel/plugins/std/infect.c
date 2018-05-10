#include <compel/plugins/std.h>

#include "common/scm.h"
#include "common/compiler.h"
#include "common/lock.h"
#include "common/page.h"

#define pr_err(fmt, ...)	print_on_level(1, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	print_on_level(3, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)	print_on_level(4, fmt, ##__VA_ARGS__)

#include "common/bug.h"

#include "uapi/compel/asm/sigframe.h"
#include "uapi/compel/infect-rpc.h"

#include "rpc-pie-priv.h"

static int tsock = -1;

static struct rt_sigframe *sigframe;

#ifdef ARCH_HAS_LONG_PAGES
/*
 * XXX: Make it compel's std plugin global variable. Drop parasite_size().
 * Hint: compel on aarch64 shall learn relocs for that.
 */
static unsigned __page_size;

unsigned __attribute((weak)) page_size(void)
{
	return __page_size;
}
#endif

int parasite_get_rpc_sock(void)
{
	return tsock;
}

/* RPC helpers */
static int __parasite_daemon_reply_ack(unsigned int cmd, int err)
{
	struct ctl_msg m;
	int ret;

	m = ctl_msg_ack(cmd, err);
	ret = sys_sendto(tsock, &m, sizeof(m), 0, NULL, 0);
	if (ret != sizeof(m)) {
		pr_err("Sent only %d bytes while %zu expected\n", ret, sizeof(m));
		return -1;
	}

	pr_debug("__sent ack msg: %d %d %d\n",
		 m.cmd, m.ack, m.err);

	return 0;
}

static int __parasite_daemon_wait_msg(struct ctl_msg *m)
{
	int ret;

	pr_debug("Daemon waits for command\n");

	while (1) {
		*m = (struct ctl_msg){ };
		ret = sys_recvfrom(tsock, m, sizeof(*m), MSG_WAITALL, NULL, 0);
		if (ret != sizeof(*m)) {
			pr_err("Trimmed message received (%d/%d)\n",
			       (int)sizeof(*m), ret);
			return -1;
		}

		pr_debug("__fetched msg: %d %d %d\n",
			 m->cmd, m->ack, m->err);
		return 0;
	}

	return -1;
}

/* Core infect code */

static noinline void fini_sigreturn(unsigned long new_sp)
{
	ARCH_RT_SIGRETURN(new_sp, sigframe);
}

static int fini(void)
{
	unsigned long new_sp;

	parasite_cleanup();

	new_sp = (long)sigframe + RT_SIGFRAME_OFFSET(sigframe);
	pr_debug("%ld: new_sp=%lx ip %lx\n", sys_gettid(),
		  new_sp, RT_SIGFRAME_REGIP(sigframe));

	sys_close(tsock);
	std_log_set_fd(-1);

	fini_sigreturn(new_sp);

	BUG();

	return -1;
}

static noinline __used int noinline parasite_daemon(void *args)
{
	struct ctl_msg m;
	int ret = -1;

	pr_debug("Running daemon thread leader\n");

	/* Reply we're alive */
	if (__parasite_daemon_reply_ack(PARASITE_CMD_INIT_DAEMON, 0))
		goto out;

	ret = 0;

	while (1) {
		if (__parasite_daemon_wait_msg(&m))
			break;

		if (ret && m.cmd != PARASITE_CMD_FINI) {
			pr_err("Command rejected\n");
			continue;
		}

		if (m.cmd == PARASITE_CMD_FINI)
			goto out;

		ret = parasite_daemon_cmd(m.cmd, args);

		if (__parasite_daemon_reply_ack(m.cmd, ret))
			break;

		if (ret) {
			pr_err("Close the control socket for writing\n");
			sys_shutdown(tsock, SHUT_WR);
		}
	}

out:
	fini();

	return 0;
}

static noinline __used int parasite_init_daemon(void *data)
{
	struct parasite_init_args *args = data;
	int ret;

	args->sigreturn_addr = (uint64_t)(uintptr_t)fini_sigreturn;
	sigframe = (void*)(uintptr_t)args->sigframe;
#ifdef ARCH_HAS_LONG_PAGES
	__page_size = args->page_size;
#endif

	ret = tsock = sys_socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if (tsock < 0) {
		pr_err("Can't create socket: %d\n", tsock);
		goto err;
	}

	ret = sys_connect(tsock, (struct sockaddr *)&args->h_addr, args->h_addr_len);
	if (ret < 0) {
		pr_err("Can't connect the control socket\n");
		goto err;
	}

	futex_set_and_wake(&args->daemon_connected, 1);

	ret = recv_fd(tsock);
	if (ret >= 0) {
		std_log_set_fd(ret);
		std_log_set_loglevel(args->log_level);
		ret = 0;
	} else
		goto err;

	parasite_daemon(data);

err:
	futex_set_and_wake(&args->daemon_connected, ret);
	fini();
	BUG();

	return -1;
}

#ifndef __parasite_entry
# define __parasite_entry
#endif

int __used __parasite_entry parasite_service(unsigned int cmd, void *args)
{
	pr_info("Parasite cmd %d/%x process\n", cmd, cmd);

	if (cmd == PARASITE_CMD_INIT_DAEMON)
		return parasite_init_daemon(args);

	return parasite_trap_cmd(cmd, args);
}
