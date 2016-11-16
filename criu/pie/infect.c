#include "common/compiler.h"
#include "common/lock.h"
#include "int.h"
#include "util-pie.h"

#include <compel/plugins/std/log.h>
#include "criu-log.h"
#include "common/bug.h"
#include "sigframe.h"
#include "infect-rpc.h"
#include "infect-pie.h"
#include "compel/include/rpc-pie-priv.h"

static int tsock = -1;

static struct rt_sigframe *sigframe;

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

static noinline int unmap_itself(void *data)
{
	struct parasite_unmap_args *args = data;

	sys_munmap(args->parasite_start, args->parasite_len);
	/*
	 * This call to sys_munmap must never return. Instead, the controlling
	 * process must trap us on the exit from munmap.
	 */

	BUG();
	return -1;
}

static noinline __used int parasite_init_daemon(void *data)
{
	struct parasite_init_args *args = data;
	int ret;

	args->sigreturn_addr = (uint64_t)(uintptr_t)fini_sigreturn;
	sigframe = (void*)(uintptr_t)args->sigframe;

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

	switch (cmd) {
	case PARASITE_CMD_INIT_DAEMON:
		return parasite_init_daemon(args);
	case PARASITE_CMD_UNMAP:
		return unmap_itself(args);
	}

	return parasite_trap_cmd(cmd, args);
}

/*
 * Mainally, -fstack-protector is disabled for parasite.
 * But we share some object files, compiled for CRIU with parasite.
 * Those files (like cpu.c) may be compiled with stack protector
 * support. We can't use gcc-ld provided stackprotector callback,
 * as Glibc is unmapped. Let's just try to cure application in
 * case of stack smashing in parasite.
 */
void __stack_chk_fail(void)
{
	/*
	 * Smash didn't happen in printing part, as it's not shared
	 * with CRIU, therefore compiled with -fnostack-protector.
	 */
	pr_err("Stack smash detected in parasite\n");
	fini();
}
