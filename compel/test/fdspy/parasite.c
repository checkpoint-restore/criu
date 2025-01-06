#include <errno.h>

#include <compel/infect-rpc.h>
#include <compel/plugins/plugin-fds.h>

/*
 * Stubs for std compel plugin.
 */
int compel_main(void *arg_p, unsigned int arg_s)
{
	return 0;
}
int parasite_trap_cmd(int cmd, void *args)
{
	return 0;
}
void parasite_cleanup(void)
{
}

#define PARASITE_CMD_GETFD PARASITE_USER_CMDS

int parasite_daemon_cmd(int cmd, void *args)
{
	if (cmd == PARASITE_CMD_GETFD)
		return (fds_send_fd(2) < 0);
	return 0;
}
