#include <errno.h>

#include <compel/plugins/std.h>
#include <infect-rpc.h>

/*
 * Stubs for std compel plugin.
 */
int parasite_trap_cmd(int cmd, void *args) { return 0; }
void parasite_cleanup(void) { }

#define PARASITE_CMD_INC	PARASITE_USER_CMDS
#define PARASITE_CMD_DEC	PARASITE_USER_CMDS + 1

int parasite_daemon_cmd(int cmd, void *args)
{
	int v;

	switch (cmd) {
	case PARASITE_CMD_INC:
		v = (*(int *)args) + 1;
		break;
	case PARASITE_CMD_DEC:
		v = (*(int *)args) - 1;
		break;
	default:
		v = -1;
		break;
	}

	sys_write(1, &v, sizeof(int));
	return 0;
}
