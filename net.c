#include <unistd.h>
#include "syscall-types.h"
#include "namespaces.h"
#include "net.h"

int dump_net_ns(int pid, struct cr_fdset *fds)
{
	int ret;

	ret = switch_ns(pid, CLONE_NEWNET, "net", NULL);

	return ret;
}

int prepare_net_ns(int pid)
{
	return -1;
}
