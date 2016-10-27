#include "uapi/plugins.h"

#include "uapi/std/syscall.h"
#include "uapi/std/string.h"
#include "uapi/plugin-fds.h"

#include "std-priv.h"

#include "common/compiler.h"

#define __sys(foo)	sys_##foo
#define __std(foo)	std_##foo

#include "../../src/shared/fds.c"

int fds_send(int *fds, int nr_fds)
{
	return fds_send_via(std_ctl_sock(), fds, nr_fds);
}

int fds_recv(int *fds, int nr_fds)
{
	return fds_recv_via(std_ctl_sock(), fds, nr_fds);
}

PLUGIN_REGISTER_DUMMY(fds)
