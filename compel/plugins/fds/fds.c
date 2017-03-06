#include <errno.h>

#include "uapi/plugins.h"
#include "uapi/plugins/std.h"
#include <compel/plugins/std/infect.h>

#define pr_err(fmt, ...)

#include "common/compiler.h"
#include "common/bug.h"

#define __sys(foo)	sys_##foo
#define __sys_err(ret)	ret

#include "common/scm.h"

int fds_send_fd(int fd)
{
	return send_fd(parasite_get_rpc_sock(), NULL, 0, fd);
}

int fds_recv_fd(void)
{
	return recv_fd(parasite_get_rpc_sock());
}
