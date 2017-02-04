#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <stdbool.h>
#include <errno.h>

#include "int.h"
#include "types.h"
#include "common/compiler.h"
#include "log.h"
#include "string.h"

#ifdef CR_NOGLIBC
# include "syscall.h"
# define __sys(foo)	sys_##foo
# define __sys_err(ret)	ret
#else
# define __sys(foo)	foo
# define __sys_err(ret)	(-errno)
#endif

#include "util-pie.h"
#include "fcntl.h"

#include "common/bug.h"

#include "common/scm-code.c"
