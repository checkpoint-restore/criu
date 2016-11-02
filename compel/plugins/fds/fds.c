#include <errno.h>

#include "uapi/plugins.h"

#include "uapi/std/syscall.h"
#include "uapi/std/string.h"
#include "uapi/plugin-fds.h"

#include "std-priv.h"
#include "log.h"

#include "common/compiler.h"
#include "common/bug.h"

#define __sys(foo)	sys_##foo
#define __memcpy	std_memcpy

#include "common/scm-code.c"

PLUGIN_REGISTER_DUMMY(fds)
