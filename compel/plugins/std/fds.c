#include <errno.h>

#include <compel/plugins/std.h>

#define pr_err(fmt, ...)

#include "common/compiler.h"
#include "common/bug.h"

#define __sys(foo)	sys_##foo
#define __sys_err(ret)	ret

#include "common/scm-code.c"
