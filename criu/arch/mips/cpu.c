#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "asm/cpu.h"
#include "asm/types.h"
#include "bitops.h"
#include <compel/asm/fpu.h>
#include <compel/cpu.h>

#include "common/compiler.h"
#include "cpu.h"
#include "cr_options.h"
#include "image.h"
#include "images/cpuinfo.pb-c.h"
#include "log.h"
#include "protobuf.h"
#include "util.h"

#undef LOG_PREFIX
#define LOG_PREFIX "cpu: "

int cpu_init(void)
{
	return 0;
}

int cpu_dump_cpuinfo(void)
{
	return 0;
}

int cpu_validate_cpuinfo(void)
{
	return 0;
}

int cpuinfo_dump(void)
{
	if (cpu_init())
		return -1;
	if (cpu_dump_cpuinfo())
		return -1;
	return 0;
}

int cpuinfo_check(void)
{
	return 0;
}
