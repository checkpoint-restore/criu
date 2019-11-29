#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include "bitops.h"
#include "asm/types.h"
#include "asm/cpu.h"
#include <compel/asm/fpu.h>
#include <compel/cpu.h>

#include "common/compiler.h"

#include "cr_options.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "cpu.h"

#include "protobuf.h"
#include "images/cpuinfo.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "cpu: "

//static compel_cpuinfo_t rt_cpu_info;

int cpu_init(void)
{
    pr_info("%s:%d WARN:no implemented!!\n",__FILE__,__LINE__);
    return 0;
}

int cpu_dump_cpuinfo(void)
{
    pr_info("ERROR''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

int cpu_validate_cpuinfo(void)
{
    pr_info("WARN''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}

int cpuinfo_dump(void)
{
    pr_info("WARN''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
	if (cpu_init())
		return -1;
	if (cpu_dump_cpuinfo())
		return -1;
	return 0;
}

int cpuinfo_check(void)
{
    pr_info("WARN''''''''%s:%d:no implemented!!\n",__FILE__,__LINE__);
	return 0;
}
