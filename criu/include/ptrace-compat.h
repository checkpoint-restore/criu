#ifndef __CR_PTRACE_ARCH_H__
#define __CR_PTRACE_ARCH_H__

#include <linux/types.h>
#include <sys/ptrace.h>
#include "config.h"

#ifndef CONFIG_HAS_PTRACE_PEEKSIGINFO
struct ptrace_peeksiginfo_args {
        __u64 off;	/* from which siginfo to start */
        __u32 flags;
        __u32 nr;	/* how may siginfos to take */
};
#endif

#endif /* __CR_PTRACE_ARCH_H__ */
