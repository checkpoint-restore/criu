#ifndef __CR_PTRACE_H__
#define __CR_PTRACE_H__

#include <compel/ptrace.h>
#include <linux/types.h>
#include "common/config.h"

#ifndef CONFIG_HAS_PTRACE_PEEKSIGINFO
struct ptrace_peeksiginfo_args {
        __u64 off;	/* from which siginfo to start */
        __u32 flags;
        __u32 nr;	/* how may siginfos to take */
};
#endif

#endif /* __CR_PTRACE_H__ */
