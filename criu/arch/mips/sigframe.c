#include <stdlib.h>
#include <stdint.h>

#include "asm/sigframe.h"
#include "asm/types.h"

#include "flog.h"
#include "log.h"
#include <stdio.h>
int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe,
		struct rt_sigframe *rsigframe)
{
    return 0;
}
