#include "asm/types.h"
#include <compel/asm/infect-types.h>
#include "asm/sigframe.h"

int sigreturn_prep_fpu_frame(struct rt_sigframe *sigframe, struct rt_sigframe *rsigframe)
{
	return 0;
}
