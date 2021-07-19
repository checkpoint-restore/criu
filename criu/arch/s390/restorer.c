#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>

#include <compel/plugins/std/syscall.h>
#include "log.h"

/*
 * All registers are restored by sigreturn - nothing to do here
 */
int restore_nonsigframe_gpregs(UserS390RegsEntry *r)
{
	return 0;
}

/*
 * Call underlying ipc system call for shmat
 */
unsigned long sys_shmat(int shmid, const void *shmaddr, int shmflg)
{
	unsigned long raddr;
	int ret;

	ret = sys_ipc(21 /*SHMAT */, shmid, /* first		*/
		      shmflg, /* second		*/
		      (unsigned long)&raddr, /* third		*/
		      shmaddr, /* ptr			*/
		      0 /* fifth not used	*/);

	if (ret)
		raddr = (unsigned long)ret;

	return raddr;
}
