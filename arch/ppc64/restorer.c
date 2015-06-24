#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include "asm/fpu.h"

#include "syscall.h"
#include "log.h"

int restore_nonsigframe_gpregs(UserPpc64RegsEntry *r)
{
	return 0;
}

unsigned long sys_shmat(int shmid, const void *shmaddr, int shmflg)
{
	unsigned long raddr;
	int ret;

	ret = sys_ipc(21 /*SHMAT */,
		      shmid,		 	/* first 		*/
		      shmflg,		 	/* second 		*/
		      (unsigned long)&raddr,	/* third 		*/
		      shmaddr,			/* ptr			*/
		      0 			/* fifth not used 	*/);

	if (ret)
		raddr = (unsigned long) ret;

	return raddr;
}
