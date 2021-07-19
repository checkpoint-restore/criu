#include <unistd.h>

#include "restorer.h"
#include "asm/restorer.h"
#include <compel/asm/fpu.h>

#include <compel/plugins/std/syscall.h>
#include "log.h"

int restore_nonsigframe_gpregs(UserPpc64RegsEntry *r)
{
#define SPRN_TFHAR  128
#define SPRN_TFIAR  129
#define SPRN_TEXASR 130

	if (r->has_tfhar) {
		asm __volatile__("ld	3, %[value]	;"
				 "mtspr	%[sprn],3	;"
				 : [value] "=m"(r->tfhar)
				 : [sprn] "i"(SPRN_TFHAR)
				 : "r3");
	}

	if (r->has_tfiar) {
		asm __volatile__("ld	3, %[value]	;"
				 "mtspr	%[sprn],3	;"
				 : [value] "=m"(r->tfiar)
				 : [sprn] "i"(SPRN_TFIAR)
				 : "r3");
	}

	if (r->has_texasr) {
		asm __volatile__("ld	3, %[value]	;"
				 "mtspr	%[sprn],3	;"
				 : [value] "=m"(r->texasr)
				 : [sprn] "i"(SPRN_TEXASR)
				 : "r3");
	}

	return 0;
}

unsigned long sys_shmat(int shmid, const void *shmaddr, int shmflg)
{
	unsigned long raddr;
	int ret;

	ret = sys_ipc(21 /*SHMAT */, shmid, /* first 		*/
		      shmflg, /* second 		*/
		      (unsigned long)&raddr, /* third 		*/
		      shmaddr, /* ptr			*/
		      0 /* fifth not used 	*/);

	if (ret)
		raddr = (unsigned long)ret;

	return raddr;
}
