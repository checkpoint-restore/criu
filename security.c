#include <unistd.h>
#include "crtools.h"
#include "log.h"

static unsigned int dumper_uid = 0;

/*
 * Setup what user is requesting for dump (via rpc or using 
 * suid bit on crtools). Later we would deny to dump/restore 
 * a task, to which the original user doesn't have the direct 
 * access to. (Or implement some trickier security policy).
 */

void restrict_uid(unsigned int uid)
{
	pr_info("Restrict C/R with %u uid\n", uid);
	dumper_uid = uid;
}

bool may_dump_uid(unsigned int uid)
{
	if (dumper_uid == 0)
		return true;
	if (dumper_uid == uid)
		return true;

	pr_err("UID (%u) != dumper's UID(%u)\n", uid, dumper_uid);
	return false;
}
