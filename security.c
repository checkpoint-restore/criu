#include <unistd.h>
#include "crtools.h"
#include "proc_parse.h"
#include "log.h"

#include "protobuf/creds.pb-c.h"

/*
 * UID and GID of user requesting for C/R
 */
static unsigned int cr_uid, cr_gid;

/*
 * Setup what user is requesting for dump (via rpc or using 
 * suid bit on crtools). Later we would deny to dump/restore 
 * a task, to which the original user doesn't have the direct 
 * access to. (Or implement some trickier security policy).
 */

void restrict_uid(unsigned int uid, unsigned int gid)
{
	pr_info("Restrict C/R with %u:%u uid\n", uid, gid);
	cr_uid = uid;
	cr_gid = gid;
}

static bool check_ids(unsigned int crid, unsigned int rid, unsigned int eid, unsigned int sid)
{
	if (crid == 0)
		return true;
	if (crid == rid && crid == eid && crid == sid)
		return true;

	pr_err("UID/GID mismatch %u != (%u,%u,%u)\n", crid, rid, eid, sid);
	return false;
}

static bool check_caps(uint32_t *inh, uint32_t *eff, uint32_t *prm)
{
	int i;

	/*
	 * Impose the most strict requirements for now.
	 * "Real" root user can use any caps, other users may
	 * use none. Later we will implement more sophisticated
	 * security model.
	 */

	if (cr_uid == 0 && cr_gid == 0)
		return true;

	for (i = 0; i < CR_CAP_SIZE; i++) {
		if (inh[i] != 0 || eff[i] != 0 || prm[i] != 0) {
			pr_err("CAPs not allowed for non-root user\n");
			return false;
		}
	}

	return true;
}

bool may_dump(struct proc_status_creds *creds)
{
	return check_ids(cr_uid, creds->uids[0], creds->uids[1], creds->uids[2]) &&
		check_ids(cr_gid, creds->gids[0], creds->gids[1], creds->gids[2]) &&
		check_caps(creds->cap_inh, creds->cap_eff, creds->cap_prm);
}

bool may_restore(CredsEntry *creds)
{
	return check_ids(cr_uid, creds->uid, creds->euid, creds->suid) &&
		check_ids(cr_gid, creds->gid, creds->egid, creds->sgid) &&
		check_caps(creds->cap_inh, creds->cap_eff, creds->cap_prm);
}
