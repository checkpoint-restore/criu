#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "crtools.h"
#include "proc_parse.h"
#include "log.h"
#include "xmalloc.h"
#include "bug.h"

#include "protobuf/creds.pb-c.h"

/*
 * UID, GID and groups of user requesting for C/R
 */
static unsigned int cr_uid, cr_gid;
static unsigned int cr_ngroups, *cr_groups;

/*
 * Setup what user is requesting for dump (via rpc or using
 * suid bit on crtools). Later we would deny to dump/restore
 * a task, to which the original user doesn't have the direct
 * access to. (Or implement some trickier security policy).
 */

int restrict_uid(unsigned int uid, unsigned int gid)
{
	struct passwd *pwd;
	unsigned int buf[NGROUPS_MAX];
	int nbuf;

	pr_info("Restrict C/R with %u:%u uid:gid\n", uid, gid);
	cr_uid = uid;
	cr_gid = gid;

	/* skip obtaining additional groups for root, as they don't matter */
	if (cr_uid == 0 && cr_gid == 0)
		return 0;

	pwd = getpwuid(uid);
	if (!pwd) {
		pr_perror("Can't get password file entry");
		return -1;
	}

	nbuf = NGROUPS_MAX;
	if (getgrouplist(pwd->pw_name, pwd->pw_gid, buf, &nbuf) < 0) {
		pr_perror("Can't get group list");
		return -1;
	}

	cr_ngroups = nbuf;
	cr_groups = xmalloc(cr_ngroups*sizeof(*cr_groups));
	if (!cr_groups)
		return -1;

	memcpy(cr_groups, buf, cr_ngroups*sizeof(*cr_groups));

	return 0;
}

static bool check_uids(unsigned int rid, unsigned int eid, unsigned int sid)
{
	if (cr_uid == 0)
		return true;
	if (cr_uid == rid && cr_uid == eid && cr_uid == sid)
		return true;

	pr_err("UID mismatch %u != (%u,%u,%u)\n", cr_uid, rid, eid, sid);
	return false;
}

static bool contains(unsigned int *crgids, unsigned int crgids_num, unsigned int gid)
{
	int i;

	for (i = 0; i < crgids_num; ++i) {
		if (crgids[i] == gid)
			return true;
	}

	return false;
}

static bool check_gids(unsigned int rid, unsigned int eid, unsigned int sid)
{
	if (cr_gid == 0)
		return true;

	if ((contains(cr_groups, cr_ngroups, rid) || cr_gid == rid) &&
	    (contains(cr_groups, cr_ngroups, eid) || cr_gid == eid) &&
	    (contains(cr_groups, cr_ngroups, sid) || cr_gid == sid))
		return true;

	pr_err("GID mismatch. User is absent in (%u,%u,%u)\n", rid, eid, sid);
	return false;
}

/*
 * There is no need to check groups on dump, because if uids and gids match
 * then groups will match too. Btw, getting groups on dump is problematic.
 * We can't parse proc, as it contains only first 32 groups. And we can't use
 * getgrouplist, as it reads /etc/group which depends on the namespace.
 *
 * On restore we're getting groups from imgs and can check if user didn't add
 * wrong groups by modifying images.
 */
static bool check_groups(unsigned int *groups, unsigned int ngroups)
{
	int i;

	if (cr_gid == 0)
		return true;

	for (i = 0; i < ngroups; ++i) {
		if (!contains(cr_groups, cr_ngroups, groups[i])) {
			pr_err("GID mismatch. User is absent in %u group\n",
								groups[i]);
			return false;
		}
	}

	return true;
}

static bool check_caps(u32 *inh, u32 *eff, u32 *prm)
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

bool cr_user_is_root()
{
	return cr_uid == 0 && cr_gid == 0;
}

bool may_dump(struct proc_status_creds *creds)
{
	return check_uids(creds->uids[0], creds->uids[1], creds->uids[2]) &&
		check_gids(creds->gids[0], creds->gids[1], creds->gids[2]) &&
		check_caps(creds->cap_inh, creds->cap_eff, creds->cap_prm);
}

bool may_restore(CredsEntry *creds)
{
	return check_uids(creds->uid, creds->euid, creds->suid) &&
		check_gids(creds->gid, creds->egid, creds->sgid) &&
		check_groups(creds->groups, creds->n_groups) &&
		check_caps(creds->cap_inh, creds->cap_eff, creds->cap_prm);
}

int cr_fchown(int fd)
{
	if (cr_user_is_root())
		return 0;

	if (fchown(fd, cr_uid, cr_gid)) {
		pr_perror("Can't chown to (%u,%u)", cr_uid, cr_gid);
		return -1;
	}

	return 0;
}
