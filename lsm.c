#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"
#include "pstree.h"
#include "util.h"

#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"
#include "protobuf/creds.pb-c.h"

#undef CONFIG_HAS_SELINUX

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

static Lsmtype	lsmtype;
static int	(*get_label)(pid_t, char **) = NULL;
static char	*name = NULL;

static int apparmor_get_label(pid_t pid, char **profile_name)
{
	FILE *f;
	char *space;

	f = fopen_proc(pid, "attr/current");
	if (!f)
		return -1;

	if (fscanf(f, "%ms", profile_name) != 1) {
		fclose(f);
		pr_perror("err scanfing");
		return -1;
	}

	fclose(f);

	/*
	 * A profile name can be followed by an enforcement mode, e.g.
	 *	lxc-default-with-nesting (enforced)
	 * but the profile name is just the part before the space.
	 */
	space = strstr(*profile_name, " ");
	if (space)
		*space = 0;

	/*
	 * An "unconfined" value means there is no profile, so we don't need to
	 * worry about trying to restore one.
	 */
	if (strcmp(*profile_name, "unconfined") == 0)
		*profile_name = NULL;

	return 0;
}

#ifdef CONFIG_HAS_SELINUX
static int selinux_get_label(pid_t pid, char **output)
{
	security_context_t ctx;
	char *pos, *last;
	int i;

	if (getpidcon_raw(pid, &ctx) < 0) {
		pr_perror("getting selinux profile failed");
		return -1;
	}

	*output = NULL;

	/*
	 * Since SELinux attributes can be finer grained than at the task
	 * level, and we currently don't try to dump any of these other bits,
	 * let's only allow unconfined profiles, which look something like:
	 *
	 *	unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
	 */
	pos = (char*)ctx;
	for (i = 0; i < 3; i++) {
		last = pos;
		pos = strstr(pos, ":");
		if (!pos) {
			pr_err("Invalid selinux context %s\n", (char *)ctx);
			freecon(ctx);
			return -1;
		}

		*pos = 0;
		if (!strstartswith(last, "unconfined_")) {
			pr_err("Non unconfined selinux contexts not supported %s\n", last);
			freecon(ctx);
			return -1;
		}

		pos++;
	}
	freecon(ctx);

	return 0;
}
#endif

void kerndat_lsm(void)
{
	if (access("/sys/kernel/security/apparmor", F_OK) == 0) {
		get_label = apparmor_get_label;
		lsmtype = LSMTYPE__APPARMOR;
		name = "apparmor";
		return;
	}

#ifdef CONFIG_HAS_SELINUX
	/*
	 * This seems to be the canonical place to mount this fs if it is
	 * enabled, although we may (?) want to check /selinux for posterity as
	 * well.
	 */
	if (access("/sys/fs/selinux", F_OK) == 0) {
		get_label = selinux_get_label;
		lsmtype = LSMTYPE__SELINUX;
		name = "selinux";
		return;
	}
#endif

	get_label = NULL;
	lsmtype = LSMTYPE__NO_LSM;
	name = "none";
}

Lsmtype host_lsm_type(void)
{
	return lsmtype;
}

int collect_lsm_profile(pid_t pid, CredsEntry *ce)
{
	ce->lsm_profile = NULL;

	if (lsmtype == LSMTYPE__NO_LSM)
		return 0;

	if (get_label(pid, &ce->lsm_profile) < 0)
		return -1;

	if (ce->lsm_profile)
		pr_info("%d has lsm profile %s\n", pid, ce->lsm_profile);

	return 0;
}

// in inventory.c
extern Lsmtype image_lsm;

int validate_lsm(CredsEntry *ce)
{
	if (image_lsm == LSMTYPE__NO_LSM || image_lsm == lsmtype)
		return 0;

	/*
	 * This is really only a problem if the processes have actually
	 * specified an LSM profile. If not, we won't restore anything anyway,
	 * so it's fine.
	 */
	if (ce->lsm_profile) {
		pr_err("mismatched lsm types and lsm profile specified\n");
		return -1;
	}

	return 0;
}

int render_lsm_profile(char *profile, char **val)
{
	*val = NULL;

	switch (lsmtype) {
	case LSMTYPE__APPARMOR:
		if (strcmp(profile, "unconfined") != 0 && asprintf(val, "changeprofile %s", profile) < 0) {
			*val = NULL;
			return -1;
		}
		break;
	case LSMTYPE__SELINUX:
		if (asprintf(val, "%s", profile) < 0) {
			*val = NULL;
			return -1;
		}
		break;
	default:
		return -1;
	}

	return 0;
}
