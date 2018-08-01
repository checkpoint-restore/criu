#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "common/config.h"
#include "kerndat.h"
#include "pstree.h"
#include "util.h"
#include "cr_options.h"
#include "lsm.h"

#include "protobuf.h"
#include "images/inventory.pb-c.h"
#include "images/creds.pb-c.h"

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

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
	if (strcmp(*profile_name, "unconfined") == 0) {
		free(*profile_name);
		*profile_name = NULL;
	}

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
	if (access(AA_SECURITYFS_PATH, F_OK) == 0) {
		kdat.lsm = LSMTYPE__APPARMOR;
		return;
	}

#ifdef CONFIG_HAS_SELINUX
	/*
	 * This seems to be the canonical place to mount this fs if it is
	 * enabled, although we may (?) want to check /selinux for posterity as
	 * well.
	 */
	if (access("/sys/fs/selinux", F_OK) == 0) {
		kdat.lsm = LSMTYPE__SELINUX;
		return;
	}
#endif

	kdat.lsm = LSMTYPE__NO_LSM;
}

Lsmtype host_lsm_type(void)
{
	return kdat.lsm;
}

int collect_lsm_profile(pid_t pid, CredsEntry *ce)
{
	int ret;

	ce->lsm_profile = NULL;

	switch (kdat.lsm) {
	case LSMTYPE__NO_LSM:
		ret = 0;
		break;
	case LSMTYPE__APPARMOR:
		ret = apparmor_get_label(pid, &ce->lsm_profile);
		break;
#ifdef CONFIG_HAS_SELINUX
	case LSMTYPE__SELINUX:
		ret = selinux_get_label(pid, &ce->lsm_profile);
		break;
#endif
	default:
		BUG();
		ret = -1;
		break;
	}

	if (ce->lsm_profile)
		pr_info("%d has lsm profile %s\n", pid, ce->lsm_profile);

	return ret;
}

// in inventory.c
extern Lsmtype image_lsm;

int validate_lsm(char *lsm_profile)
{
	if (image_lsm == LSMTYPE__NO_LSM || image_lsm == kdat.lsm)
		return 0;

	/*
	 * This is really only a problem if the processes have actually
	 * specified an LSM profile. If not, we won't restore anything anyway,
	 * so it's fine.
	 */
	if (lsm_profile) {
		pr_err("mismatched lsm types and lsm profile specified\n");
		return -1;
	}

	return 0;
}

int render_lsm_profile(char *profile, char **val)
{
	*val = NULL;

	switch (kdat.lsm) {
	case LSMTYPE__APPARMOR:
		if (strcmp(profile, "unconfined") != 0 && asprintf(val, "changeprofile %s", profile) < 0) {
			pr_err("allocating lsm profile failed\n");
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
		pr_err("can't render profile %s for lsmtype %d\n", profile, LSMTYPE__NO_LSM);
		return -1;
	}

	return 0;
}

int lsm_check_opts(void)
{
	char *aux;

	if (!opts.lsm_supplied)
		return 0;

	aux = strchr(opts.lsm_profile, ':');
	if (aux == NULL) {
		pr_err("invalid argument %s for --lsm-profile\n", opts.lsm_profile);
		return -1;
	}

	*aux = '\0';
	aux++;

	if (strcmp(opts.lsm_profile, "apparmor") == 0) {
		if (kdat.lsm != LSMTYPE__APPARMOR) {
			pr_err("apparmor LSM specified but apparmor not supported by kernel\n");
			return -1;
		}

		SET_CHAR_OPTS(lsm_profile, aux);
	} else if (strcmp(opts.lsm_profile, "selinux") == 0) {
		if (kdat.lsm != LSMTYPE__SELINUX) {
			pr_err("selinux LSM specified but selinux not supported by kernel\n");
			return -1;
		}

		SET_CHAR_OPTS(lsm_profile, aux);
	} else if (strcmp(opts.lsm_profile, "none") == 0) {
		xfree(opts.lsm_profile);
		opts.lsm_profile = NULL;
	} else {
		pr_err("unknown lsm %s\n", opts.lsm_profile);
		return -1;
	}

	return 0;
}
