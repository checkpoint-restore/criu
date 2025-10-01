#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "common/config.h"
#include "kerndat.h"
#include "pstree.h"
#include "util.h"
#include "cr_options.h"
#include "lsm.h"
#include "fdstore.h"
#include "apparmor.h"

#include "protobuf.h"
#include "images/inventory.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/fdinfo.pb-c.h"

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#endif

static int apparmor_get_label(pid_t pid, char **profile_name)
{
	FILE *f;
	char *space;

	f = fopen_proc(pid, "attr/apparmor/current");
	if (!f)
		f = fopen_proc(pid, "attr/current");
	if (!f)
		return -1;

	if (fscanf(f, "%ms", profile_name) != 1) {
		pr_perror("err scanfing");
		fclose(f);
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

	if (*profile_name && collect_aa_namespace(*profile_name) < 0) {
		free(*profile_name);
		*profile_name = NULL;
		pr_err("failed to collect AA namespace\n");
		return -1;
	}

	return 0;
}

#ifdef CONFIG_HAS_SELINUX
static int verify_selinux_label(char *ctx)
{
	char *pos;
	int i;

	/*
	 * There are SELinux setups where SELinux seems to be enabled,
	 * but the returned labels are not really valid. See also
	 * https://github.com/torvalds/linux/blob/master/security/selinux/include/initial_sid_to_string.h
	 *
	 * CRIU tells the user that such labels are invalid
	 * and CRIU expects a SELinux label to contain three ':'.
	 *
	 * A label should look like this:
	 *
	 *      unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
	 */
	pos = (char *)ctx;
	for (i = 0; i < 3; i++) {
		pos = strstr(pos, ":");
		if (!pos)
			return -1;
		pos++;
	}

	return 0;
}

static int selinux_get_label(pid_t pid, char **output)
{
	char *ctx;
	int ret = -1;

	if (getpidcon_raw(pid, &ctx) < 0) {
		pr_perror("getting selinux profile failed");
		return -1;
	}

	if (verify_selinux_label(ctx)) {
		pr_err("Invalid selinux context %s\n", (char *)ctx);
		goto err;
	}

	*output = xstrdup((char *)ctx);
	if (!*output)
		goto err;

	ret = 0;
err:
	freecon(ctx);
	return ret;
}

/*
 * selinux_get_sockcreate_label reads /proc/PID/attr/sockcreate
 * to see if the PID has a special label specified for sockets.
 * Most of the time this will be empty and the process will use
 * the process context also for sockets.
 */
static int selinux_get_sockcreate_label(pid_t pid, char **output)
{
	FILE *f;
	int ret;

	f = fopen_proc(pid, "attr/sockcreate");
	if (!f)
		return -1;

	ret = fscanf(f, "%ms", output);
	if (ret == -1 && errno != 0) {
		pr_perror("Unable to parse /proc/%d/attr/sockcreate", pid);
		/*
		 * Only if the error indicator is set it is a real error.
		 * -1 could also be EOF, which would mean that sockcreate
		 * was just empty, which is the most common case.
		 */
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

int reset_setsockcreatecon(void)
{
	/* Currently this only works for SELinux. */
	if (kdat.lsm != LSMTYPE__SELINUX)
		return 0;

	if (setsockcreatecon_raw(NULL)) {
		pr_perror("Unable to reset socket SELinux context");
		return -1;
	}
	return 0;
}

int run_setsockcreatecon(FdinfoEntry *e)
{
	char *ctx = NULL;

	/* Currently this only works for SELinux. */
	if (kdat.lsm != LSMTYPE__SELINUX)
		return 0;

	ctx = e->xattr_security_selinux;
	/* Writing to the FD using fsetxattr() did not work for some reason. */
	if (setsockcreatecon_raw(ctx)) {
		pr_perror("Unable to set the %s socket SELinux context", ctx);
		return -1;
	}
	return 0;
}

int dump_xattr_security_selinux(int fd, FdinfoEntry *e)
{
	char *ctx = NULL;
	int len;
	int ret;

	/* Currently this only works for SELinux. */
	if (kdat.lsm != LSMTYPE__SELINUX)
		return 0;

	/* Get the size of the xattr. */
	len = fgetxattr(fd, "security.selinux", ctx, 0);
	if (len == -1) {
		pr_err("Reading xattr security.selinux from FD %d failed\n", fd);
		return -1;
	}

	ctx = xmalloc(len);
	if (!ctx) {
		pr_err("xmalloc to read xattr for FD %d failed\n", fd);
		return -1;
	}

	ret = fgetxattr(fd, "security.selinux", ctx, len);
	if (len != ret) {
		pr_err("Reading xattr %s to FD %d failed\n", ctx, fd);
		return -1;
	}

	e->xattr_security_selinux = ctx;

	return 0;
}

#endif

void kerndat_lsm(void)
{
	if (access(AA_SECURITYFS_PATH, F_OK) == 0) {
		kdat.lsm = LSMTYPE__APPARMOR;
		kdat.apparmor_ns_dumping_enabled = check_aa_ns_dumping();
		return;
	}

#ifdef CONFIG_HAS_SELINUX
	if (is_selinux_enabled()) {
		char *ctx;

		/*
		 * CRIU used to only check if /sys/fs/selinux is mounted, but that does not
		 * seem to be enough for CRIU's use case. CRIU actually needs to look if
		 * a valid label is returned.
		 */
		if (getpidcon_raw(getpid(), &ctx) < 0)
			goto no_lsm;

		if (verify_selinux_label(ctx)) {
			freecon(ctx);
			goto no_lsm;
		}

		kdat.lsm = LSMTYPE__SELINUX;
		freecon(ctx);
		return;
	}
no_lsm:
#endif

	kdat.lsm = LSMTYPE__NO_LSM;
}

Lsmtype host_lsm_type(void)
{
	return kdat.lsm;
}

static int collect_lsm_profile(pid_t pid, struct thread_lsm *lsm)
{
	int ret;

	switch (kdat.lsm) {
	case LSMTYPE__NO_LSM:
		ret = 0;
		break;
	case LSMTYPE__APPARMOR:
		ret = apparmor_get_label(pid, &lsm->profile);
		break;
#ifdef CONFIG_HAS_SELINUX
	case LSMTYPE__SELINUX:
		ret = selinux_get_label(pid, &lsm->profile);
		if (ret)
			break;
		ret = selinux_get_sockcreate_label(pid, &lsm->sockcreate);
		break;
#endif
	default:
		BUG();
		ret = -1;
		break;
	}

	if (lsm->profile)
		pr_info("%d has lsm profile %s\n", pid, lsm->profile);
	if (lsm->sockcreate)
		pr_info("%d has lsm sockcreate label %s\n", pid, lsm->sockcreate);

	return ret;
}

int collect_and_suspend_lsm(void)
{
	struct pstree_item *item;

	for_each_pstree_item(item) {
		struct thread_lsm **thread_lsms;
		int i;

		thread_lsms = xzalloc((item->nr_threads + 1) * sizeof(thread_lsms));
		if (!thread_lsms)
			return -1;
		dmpi(item)->thread_lsms = thread_lsms;

		for (i = 0; i < item->nr_threads; i++) {
			thread_lsms[i] = xzalloc(sizeof(**thread_lsms));
			if (!thread_lsms[i])
				return -1;

			if (collect_lsm_profile(item->threads[i].real, thread_lsms[i]) < 0)
				return -1;
		}
	}

	/* now, suspend the LSM; this is where code that implements something
	 * like PTRACE_O_SUSPEND_LSM should live. */
	switch (kdat.lsm) {
	case LSMTYPE__APPARMOR:
		if (suspend_aa() < 0)
			return -1;
		break;
	case LSMTYPE__SELINUX:
		break;
	case LSMTYPE__NO_LSM:
		break;
	default:
		pr_debug("don't know how to suspend LSM %d\n", kdat.lsm);
	}

	return 0;
}

int unsuspend_lsm(void)
{
	if (kdat.lsm == LSMTYPE__APPARMOR && unsuspend_aa())
		return -1;

	return 0;
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
		return render_aa_profile(val, profile);
	case LSMTYPE__SELINUX:
		if (asprintf(val, "%s", opts.lsm_supplied ? opts.lsm_profile : profile) < 0) {
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
