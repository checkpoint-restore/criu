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

	return 0;
}

#ifdef CONFIG_HAS_SELINUX
static int selinux_get_label(pid_t pid, char **output)
{
	security_context_t ctx;
	char *pos;
	int i;
	int ret = -1;

	if (getpidcon_raw(pid, &ctx) < 0) {
		pr_perror("getting selinux profile failed");
		return -1;
	}

	*output = xstrdup((char *)ctx);
	if (!*output)
		goto err;

	/*
	 * Make sure it is a valid SELinux label. It should look like this:
	 *
	 *	unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
	 */
	pos = (char*)ctx;
	for (i = 0; i < 3; i++) {
		pos = strstr(pos, ":");
		if (!pos) {
			pr_err("Invalid selinux context %s\n", (char *)ctx);
			xfree(*output);
			*output = NULL;
			goto err;
		}

		*pos = 0;
		pos++;
	}

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
#endif

int run_setsockcreatecon(FdinfoEntry *e)
{
#ifdef CONFIG_HAS_SELINUX
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
#endif
	return 0;
}

int dump_xattr_security_selinux(int fd, FdinfoEntry *e)
{
#ifdef CONFIG_HAS_SELINUX
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

#endif
	return 0;
}

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
	ce->lsm_sockcreate = NULL;

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
		if (ret)
			break;
		ret = selinux_get_sockcreate_label(pid, &ce->lsm_sockcreate);
		break;
#endif
	default:
		BUG();
		ret = -1;
		break;
	}

	if (ce->lsm_profile)
		pr_info("%d has lsm profile %s\n", pid, ce->lsm_profile);
	if (ce->lsm_sockcreate)
		pr_info("%d has lsm sockcreate label %s\n", pid, ce->lsm_sockcreate);

	return ret;
}

/*
 * If running on a system with SELinux enabled the socket for the
 * communication between parasite daemon and the main
 * CRIU process needs to be correctly labeled.
 * Initially this was motivated by Podman's use case: The container
 * is usually running as something like '...:...:container_t:...:....'
 * and CRIU started from runc and Podman will run as
 * '...:...:container_runtime_t:...:...'. As the parasite will be
 * running with the same context as the container process: 'container_t'.
 * Allowing a container process to connect via socket to the outside
 * of the container ('container_runtime_t') is not desired and
 * therefore CRIU needs to label the socket with the context of
 * the container: 'container_t'.
 * So this first gets the context of the root container process
 * and tells SELinux to label the next created socket with
 * the same label as the root container process.
 * For this to work it is necessary to have the correct SELinux
 * policies installed. For Fedora based systems this is part
 * of the container-selinux package.
 */
int lsm_start_socket_labeling(void)
{
#ifdef CONFIG_HAS_SELINUX
	security_context_t ctx;
	int ret;

	/*
	 * This assumes that all processes CRIU wants to dump are labeled
	 * with the same SELinux context. If some of the child processes
	 * have different labels this will not work and needs additional
	 * SELinux policies. But the whole SELinux socket labeling relies
	 * on the correct SELinux being available.
	 */
	if (kdat.lsm != LSMTYPE__SELINUX)
		return 0;

	ret = getpidcon_raw(root_item->pid->real, &ctx);
	if (ret < 0) {
		pr_perror("Getting SELinux context for PID %d failed",
				root_item->pid->real);
		return ret;
	}

	ret = setsockcreatecon(ctx);
	freecon(ctx);
	if (ret < 0) {
		pr_perror("Setting SELinux socket context for PID %d failed",
				root_item->pid->real);
		return ret;
	}
#endif
	return 0;
}

/*
 * Once the socket has been created, reset the SELinux socket labelling
 * back to the default value of this process.
 */
int lsm_stop_socket_labeling(void)
{
#ifdef CONFIG_HAS_SELINUX
	int ret;

	if (kdat.lsm != LSMTYPE__SELINUX)
		return 0;

	ret = setsockcreatecon_raw(NULL);
	if (ret < 0) {
		pr_perror("Resetting SELinux socket context to "
				"default for PID %d failed",
				root_item->pid->real);
		return ret;
	}
#endif
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
