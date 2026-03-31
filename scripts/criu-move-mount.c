/*
 * criu-move-mount — CRIU action-script helper for adding bind mounts during restore.
 *
 * Reads mount rules from CRIU_ADD_MOUNTS env var and mounts host directories
 * into container's mount namespace during pre-resume phase.
 *
 * Usage:
 *   CRTOOLS_SCRIPT_ACTION=pre-resume
 *   CRTOOLS_INIT_PID=<container-pid>
 *   CRIU_ADD_MOUNTS="src=/host/path,dst=/container/path[,options=rbind:ro]"
 *
 * Compile: gcc -O2 -o criu-move-mount criu-move-mount.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

__attribute__((format(printf, 1, 2)))

static void logmsg(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* Recursively create directories (like mkdir -p). */
static int mkdir_p(const char *path, mode_t mode)
{
	char tmp[4096], *p;

	snprintf(tmp, sizeof(tmp), "%s", path);
	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode) && errno != EEXIST)
			return -1;
		*p = '/';
	}
	return (mkdir(tmp, mode) && errno != EEXIST) ? -1 : 0;
}

/*
 * Perform a single cross-namespace bind mount.
 *
 * The caller must be in the host mount namespace on entry.
 * On return the process is left in the container mount namespace.
 */
static int apply_mount(int host_nsfd, int container_nsfd,
		       const char *src, const char *dst,
		       int rbind, int ro)
{
	unsigned int flags;
	int treefd;

	logmsg("add-mounts: mounting %s -> %s (rbind=%d, ro=%d)\n",
	       src, dst, rbind, ro);

	/* Make sure we are in the host namespace for open_tree(). */
	if (setns(host_nsfd, CLONE_NEWNS) < 0) {
		logmsg("add-mounts: setns host: %s\n", strerror(errno));
		return -1;
	}

	flags = AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW | OPEN_TREE_CLONE;
	if (rbind)
		flags |= AT_RECURSIVE;

	treefd = syscall(__NR_open_tree, AT_FDCWD, src, flags);
	if (treefd < 0) {
		logmsg("add-mounts: open_tree(%s): %s\n", src, strerror(errno));
		return -1;
	}

	/* Switch to the container namespace. */
	if (setns(container_nsfd, CLONE_NEWNS) < 0) {
		logmsg("add-mounts: setns container: %s\n", strerror(errno));
		close(treefd);
		return -1;
	}

	if (mkdir_p(dst, 0755) < 0) {
		logmsg("add-mounts: mkdir_p(%s): %s\n", dst, strerror(errno));
		close(treefd);
		return -1;
	}

	if (syscall(__NR_move_mount, treefd, "", AT_FDCWD, dst,
		    MOVE_MOUNT_F_EMPTY_PATH) < 0) {
		logmsg("add-mounts: move_mount(%s): %s\n", dst, strerror(errno));
		close(treefd);
		return -1;
	}

	if (ro && mount(NULL, dst, NULL,
			MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) < 0) {
		logmsg("add-mounts: remount ro(%s): %s\n", dst, strerror(errno));
		close(treefd);
		return -1;
	}

	logmsg("add-mounts: OK %s -> %s\n", src, dst);
	close(treefd);
	return 0;
}

/*
 * Parse a single mount-rule string and call apply_mount().
 * Rule format: [type=bind,]src=<path>,dst=<path>[,options=rbind:rw]
 * Returns 0 on success, -1 on failure.
 */
static int parse_and_apply(int host_nsfd, int container_nsfd, const char *spec)
{
	char *buf, *saveptr, *field;
	char *src = NULL, *dst = NULL;
	int rbind = 0, ro = 0;

	buf = strdup(spec);
	if (!buf) {
		perror("strdup");
		return -1;
	}

	for (field = strtok_r(buf, ",", &saveptr); field;
	     field = strtok_r(NULL, ",", &saveptr)) {
		if (strncmp(field, "src=", 4) == 0) {
			src = field + 4;
		} else if (strncmp(field, "dst=", 4) == 0) {
			dst = field + 4;
		} else if (strncmp(field, "type=", 5) == 0) {
			/* ignored — only bind is supported */
		} else if (strncmp(field, "options=", 8) == 0) {
			char *opts = field + 8;
			char *osave, *opt;

			for (opt = strtok_r(opts, ":", &osave); opt;
			     opt = strtok_r(NULL, ":", &osave)) {
				if (strcmp(opt, "rbind") == 0)
					rbind = 1;
				else if (strcmp(opt, "ro") == 0)
					ro = 1;
			}
		}
	}

	if (!src || !*src || !dst || !*dst) {
		logmsg("add-mounts: bad spec (missing src or dst): %s\n", spec);
		free(buf);
		return -1;
	}

	int rc = apply_mount(host_nsfd, container_nsfd, src, dst, rbind, ro);

	free(buf);
	return rc;
}

/* Strip leading and trailing whitespace in-place. */
static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	if (*s) {
		char *e = s + strlen(s) - 1;
		while (e > s && (*e == ' ' || *e == '\t'))
			*e-- = '\0';
	}
	return s;
}

int main(void)
{
	const char *action, *initpid_str, *mounts_env;
	char ns_path[64];
	int host_nsfd, container_nsfd;
	char *mounts, *saveptr, *entry;
	int initpid;

	action = getenv("CRTOOLS_SCRIPT_ACTION");
	logmsg("add-mounts: action=%s\n", action ? action : "(null)");

	/*
	 * Phase filter — only run during pre-resume.
	 * Exit silently (success) for all other phases so CRIU continues
	 * the restore without error.
	 */
	if (!action || strcmp(action, "pre-resume") != 0) {
		return 0;
	}

	initpid_str = getenv("CRTOOLS_INIT_PID");
	if (!initpid_str || !*initpid_str) {
		logmsg("add-mounts: CRTOOLS_INIT_PID not set\n");
		return 1;
	}
	initpid = atoi(initpid_str);

	mounts_env = getenv("CRIU_ADD_MOUNTS");
	logmsg("add-mounts: pid=%d, CRIU_ADD_MOUNTS=%s\n",
	       initpid, mounts_env ? mounts_env : "(null)");

	if (!mounts_env || !*mounts_env) {
		logmsg("add-mounts: no rules, nothing to do\n");
		return 0;
	}

	/* Open the container's mount namespace fd. */
	snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", initpid);
	container_nsfd = open(ns_path, O_RDONLY);
	if (container_nsfd < 0) {
		logmsg("add-mounts: open(%s): %s\n", ns_path, strerror(errno));
		return 1;
	}

	/* Save the host mount namespace so we can switch back for each rule. */
	host_nsfd = open("/proc/self/ns/mnt", O_RDONLY);
	if (host_nsfd < 0) {
		logmsg("add-mounts: open(/proc/self/ns/mnt): %s\n",
		       strerror(errno));
		close(container_nsfd);
		return 1;
	}

	mounts = strdup(mounts_env);
	if (!mounts) {
		logmsg("add-mounts: strdup: %s\n", strerror(errno));
		close(container_nsfd);
		close(host_nsfd);
		return 1;
	}

	/*
	 * Individual mount failures are logged but do not abort the whole
	 * process — matching the original shell script's "|| true" behaviour.
	 * This prevents one bad rule from blocking other valid mounts and
	 * avoids failing the entire CRIU restore.
	 */
	for (entry = strtok_r(mounts, ";", &saveptr); entry;
	     entry = strtok_r(NULL, ";", &saveptr)) {
		entry = trim(entry);
		if (!*entry)
			continue;
		parse_and_apply(host_nsfd, container_nsfd, entry);
	}

	free(mounts);
	close(container_nsfd);
	close(host_nsfd);
	return 0;
}


