/*
 * LUO (Live Update Unified Operation) session management implementation.
 *
 * This module provides the core functionality for managing LUO sessions,
 * which allow file descriptors to be preserved across kexec reboots.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "luo.h"
#include "cr_options.h"
#include "log.h"
#include "servicefd.h"
#include "util.h"

#ifdef CONFIG_HAS_LIVEUPDATE
/* Include the liveupdate header from the kernel source */
#include <linux/liveupdate.h>

/* Global LUO session state */
static int luo_dev_fd = -1;
static int luo_session_fd = -1;

/* Token generation counter */
static uint64_t luo_token_counter;

/* List of FD mappings for restore */
static LIST_HEAD(luo_fd_mappings);

/*
 * Generate a unique token based on path hash + counter.
 * This ensures each preserved memfd gets a unique token.
 */
static uint64_t luo_generate_token(const char *path)
{
	uint64_t token;
	uint64_t hash = 0;
	const unsigned char *p;
	size_t len;

	/* Simple hash based on path string */
	for (p = (const unsigned char *)path, len = 0; *p; p++, len++)
		hash = hash * 33 + *p;

	/* Combine hash with counter for uniqueness */
	token = hash ^ (luo_token_counter++ << 48);

	pr_debug("LUO: Generated token 0x%016llx for path '%s'\n",
		 (unsigned long long)token, path);

	return token;
}

static int open_luo_device(void)
{
	if (luo_dev_fd >= 0)
		return 0;

	luo_dev_fd = open("/dev/liveupdate", O_RDWR);
	if (luo_dev_fd < 0) {
		pr_perror("Failed to open /dev/liveupdate");
		return -errno;
	}

	return 0;
}

static void close_luo_device(void)
{
	if (luo_dev_fd >= 0) {
		close(luo_dev_fd);
		luo_dev_fd = -1;
	}
}

int luo_init_session(const char *session_name)
{
	int ret;
	struct liveupdate_ioctl_create_session create_req = {
		.size = sizeof(create_req),
		.fd = -1,
	};

	if (!opts.images_in_memfd) {
		pr_debug("LUO: init_session skipped (images_in_memfd=%d)\n",
			 opts.images_in_memfd);
		return 0;
	}

	ret = open_luo_device();
	if (ret < 0)
		return ret;

	strncpy((char *)create_req.name, session_name, sizeof(create_req.name) - 1);
	create_req.name[sizeof(create_req.name) - 1] = '\0';

	ret = ioctl(luo_dev_fd, LIVEUPDATE_IOCTL_CREATE_SESSION, &create_req);
	if (ret < 0) {
		pr_perror("LUO [DUMP]: Failed to create LUO session '%s'", session_name);
		close_luo_device();
		return -errno;
	}

	luo_session_fd = create_req.fd;

	/* Register as service fd so it won't be closed by close_old_fds() */
	if (install_service_fd(LUO_SESSION_FD_OFF, luo_session_fd) < 0) {
		pr_err("Can't install luo session fd as service fd\n");
		close(luo_session_fd);
		luo_session_fd = -1;
		close_luo_device();
		return -1;
	}

	close_luo_device();
	pr_info("LUO [DUMP]: CREATE SESSION: name='%s' session_fd=%d\n",
		session_name, luo_session_fd);
	return 0;
}

int luo_preserve_fd(int fd, uint64_t *token, const char *path)
{
	int ret;
	struct luo_fd_mapping *mapping;
	uint64_t generated_token;
	struct liveupdate_session_preserve_fd preserve_req = {
		.size = sizeof(preserve_req),
		.fd = fd,
		.token = 0,
	};

	if (!opts.images_in_memfd || luo_session_fd < 0) {
		pr_debug("LUO: preserve_fd skipped (images_in_memfd=%d, session_fd=%d)\n",
			 opts.images_in_memfd, luo_session_fd);
		return 0;
	}

	/* Generate unique token for this path */
	generated_token = luo_generate_token(path);
	preserve_req.token = generated_token;

	ret = ioctl(luo_session_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &preserve_req);
	if (ret < 0) {
		pr_perror("LUO [DUMP]: Failed to preserve FD %d with LUO (token=0x%016llx)",
			  fd, (unsigned long long)generated_token);
		return -errno;
	}

	*token = generated_token;

	pr_info("LUO [DUMP]: PRESERVE: path='%s' token=0x%016llx fd=%d\n",
		path, (unsigned long long)*token, fd);

	/* Track mapping for restore */
	mapping = xmalloc(sizeof(*mapping));
	if (!mapping)
		return -ENOMEM;

	mapping->path = xstrdup(path);
	if (!mapping->path) {
		xfree(mapping);
		return -ENOMEM;
	}

	mapping->token = *token;
	list_add(&mapping->list, &luo_fd_mappings);

	return 0;
}

int luo_retrieve_fd_by_path(const char *path, int *fd)
{
	struct luo_fd_mapping *mapping;

	pr_debug("LUO [RESTORE]: Looking up path '%s'\n", path);

	if (!opts.images_in_memfd) {
		pr_debug("LUO: retrieve_fd_by_path skipped (images_in_memfd=%d)\n",
			 opts.images_in_memfd);
		return -ENOENT;
	}

	/* Look for the matching path */
	list_for_each_entry(mapping, &luo_fd_mappings, list) {
		if (strcmp(mapping->path, path) == 0) {
			pr_info("LUO [RESTORE]: LOOKUP PATH: path='%s' -> token=0x%016llx\n",
				path, (unsigned long long)mapping->token);
			return luo_retrieve_fd(mapping->token, fd);
		}
	}

	pr_warn("LUO [RESTORE]: PATH NOT FOUND: path='%s'\n", path);
	return -ENOENT;
}

int luo_retrieve_session(const char *session_name)
{
	int ret;
	struct liveupdate_ioctl_retrieve_session retrieve_req = {
		.size = sizeof(retrieve_req),
		.fd = -1,
	};

	if (!opts.images_in_memfd) {
		pr_debug("LUO: retrieve_session skipped (images_in_memfd=%d)\n",
			 opts.images_in_memfd);
		return 0;
	}

	pr_info("LUO [RESTORE]: Retrieving LUO session: %s\n", session_name);

	ret = open_luo_device();
	if (ret < 0)
		return ret;

	strncpy((char *)retrieve_req.name, session_name, sizeof(retrieve_req.name) - 1);
	retrieve_req.name[sizeof(retrieve_req.name) - 1] = '\0';

	ret = ioctl(luo_dev_fd, LIVEUPDATE_IOCTL_RETRIEVE_SESSION, &retrieve_req);
	if (ret < 0) {
		int saved_errno = errno;

		pr_err("LUO [RESTORE]: ioctl RETRIEVE_SESSION failed: errno=%d (%s)\n",
			saved_errno, strerror(saved_errno));
		return -saved_errno;
	}

	luo_session_fd = retrieve_req.fd;

	/* Register as service fd */
	if (install_service_fd(LUO_SESSION_FD_OFF, luo_session_fd) < 0) {
		pr_err("Can't install luo session fd as service fd\n");
		close(luo_session_fd);
		return -1;
	}

	pr_info("LUO [RESTORE]: RETRIEVE SESSION: name='%s' -> session_fd=%d\n",
		session_name, luo_session_fd);
	close_luo_device();

	return 0;
}

int luo_retrieve_fd(uint64_t token, int *fd)
{
	int ret;
	struct liveupdate_session_retrieve_fd retrieve_req = {
		.size = sizeof(retrieve_req),
		.fd = -1,
		.token = token,
	};

	if (!opts.images_in_memfd || luo_session_fd < 0) {
		pr_err("LUO: retrieve_fd skipped (images_in_memfd=%d, session_fd=%d)\n",
			 opts.images_in_memfd, luo_session_fd);
		return -EINVAL;
	}

	/*
	 * luo_session_fd may be stale (original fd was closed by install_service_fd).
	 * Use get_service_fd() to get the actual service fd at the protected slot.
	 */
	luo_session_fd = get_service_fd(LUO_SESSION_FD_OFF);
	if (luo_session_fd < 0) {
		pr_err("LUO: session fd not available\n");
		return -EINVAL;
	}

	ret = ioctl(luo_session_fd, LIVEUPDATE_SESSION_RETRIEVE_FD, &retrieve_req);
	if (ret < 0) {
		int saved_errno = errno;

		pr_err("LUO [RESTORE]: RETRIEVE_FD FAILED: token=0x%016llx errno=%d (%s)\n",
			(unsigned long long)token, saved_errno, strerror(saved_errno));
		return -saved_errno;
	}

	*fd = retrieve_req.fd;
	pr_info("LUO [RESTORE]: RETRIEVE_FD: token=0x%016llx -> fd=%d\n",
		(unsigned long long)token, *fd);

	return 0;
}

int luo_finish_session(void)
{
	int ret;
	struct liveupdate_session_finish finish_req = {
		.size = sizeof(finish_req),
		.reserved = 0,
	};

	if (!opts.images_in_memfd || luo_session_fd < 0)
		return 0;

	ret = ioctl(luo_session_fd, LIVEUPDATE_SESSION_FINISH, &finish_req);
	if (ret < 0) {
		pr_perror("LUO [DUMP]: Failed to finish LUO session");
		return -errno;
	}

	pr_info("LUO [DUMP]: FINISH SESSION\n");
	return 0;
}

void luo_daemonize_and_wait(void)
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_err("fork failed, errorno:%s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (pid > 0) {
		/* Parent: wait for child to signal ready */
		pr_info("LUO [DUMP]: Daemon PID: %d (holds session fd) parent_pid=%d\n",
			pid, getpid());
		pr_info("LUO [DUMP]: You may now perform kexec reboot.\n");
	} else {
		/* Child: signal ready then sleep forever */
		pr_info("LUO [DUMP]: Daemon started pid=%d\n", getpid());

		if (setsid() < 0) {
			pr_err("setsid failed, child exit, errorno:%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		/* Change dir to root to avoid locking filesystems */
		if (chdir("/") < 0)
			exit(EXIT_FAILURE);

		while (1)
			sleep(60);
	}
}

void luo_cleanup(bool finish_session)
{
	struct luo_fd_mapping *mpos, *mtmp;

	/* Clean up FD mappings */
	list_for_each_entry_safe(mpos, mtmp, &luo_fd_mappings, list) {
		list_del(&mpos->list);
		xfree(mpos->path);
		xfree(mpos);
	}

	/* Clean up session */
	if (luo_session_fd >= 0) {
		if (finish_session)
			luo_finish_session();

		close_service_fd(LUO_SESSION_FD_OFF);
		luo_session_fd = -1;
	}
}

#endif /* CONFIG_HAS_LIVEUPDATE */
