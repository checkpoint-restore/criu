#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <grp.h>

#include "log.h"
#include "namespaces.h"
#include "userns-broker.h"
#include "util.h"

static void broker_pr_perror(const char *broker_name, const char *op_name, const char *msg)
{
	if (op_name)
		pr_perror("%s %s: %s", broker_name, op_name, msg);
	else
		pr_perror("%s: %s", broker_name, msg);
}

int userns_broker_drop_groups(const char *broker_name, const char *op_name)
{
	if (setgroups(0, NULL)) {
		if (errno == EPERM) {
			gid_t *groups = NULL;
			int i, nr_groups;

			/*
			 * setgroups() can already be blocked after entering a
			 * non-initial user namespace. That is acceptable only
			 * when no supplementary groups can escape the target
			 * namespace credentials.
			 */
			nr_groups = getgroups(0, NULL);
			if (nr_groups > 0) {
				groups = xmalloc(sizeof(*groups) * nr_groups);
				if (!groups)
					return -1;
				nr_groups = getgroups(nr_groups, groups);
			}

			for (i = 0; i < nr_groups; i++) {
				if (groups[i] != 0)
					break;
			}

			xfree(groups);
			if (nr_groups >= 0 && i == nr_groups) {
				if (op_name)
					pr_info("%s %s: setgroups denied, groups already safe\n", broker_name, op_name);
				else
					pr_info("%s: setgroups denied, groups already safe\n", broker_name);
				return 0;
			}
		}
		broker_pr_perror(broker_name, op_name, "setgroups");
		return -1;
	}

	return 0;
}

int userns_broker_enter_creds(const char *broker_name, const char *op_name)
{
	if ((geteuid() != 0 && setuid(0)) || (getegid() != 0 && setgid(0))) {
		broker_pr_perror(broker_name, op_name, "set uid/gid 0 in target userns");
		return -1;
	}

	return 0;
}

static int userns_broker_same_ns(int ns_fd, const char *op_name)
{
	struct stat cur_st, target_st;
	int cur_fd;

	cur_fd = open("/proc/self/ns/user", O_RDONLY);
	if (cur_fd < 0) {
		pr_perror("userns broker %s: open current userns", op_name);
		return -1;
	}

	if (fstat(cur_fd, &cur_st)) {
		pr_perror("userns broker %s: stat current userns", op_name);
		close(cur_fd);
		return -1;
	}
	close(cur_fd);

	if (fstat(ns_fd, &target_st)) {
		pr_perror("userns broker %s: stat target userns", op_name);
		return -1;
	}

	return cur_st.st_dev == target_st.st_dev && cur_st.st_ino == target_st.st_ino;
}

int userns_broker_enter(int pid, const char *op_name)
{
	int userns_fd;

	if (userns_broker_drop_groups("userns broker", op_name))
		return -1;

	userns_fd = do_open_proc(pid, O_RDONLY, "ns/user");
	if (userns_fd < 0) {
		pr_perror("userns broker %s: open proc %d ns/user", op_name, pid);
		return -1;
	}

	if (setns(userns_fd, CLONE_NEWUSER)) {
		int setns_errno = errno;

		if (setns_errno == EINVAL && userns_broker_same_ns(userns_fd, op_name) > 0)
			pr_info("userns broker %s: already in target userns\n", op_name);
		else {
			errno = setns_errno;
			pr_perror("userns broker %s: setns userns %d", op_name, pid);
			close(userns_fd);
			return -1;
		}
	}
	close(userns_fd);

	return userns_broker_enter_creds("userns broker", op_name);
}
