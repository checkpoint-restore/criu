#include <sched.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <grp.h>

#ifdef CONFIG_HAS_SELINUX
#include <selinux/selinux.h>
#include "images/inventory.pb-c.h"
#endif

#include "common/list.h"
#include "common/scm.h"
#include "external.h"
#include "fdstore.h"
#include "kerndat.h"
#include "log.h"
#include "lsm.h"
#include "namespaces.h"
#include "netns-broker.h"
#include "userns-broker.h"
#include "util.h"

#undef LOG_PREFIX
#define LOG_PREFIX "netns-bkr: "

struct prep_msg {
	int ret;
};

static int prep_sockets_in_child(bool for_dump, int root_pid, int *nlsk, int *seqsk)
{
	int ret;

	*nlsk = -1;
	*seqsk = -1;

	if (for_dump) {
		ret = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
		if (ret < 0) {
			pr_perror("Can't create sock diag socket");
			return -1;
		}
		*nlsk = ret;
	}

#ifdef CONFIG_HAS_SELINUX
	if (kdat.lsm == LSMTYPE__SELINUX) {
		char *ctx;

		ret = getpidcon_raw(root_pid, &ctx);
		if (ret < 0) {
			pr_perror("Getting SELinux context for PID %d failed", root_pid);
			goto err;
		}

		ret = setsockcreatecon(ctx);
		freecon(ctx);
		if (ret < 0) {
			pr_perror("Setting SELinux socket context for PID %d failed", root_pid);
			goto err;
		}
	}
#endif

	ret = socket(PF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
	if (ret < 0) {
		pr_perror("Can't create seqsk for parasite");
		goto err;
	}
	*seqsk = ret;

#ifdef CONFIG_HAS_SELINUX
	if (kdat.lsm == LSMTYPE__SELINUX) {
		ret = setsockcreatecon_raw(NULL);
		if (ret < 0) {
			pr_perror("Resetting SELinux socket context failed");
			goto err;
		}
	}
#endif

	return 0;

err:
	if (*seqsk >= 0) {
		close(*seqsk);
		*seqsk = -1;
	}
	if (*nlsk >= 0) {
		close(*nlsk);
		*nlsk = -1;
	}
	return -1;
}

int netns_broker_prep(const struct ns_id *ns, bool for_dump,
		      struct netns_broker_resp *resp)
{
	int sk[2], netns_fd = -1, pid, status;
	int fds[2] = { -1, -1 }, nr_fds;
	struct prep_msg msg = {};
	bool netns_owned = false;

	resp->nlsk = -1;
	resp->seqsk = -1;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sk) < 0) {
		pr_perror("netns broker: socketpair");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		pr_perror("netns broker: fork");
		close(sk[0]);
		close(sk[1]);
		return -1;
	}

	if (pid == 0) {
		int nlsk = -1, seqsk = -1, ret;

		close(sk[0]);

		if (userns_broker_enter(ns->ns_pid, "netns prep"))
			goto child_err;

		/* Step 2: enter the target network namespace. */
		if (ns->ext_key) {
			netns_fd = inherit_fd_lookup_id(ns->ext_key);
			if (netns_fd < 0) {
				/*
				 * External netns FD isn't in the broker
				 * child's FD table. Fall back to opening
				 * via /proc — works in rootless setups
				 * where the container's /proc is reachable.
				 */
				pr_debug("netns broker: %s not in inherit fds, trying /proc\n",
					 ns->ext_key);
				netns_fd = do_open_proc(ns->ns_pid, O_RDONLY, "ns/net");
				if (netns_fd < 0) {
					pr_perror("netns broker: open proc %d ns/net",
						  ns->ns_pid);
					goto child_err;
				}
				netns_owned = true;
			}
		} else {
			netns_fd = do_open_proc(ns->ns_pid, O_RDONLY, "ns/net");
			if (netns_fd < 0) {
				pr_perror("netns broker: open proc %d ns/net",
					  ns->ns_pid);
				goto child_err;
			}
			netns_owned = true;
		}

		if (setns(netns_fd, CLONE_NEWNET)) {
			pr_perror("netns broker: setns netns %d", ns->ns_pid);
			goto child_err;
		}

		if (netns_owned) {
			close(netns_fd);
			netns_fd = -1;
		}

		/* Step 3: create sockets inside the target netns. */
		ret = prep_sockets_in_child(for_dump, ns->ns_pid, &nlsk, &seqsk);
		if (ret)
			goto child_err;

		nr_fds = 0;
		if (for_dump)
			fds[nr_fds++] = nlsk;
		fds[nr_fds++] = seqsk;

		msg.ret = 0;
		if (send_fds(sk[1], NULL, 0, fds, nr_fds, &msg, sizeof(msg)))
			goto child_err;

		close(sk[1]);
		_exit(0);

child_err:
		msg.ret = -1;
		send_fds(sk[1], NULL, 0, NULL, 0, &msg, sizeof(msg));
		close(sk[1]);
		if (netns_owned && netns_fd >= 0)
			close(netns_fd);
		_exit(1);
	}

	close(sk[1]);

	nr_fds = for_dump ? 2 : 1;
	if (recv_fds(sk[0], fds, nr_fds, &msg, sizeof(msg)) < 0) {
		pr_perror("netns broker: recv fds");
		close(sk[0]);
		waitpid(pid, &status, 0);
		return -1;
	}

	close(sk[0]);

	if (waitpid(pid, &status, 0) < 0) {
		pr_perror("netns broker: waitpid");
		return -1;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || msg.ret) {
		int i;

		pr_err("netns broker: child failed (exit %d, ret %d)\n",
		       WIFEXITED(status) ? WEXITSTATUS(status) : -1, msg.ret);
		for (i = 0; i < nr_fds; i++)
			if (fds[i] >= 0)
				close(fds[i]);
		return -1;
	}

	if (for_dump) {
		resp->nlsk = fds[0];
		resp->seqsk = fds[1];
	} else {
		resp->seqsk = fds[0];
	}

	pr_info("Prepared netns sockets via broker for pid %d\n", ns->ns_pid);
	return 0;
}
