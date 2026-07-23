#ifndef __CR_NETNS_BROKER_H__
#define __CR_NETNS_BROKER_H__

#include <stdbool.h>
#include <sys/types.h>

/*
 * One-shot helper per network namespace operation.  The parent forks,
 * the child enters the target user namespace *first* followed by the
 * target network namespace, creates the required sockets, and passes
 * the file-descriptors back to the parent via SCM_RIGHTS.
 *
 * This is needed when the target network namespace is owned by a
 * different user namespace than CRIU's current user namespace.
 */

struct ns_id;

struct netns_broker_resp {
	int nlsk;  /* SOCK_DIAG socket, or -1 */
	int seqsk; /* parasite seqpacket socket */
};

extern int netns_broker_prep(const struct ns_id *ns, bool for_dump,
			     struct netns_broker_resp *resp);

#endif /* __CR_NETNS_BROKER_H__ */
