#include <linux/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>
#include <unistd.h>

#include "libnetlink.h"
#include "util.h"

int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if ((rta->rta_type <= max) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		pr_warn("Trimmed RTA: len %d, rta_len %d\n", len, rta->rta_len);
	return 0;
}

int nlmsg_receive(char *buf, int len, int (*cb)(struct nlmsghdr *))
{
	struct nlmsghdr *hdr;

	for (hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
		if (hdr->nlmsg_seq != CR_NLMSG_SEQ)
			continue;
		if (hdr->nlmsg_type == NLMSG_DONE)
			return 0;
		if (hdr->nlmsg_type == NLMSG_ERROR) {
			pr_err("Error getting sockets list\n");
			return -1;
		}
		if (cb(hdr))
			return -1;
	}

	return 1;
}
