#include <linux/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		pr_warn("Trimmed RTA: len %d, rta_len %d\n", len, rta->rta_len);
	return 0;
}

static int nlmsg_receive(char *buf, int len, int (*cb)(struct nlmsghdr *, void *), void *arg)
{
	struct nlmsghdr *hdr;

	for (hdr = (struct nlmsghdr *)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
		if (hdr->nlmsg_seq != CR_NLMSG_SEQ)
			continue;
		if (hdr->nlmsg_type == NLMSG_DONE) {
			int *len = (int *)NLMSG_DATA(hdr);

			if (*len < 0) {
				pr_err("ERROR %d reported by netlink (%s)\n",
					*len, strerror(-*len));
				return *len;
			}

			return 0;
		}
		if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(hdr);

			if (hdr->nlmsg_len - sizeof(*hdr) < sizeof(struct nlmsgerr)) {
				pr_err("ERROR truncated\n");
				return -1;
			}

			if (err->error == 0)
				return 0;

			pr_err("ERROR %d reported by netlink\n", err->error);
			return err->error;
		}
		if (cb(hdr, arg))
			return -1;
	}

	return 1;
}

int do_rtnl_req(int nl, void *req, int size,
		int (*receive_callback)(struct nlmsghdr *h, void *), void *arg)
{
	struct msghdr msg;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	static char buf[4096];
	int err;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name	= &nladdr;
	msg.msg_namelen	= sizeof(nladdr);
	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	iov.iov_base	= req;
	iov.iov_len	= size;

	if (sendmsg(nl, &msg, 0) < 0) {
		err = -errno;
		pr_perror("Can't send request message");
		goto err;
	}

	iov.iov_base	= buf;
	iov.iov_len	= sizeof(buf);

	while (1) {

		memset(&msg, 0, sizeof(msg));
		msg.msg_name	= &nladdr;
		msg.msg_namelen	= sizeof(nladdr);
		msg.msg_iov	= &iov;
		msg.msg_iovlen	= 1;

		err = recvmsg(nl, &msg, 0);
		if (err < 0) {
			if (errno == EINTR)
				continue;
			else {
				err = -errno;
				pr_perror("Error receiving nl report");
				goto err;
			}
		}
		if (err == 0)
			break;

		err = nlmsg_receive(buf, err, receive_callback, arg);
		if (err < 0)
			goto err;
		if (err == 0)
			break;
	}

	return 0;

err:
	return err;
}

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		pr_err("addattr_l ERROR: message exceeded bound of %d\n", maxlen);
		return -1;
	}

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}
