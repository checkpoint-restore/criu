#include <linux/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/msg.h>
#include <string.h>
#include <unistd.h>

#include "libnetlink.h"
#include "util.h"

static int nlmsg_receive(char *buf, int len, int (*cb)(struct nlmsghdr *, void *), 
		int (*err_cb)(int, void *), void *arg)
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

			return err_cb(err->error, arg);
		}
		if (cb(hdr, arg))
			return -1;
	}

	return 1;
}

static int rtnl_return_err(int err, void *arg)
{
	pr_warn("ERROR %d reported by netlink\n", err);
	return err;
}

int do_rtnl_req(int nl, void *req, int size,
		int (*receive_callback)(struct nlmsghdr *h, void *),
		int (*error_callback)(int err, void *), void *arg)
{
	struct msghdr msg;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	static char buf[16384];
	int err;

	if (!error_callback)
		error_callback = rtnl_return_err;

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

		if (msg.msg_flags & MSG_TRUNC) {
			pr_err("Message truncated\n");
			err = -EMSGSIZE;
			goto err;
		}

		err = nlmsg_receive(buf, err, receive_callback, error_callback, arg);
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
	int len = nla_attr_size(alen);
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

/*
 * Here is a workaround for a bug in libnl-3:
 * 6a8d90f5fec4 "attr: Allow attribute type 0
 */

/**
 * Create attribute index based on a stream of attributes.
 * @arg tb		Index array to be filled (maxtype+1 elements).
 * @arg maxtype		Maximum attribute type expected and accepted.
 * @arg head		Head of attribute stream.
 * @arg len		Length of attribute stream.
 * @arg policy		Attribute validation policy.
 *
 * Iterates over the stream of attributes and stores a pointer to each
 * attribute in the index array using the attribute type as index to
 * the array. Attribute with a type greater than the maximum type
 * specified will be silently ignored in order to maintain backwards
 * compatibility. If \a policy is not NULL, the attribute will be
 * validated using the specified policy.
 *
 * @see nla_validate
 * @return 0 on success or a negative error code.
 */
int __wrap_nla_parse(struct nlattr *tb[], int maxtype, struct nlattr *head, int len,
	      struct nla_policy *policy)
{
	struct nlattr *nla;
	int rem;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		int type = nla_type(nla);

		if (type > maxtype)
			continue;

		if (tb[type])
			pr_warn("Attribute of type %#x found multiple times in message, "
				  "previous attribute is being ignored.\n", type);

		tb[type] = nla;
	}

	if (rem > 0)
		pr_warn("netlink: %d bytes leftover after parsing "
		       "attributes.\n", rem);

	return 0;
}

/**
 * parse attributes of a netlink message
 * @arg nlh		netlink message header
 * @arg hdrlen		length of family specific header
 * @arg tb		destination array with maxtype+1 elements
 * @arg maxtype		maximum attribute type to be expected
 * @arg policy		validation policy
 *
 * See nla_parse()
 */
int __wrap_nlmsg_parse(struct nlmsghdr *nlh, int hdrlen, struct nlattr *tb[],
		int maxtype, struct nla_policy *policy)
{
	if (!nlmsg_valid_hdr(nlh, hdrlen))
		return -NLE_MSG_TOOSHORT;

	return nla_parse(tb, maxtype, nlmsg_attrdata(nlh, hdrlen),
			 nlmsg_attrlen(nlh, hdrlen), policy);
}
