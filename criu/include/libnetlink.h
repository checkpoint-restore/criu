#ifndef __CR_LIBNETLINK_H__
#define __CR_LIBNETLINK_H__

#define CR_NLMSG_SEQ		24680	/* arbitrary chosen */

struct ns_id;
extern int do_rtnl_req(int nl, void *req, int size,
		int (*receive_callback)(struct nlmsghdr *h, struct ns_id *ns, void *),
		int (*error_callback)(int err, struct ns_id *ns, void *), struct ns_id *ns, void *);

extern int addattr_l(struct nlmsghdr *n, int maxlen, int type,
		const void *data, int alen);

extern int32_t nla_get_s32(const struct nlattr *nla);

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef NETNS_RTA
#define NETNS_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtgenmsg))))
#endif

#endif /* __CR_LIBNETLINK_H__ */
