#ifndef __CR_LIBNETLINK_H__
#define __CR_LIBNETLINK_H__

#define CR_NLMSG_SEQ		24680	/* arbitrary chosen */

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
#define parse_rtattr_nested(tb, max, rta) \
	(parse_rtattr((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta)))
extern int do_rtnl_req(int nl, void *req, int size,
		int (*receive_callback)(struct nlmsghdr *h, void *),
		int (*error_callback)(int err, void *), void *);

extern int addattr_l(struct nlmsghdr *n, int maxlen, int type,
		const void *data, int alen);

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))


#endif /* __CR_LIBNETLINK_H__ */
