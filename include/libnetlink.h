#ifndef LIBNETLINK_H__
#define LIBNETLINK_H__

#define CR_NLMSG_SEQ		24680	/* arbitrary chosen */

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int do_rtnl_req(int nl, void *req, int size,
		int (*receive_callback)(struct nlmsghdr *h));

#endif /* LIBNETLINK_H__ */
