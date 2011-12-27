#ifndef LIBNETLINK_H__
#define LIBNETLINK_H__

struct rtattr {
	unsigned short  rta_len;
	unsigned short  rta_type;
};

/* Macros to handle rtattributes */

#define RTA_ALIGNTO		4
#define RTA_ALIGN(len)		(((len) + RTA_ALIGNTO - 1) & ~(RTA_ALIGNTO - 1))

#define RTA_OK(rta, len)	((len) >= (int)sizeof(struct rtattr) &&		\
				 (rta)->rta_len >= sizeof(struct rtattr) &&	\
				 (rta)->rta_len <= (len))

#define RTA_NEXT(rta, attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len),	\
				 (struct rtattr *)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))

#define RTA_LENGTH(len)		(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_SPACE(len)		RTA_ALIGN(RTA_LENGTH(len))
#define RTA_DATA(rta)		((void *)(((char *)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta)	((int)((rta)->rta_len) - RTA_LENGTH(0))

#ifndef NLMSG_ALIGN
# define NLMSG_ALIGN(len)	(((len) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1))
#endif

#ifndef NLMSG_HDRLEN
# define NLMSG_HDRLEN		((int)NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#endif

#ifndef NLMSG_LENGTH
# define NLMSG_LENGTH(len)	((len) + NLMSG_ALIGN(NLMSG_HDRLEN))
#endif

#define NLMSG_SPACE(len)	NLMSG_ALIGN(NLMSG_LENGTH(len))

#ifndef NLMSG_DATA
# define NLMSG_DATA(nlh)	((void *)(((char *)nlh) + NLMSG_LENGTH(0)))
#endif

#ifndef NLMSG_NEXT
# define NLMSG_NEXT(nlh, len)	((len) -= NLMSG_ALIGN((nlh)->nlmsg_len),	\
				 (struct nlmsghdr *)(((char *)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#endif

#define NLMSG_OK(nlh, len)	((len) >= (int)sizeof(struct nlmsghdr) &&	\
				 (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
				 (nlh)->nlmsg_len <= (len))

#define NLMSG_PAYLOAD(nlh, len)	((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#define NLMSG_NOOP              0x1     /* Nothing.             */
#define NLMSG_ERROR             0x2     /* Error                */
#define NLMSG_DONE              0x3     /* End of a dump        */
#define NLMSG_OVERRUN           0x4     /* Data lost            */

#define NLMSG_MIN_TYPE          0x10    /* < 0x10: reserved control messages */

#define CR_NLMSG_SEQ		24680	/* arbitrary chosen */

extern int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
extern int nlmsg_receive(char *buf, int len, int (*cb)(struct nlmsghdr *));

#endif /* LIBNETLINK_H__ */
