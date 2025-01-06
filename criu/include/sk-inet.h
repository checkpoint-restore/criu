#ifndef __CR_SK_INET_H__
#define __CR_SK_INET_H__

#include <netinet/tcp.h>

#include "sockets.h"
#include "files.h"
#include "common/list.h"
#include "images/sk-inet.pb-c.h"

#define INET_ADDR_LEN 48 /* max of INET_ADDRSTRLEN and INET6_ADDRSTRLEN */
#ifndef TCP_REPAIR
#define TCP_REPAIR	   19 /* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE   20
#define TCP_QUEUE_SEQ	   21
#define TCP_REPAIR_OPTIONS 22
#endif

#ifndef IP_HDRINCL
#define IP_HDRINCL 3
#endif

#ifndef IP_NODEFRAG
#define IP_NODEFRAG 22
#endif

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif

struct inet_sk_desc {
	struct socket_desc sd;
	unsigned int type;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int state;
	unsigned int rqlen;
	unsigned int wqlen;  /* sent + unsent data */
	unsigned int uwqlen; /* unsent data */
	unsigned int src_addr[4];
	unsigned int dst_addr[4];
	unsigned short shutdown;
	bool cork;

	int rfd;
	int cpt_reuseaddr;
	struct list_head rlist;

	void *priv;
};

struct inet_port;
struct inet_sk_info {
	InetSkEntry *ie;
	struct file_desc d;
	struct inet_port *port;
	struct list_head port_list;
	/*
	 * This is an fd by which the socket is opened.
	 * It will be carried down to restorer code to
	 * repair-off the socket at the very end.
	 */
	int sk_fd;
	struct list_head rlist;
};

extern int inet_bind(int sk, struct inet_sk_info *);
extern int inet_connect(int sk, struct inet_sk_info *);

#ifdef CR_NOGLIBC
#define setsockopt sys_setsockopt
#define pr_perror(fmt, ...) pr_err(fmt ": errno %d\n", ##__VA_ARGS__, -ret)
#endif
static inline void tcp_repair_off(int fd)
{
	int aux = 0, ret;

	ret = setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux));
	if (ret < 0)
		pr_perror("Failed to turn off repair mode on socket %d", fd);
}

extern void tcp_locked_conn_add(struct inet_sk_info *);
extern void rst_unlock_tcp_connections(void);
extern void cpt_unlock_tcp_connections(void);

extern int dump_one_tcp(int sk, struct inet_sk_desc *sd, SkOptsEntry *soe);
extern int restore_one_tcp(int sk, struct inet_sk_info *si);

extern int dump_tcp_opts(int sk, TcpOptsEntry *toe);
extern int restore_tcp_opts(int sk, TcpOptsEntry *toe);

#define SK_EST_PARAM	  "tcp-established"
#define SK_INFLIGHT_PARAM "skip-in-flight"
#define SK_CLOSE_PARAM	  "tcp-close"

struct task_restore_args;
int prepare_tcp_socks(struct task_restore_args *);

struct rst_tcp_sock {
	int sk;
	bool reuseaddr;
};

union libsoccr_addr;
int restore_sockaddr(union libsoccr_addr *sa, int family, u32 pb_port, u32 *pb_addr, u32 ifindex);

#endif /* __CR_SK_INET_H__ */
