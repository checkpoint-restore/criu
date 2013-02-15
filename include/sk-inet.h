#ifndef __CR_SK_INET_H__
#define __CR_SK_INET_H__

#include <netinet/tcp.h>

#include "sockets.h"
#include "files.h"
#include "list.h"
#include "protobuf.h"
#include "protobuf/sk-inet.pb-c.h"

#define INET_ADDR_LEN		40
#ifndef TCP_REPAIR
#define TCP_REPAIR		19      /* TCP sock is under repair right now */
#define TCP_REPAIR_QUEUE	20
#define TCP_QUEUE_SEQ		21
#define TCP_REPAIR_OPTIONS	22
#endif

struct inet_sk_desc {
	struct socket_desc	sd;
	unsigned int		type;
	unsigned int		proto;
	unsigned int		src_port;
	unsigned int		dst_port;
	unsigned int		state;
	unsigned int		rqlen;
	unsigned int		wqlen;
	unsigned int		src_addr[4];
	unsigned int		dst_addr[4];
	unsigned short		shutdown;

	int rfd;
	struct list_head rlist;
};

struct inet_port;
struct inet_sk_info {
	InetSkEntry *ie;
	struct file_desc d;
	struct inet_port *port;
	struct list_head rlist;
};

int inet_bind(int sk, struct inet_sk_info *);
int inet_connect(int sk, struct inet_sk_info *);

struct rst_tcp_sock {
	int	sk;
	bool	reuseaddr;
};

static inline void tcp_repair_off(int fd)
{
	int aux = 0;

	if (sys_setsockopt(fd, SOL_TCP, TCP_REPAIR, &aux, sizeof(aux)) < 0)
		pr_perror("Failed to turn off repair mode on socket");
}

void tcp_locked_conn_add(struct inet_sk_info *);
void rst_unlock_tcp_connections(void);
void cpt_unlock_tcp_connections(void);

int dump_one_tcp(int sk, struct inet_sk_desc *sd);
int restore_one_tcp(int sk, struct inet_sk_info *si);

#define SK_EST_PARAM	"tcp-established"

struct cr_options;
void show_tcp_stream(int fd, struct cr_options *);

int check_tcp(void);

extern int rst_tcp_socks_size;
extern int rst_tcp_socks_remap(void *addr);

#endif /* __CR_SK_INET_H__ */
