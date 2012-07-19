#ifndef __CR_SK_INET_H__
#define __CR_SK_INET_H__

#include "protobuf.h"
#include "../protobuf/sk-inet.pb-c.h"

#define INET_ADDR_LEN		40

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

	int rfd;
	struct list_head rlist;
};

struct inet_sk_info {
	InetSkEntry *ie;
	struct file_desc d;
	struct list_head rlist;
};

int inet_bind(int sk, struct inet_sk_info *);
int inet_connect(int sk, struct inet_sk_info *);

void tcp_unlock_all(void);
void tcp_locked_conn_add(struct inet_sk_info *);
void tcp_unlock_connections(void);

int dump_one_tcp(int sk, struct inet_sk_desc *sd);
int restore_one_tcp(int sk, struct inet_sk_info *si);

#define SK_EST_PARAM	"tcp-established"

struct cr_options;
void show_tcp_stream(int fd, struct cr_options *);

int check_tcp_repair(void);
#endif
