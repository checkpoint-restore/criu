#ifndef __CR_SK_INET_H__
#define __CR_SK_INET_H__

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
};

struct inet_sk_info {
	struct inet_sk_entry ie;
	struct file_desc d;
};

int inet_bind(int sk, struct inet_sk_info *);
int inet_connect(int sk, struct inet_sk_info *);
#endif
