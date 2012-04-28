#ifndef __CR_SK_INET_H__
#define __CR_SK_INET_H__
struct inet_sk_info;
int inet_bind(int sk, struct inet_sk_info *);
int inet_connect(int sk, struct inet_sk_info *);
#endif
