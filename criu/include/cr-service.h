#ifndef __CR_SERVICE_H__
#define __CR_SERVICE_H__

#include "images/rpc.pb-c.h"

extern int cr_service(bool daemon_mode);
int cr_service_work(int sk);

extern int send_criu_dump_resp(int socket_fd, bool success, bool restored);

extern struct _cr_service_client *cr_service_client;
extern unsigned int service_sk_ino;

#endif /* __CR_SERVICE_H__ */
