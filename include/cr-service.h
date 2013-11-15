#ifndef __CR_SERVICE_H__
#define __CR_SERVICE_H__

#include "protobuf/rpc.pb-c.h"

#define CR_DEFAULT_SERVICE_ADDRESS "/var/run/criu_service.socket"
#define MAX_MSG_SIZE 1024

extern int cr_service(bool deamon_mode);

extern int send_criu_dump_resp(int socket_fd, bool success, bool restored);

extern struct _cr_service_client *cr_service_client;
extern unsigned int service_sk_ino;

#endif /* __CR_SERVICE_H__ */
