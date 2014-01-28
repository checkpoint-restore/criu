#ifndef __CR_SERVICE_H__
#define __CR_SERVICE_H__

#include "protobuf/rpc.pb-c.h"

extern int cr_service(bool deamon_mode);

extern int send_criu_dump_resp(int socket_fd, bool success, bool restored);
extern int send_criu_rpc_script(char *name, int arg);

extern struct _cr_service_client *cr_service_client;
extern unsigned int service_sk_ino;

#endif /* __CR_SERVICE_H__ */
