#ifndef __CR_SK_PACKET_H__
#define __CR_SK_PACKET_H__
struct cr_fdset;
struct fd_parms;
struct cr_options;

int dump_one_packet_sk(struct fd_parms *p, int lfd, const struct cr_fdset *fds);
int collect_packet_sockets(void);
void show_packetsk(int fd, struct cr_options *);
#endif
