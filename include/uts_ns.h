#ifndef CR_UTS_NS_H_
#define CR_UTS_NS_H_

#include "crtools.h"

int dump_uts_ns(int ns_pid, struct cr_fdset *fdset);
struct cr_options;
void show_utsns(int fd, struct cr_options *);
int prepare_utsns(int pid);

#endif /* CR_UTS_NS_H_ */
