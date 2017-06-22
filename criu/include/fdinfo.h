#ifndef __CR_FDINFO_H__
#define __CR_FDINFO_H__

#include "common/list.h"

#include "images/eventfd.pb-c.h"
#include "images/eventpoll.pb-c.h"
#include "images/signalfd.pb-c.h"
#include "images/fsnotify.pb-c.h"
#include "images/timerfd.pb-c.h"

struct fdinfo_common {
	off64_t pos;
	int flags;
	int mnt_id;
	int owner;
};

extern int parse_fdinfo(int fd, int type, void *arg);
extern int parse_fdinfo_pid(int pid, int fd, int type, void *arg);

#endif
