#ifndef __CR_FDINFO_H__
#define __CR_FDINFO_H__

#include "common/list.h"

#include "images/eventfd.pb-c.h"
#include "images/eventpoll.pb-c.h"
#include "images/signalfd.pb-c.h"
#include "images/fsnotify.pb-c.h"
#include "images/timerfd.pb-c.h"

struct inotify_wd_entry {
	InotifyWdEntry e;
	FhEntry f_handle;
	struct list_head node;
};

struct fanotify_mark_entry {
	FanotifyMarkEntry e;
	FhEntry f_handle;
	struct list_head node;
	union {
		FanotifyInodeMarkEntry ie;
		FanotifyMountMarkEntry me;
	};
};

struct eventpoll_tfd_entry {
	EventpollTfdEntry e;
	struct list_head node;
};

union fdinfo_entries {
	EventfdFileEntry efd;
	SignalfdEntry sfd;
	struct inotify_wd_entry ify;
	struct fanotify_mark_entry ffy;
	struct eventpoll_tfd_entry epl;
	TimerfdEntry tfy;
};

extern void free_inotify_wd_entry(union fdinfo_entries *e);
extern void free_fanotify_mark_entry(union fdinfo_entries *e);
extern void free_event_poll_entry(union fdinfo_entries *e);

struct fdinfo_common {
	off64_t pos;
	int flags;
	int mnt_id;
	int owner;
};

extern int parse_fdinfo(int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);
extern int parse_fdinfo_pid(int pid, int fd, int type,
		int (*cb)(union fdinfo_entries *e, void *arg), void *arg);

#endif
