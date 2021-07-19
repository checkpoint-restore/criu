#ifndef __FILE_LOCK_H__
#define __FILE_LOCK_H__

#include "common/list.h"

#include "protobuf.h"
#include "images/file-lock.pb-c.h"

#define FL_UNKNOWN -1
#define FL_POSIX   1
#define FL_FLOCK   2
#define FL_OFD	   4
#define FL_LEASE   8

/* for posix fcntl() and lockf() */
#ifndef F_RDLCK
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#endif

/* for OFD locks fcntl() */
#ifndef F_OFD_GETLK
#define F_OFD_GETLK  36
#define F_OFD_SETLK  37
#define F_OFD_SETLKW 38
#endif

/* operations for bsd flock(), also used by the kernel implementation */
#define LOCK_SH 1 /* shared lock */
#define LOCK_EX 2 /* exclusive lock */
#define LOCK_NB \
	4 /* or'd with one of the above to prevent
				   blocking */
#define LOCK_UN 8 /* remove lock */

#define LOCK_MAND  32 /* This is a mandatory flock ... */
#define LOCK_READ  64 /* which allows concurrent read operations */
#define LOCK_WRITE 128 /* which allows concurrent write operations */
#define LOCK_RW	   192 /* which allows concurrent read & write ops */

/* for leases */
#define LEASE_BREAKING 4

struct file_lock {
	long long fl_id;
	int fl_kind;
	int fl_ltype;

	pid_t fl_owner; /* process, which created the lock */
	pid_t fl_holder; /* pid of fd on whose the lock is found */
	int maj, min;
	unsigned long i_no;
	long long start;
	char end[32];

	struct list_head list; /* list of all file locks */

	int real_owner;
	int owners_fd;
};

extern struct list_head file_lock_list;

extern struct file_lock *alloc_file_lock(void);
extern void free_file_locks(void);

extern int prepare_file_locks(int pid);
extern struct collect_image_info file_locks_cinfo;

struct pid;
struct fd_parms;
extern void discard_dup_locks_tail(pid_t pid, int fd);
extern int correct_file_leases_type(struct pid *, int fd, int lfd);
extern int note_file_lock(struct pid *, int fd, int lfd, struct fd_parms *);
extern int dump_file_locks(void);

#define OPT_FILE_LOCKS "file-locks"

#endif /* __FILE_LOCK_H__ */
