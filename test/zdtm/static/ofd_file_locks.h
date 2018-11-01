#ifndef ZDTM_OFD_FILE_LOCKS_H_
#define ZDTM_OFD_FILE_LOCKS_H_

#include <sys/file.h>

#ifndef F_OFD_GETLK
#define F_OFD_GETLK	36
#define F_OFD_SETLK	37
#define F_OFD_SETLKW	38
#endif

/*
 * Functions for parsing of OFD locks
 * from procfs and checking them after restoring.
 */

extern int check_lock_exists(const char *filename, struct flock *lck);
extern int check_file_lock_restored(int pid, int fd, struct flock *lck);

#endif /* ZDTM_OFD_FILE_LOCKS_H_ */
