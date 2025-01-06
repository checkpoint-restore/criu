#ifndef __CRIU_FDSTORE_H__
#define __CRIU_FDSTORE_H__

/*
 * fdstore is a storage for file descriptors which is shared
 * between processes.
 */

int fdstore_init(void);

/* Add a file descriptor to the storage and return its id */
int fdstore_add(int fd);

/* Get a file descriptor from a storage by id */
int fdstore_get(int id);

#endif
