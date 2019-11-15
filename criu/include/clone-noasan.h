#ifndef __CR_CLONE_NOASAN_H__
#define __CR_CLONE_NOASAN_H__

#include "common/lock.h"

int clone_noasan(int (*fn)(void *), int flags, void *arg);
int clone_noasan_init(void);
void clone_noasan_fini(void);
int clone_noasan_set_mutex(mutex_t *clone_mutex);

#endif /* __CR_CLONE_NOASAN_H__ */
