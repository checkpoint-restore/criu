#ifndef __CR_KERNDAT_H__
#define __CR_KERNDAT_H__

#include "asm/types.h"

/*
 * kerndat stands for "kernel data" and is a collection
 * of run-time information about current kernel
 */

extern int kerndat_init(void);
extern int kerndat_init_rst(void);
extern int kerndat_get_dirty_track(void);

extern dev_t kerndat_shmem_dev;
extern bool kerndat_has_dirty_track;

extern int tcp_max_wshare;
extern int tcp_max_rshare;

extern int kern_last_cap;

#endif /* __CR_KERNDAT_H__ */
