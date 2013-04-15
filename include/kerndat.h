#ifndef __CR_KERNDAT_H__
#define __CR_KERNDAT_H__
/*
 * kerndat stands for "kernel data" and is a collection
 * of run-time information about current kernel
 */

int kerndat_init(void);

extern dev_t kerndat_shmem_dev;
#endif
