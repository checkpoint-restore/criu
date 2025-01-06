#ifndef __CR_IRMAP__H__
#define __CR_IRMAP__H__

#include "images/fh.pb-c.h"

char *irmap_lookup(unsigned int s_dev, unsigned long i_ino);
int irmap_queue_cache(unsigned int dev, unsigned long ino, FhEntry *fh);
int irmap_predump_prep(void);
int irmap_predump_run(void);
int check_open_handle(unsigned int s_dev, unsigned long i_ino, FhEntry *f_handle);
int irmap_load_cache(void);
int irmap_scan_path_add(char *path);
#endif
