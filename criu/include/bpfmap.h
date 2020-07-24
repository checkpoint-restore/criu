#ifndef __CR_BPFMAP_H__
#define __CR_BPFMAP_H__

#include "files.h"
#include "bpfmap-file.pb-c.h"

extern int is_bpfmap_link(char *link);
extern const struct fdtype_ops bpfmap_dump_ops;

#endif /* __CR_BPFMAP_H__ */ 
