#ifndef __CR_BPFMAP_H__
#define __CR_BPFMAP_H__

#include "files.h"
#include "bpfmap-file.pb-c.h"
#include "bpfmap-data.pb-c.h"

struct bpfmap_file_info {
	BpfmapFileEntry		*bpfe;
	struct file_desc	d;
};

extern int is_bpfmap_link(char *link);
extern int dump_one_bpfmap_data(BpfmapFileEntry *bpf, int lfd, const struct fd_parms *p);

extern const struct fdtype_ops bpfmap_dump_ops;
extern struct collect_image_info bpfmap_cinfo;

#endif /* __CR_BPFMAP_H__ */ 
