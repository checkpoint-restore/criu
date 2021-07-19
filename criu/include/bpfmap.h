#ifndef __CR_BPFMAP_H__
#define __CR_BPFMAP_H__

#include "files.h"
#include "bpfmap-file.pb-c.h"
#include "bpfmap-data.pb-c.h"

struct bpfmap_file_info {
	BpfmapFileEntry *bpfe;
	struct file_desc d;
};

struct bpfmap_data_rst {
	BpfmapDataEntry *bde;
	void *data;
	struct bpfmap_data_rst *next;
};

#define BPFMAP_DATA_HASH_BITS  5
#define BPFMAP_DATA_TABLE_SIZE (1 << BPFMAP_DATA_HASH_BITS)
#define BPFMAP_DATA_HASH_MASK  (BPFMAP_DATA_TABLE_SIZE - 1)

extern int is_bpfmap_link(char *link);
extern int dump_one_bpfmap_data(BpfmapFileEntry *bpf, int lfd, const struct fd_parms *p);
extern int do_collect_bpfmap_data(struct bpfmap_data_rst *, ProtobufCMessage *, struct cr_img *,
				  struct bpfmap_data_rst **);
extern int restore_bpfmap_data(int, uint32_t, struct bpfmap_data_rst **);

extern const struct fdtype_ops bpfmap_dump_ops;
extern struct collect_image_info bpfmap_cinfo;
extern struct collect_image_info bpfmap_data_cinfo;

#endif /* __CR_BPFMAP_H__ */
