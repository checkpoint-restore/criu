#include <stdio.h>

#include "common/compiler.h"
#include "imgset.h"
#include "bpfmap.h"
#include "fdinfo.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"
#include "bpfmap-file.pb-c.h"

int is_bpfmap_link(char *link)
{
    printf("is_bpfmap_link: %s\n", link);
	return is_anon_link_type(link, "bpf-map");
}

static void pr_info_bpfmap(char *action, BpfmapFileEntry *bpf)
{
	pr_info("%sbpfmap: id %#08x map_id %#08x map_type %d flags %#04x\n",
		action, bpf->id, bpf->map_id, bpf->map_type, bpf->flags);
}

static int dump_one_bpfmap(int lfd, u32 id, const struct fd_parms *p)
{
	BpfmapFileEntry bpf = BPFMAP_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;

	if (parse_fdinfo(lfd, FD_TYPES__BPFMAP, &bpf))
		return -1;

	bpf.id = id;
	bpf.flags = p->flags;
	bpf.fown = (FownEntry *)&p->fown;

	fe.type = FD_TYPES__BPFMAP;
	fe.id = bpf.id;
	fe.bpf = &bpf;

	pr_info_bpfmap("Dumping ", &bpf);
	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops bpfmap_dump_ops = {
	.type		= FD_TYPES__BPFMAP,
	.dump		= dump_one_bpfmap,
};