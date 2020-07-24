#include <stdio.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

#include "common/compiler.h"
#include "imgset.h"
#include "bpfmap.h"
#include "fdinfo.h"
#include "image.h"
#include "util.h"
#include "log.h"

#include "protobuf.h"

int is_bpfmap_link(char *link)
{
	return is_anon_link_type(link, "bpf-map");
}

static void pr_info_bpfmap(char *action, BpfmapFileEntry *bpf)
{
	pr_info("%sbpfmap: id %#08x map_id %#08x map_type %d flags %"PRIx32"\n",
		action, bpf->id, bpf->map_id, bpf->map_type, bpf->map_flags);
}

int dump_one_bpfmap_data(BpfmapFileEntry *bpf, int lfd, const struct fd_parms *p)
{
	/*
	 * Linux kernel patch notes for bpf_map_*_batch():
	 *
	 * in_batch/out_batch are opaque values use to communicate between
	 * user/kernel space, in_batch/out_batch must be of key_size length.
	 * To start iterating from the beginning in_batch must be null,
	 * count is the # of key/value elements to retrieve. Note that the 'keys'
	 * buffer must be a buffer of key_size * count size and the 'values' buffer
	 * must be value_size * count, where value_size must be aligned to 8 bytes
	 * by userspace if it's dealing with percpu maps. 'count' will contain the
	 * number of keys/values successfully retrieved. Note that 'count' is an
	 * input/output variable and it can contain a lower value after a call.
	 * 
	 * If there's no more entries to retrieve, ENOENT will be returned. If error
	 * is ENOENT, count might be > 0 in case it copied some values but there were
	 * no more entries to retrieve.
	 * 
	 * Note that if the return code is an error and not -EFAULT,
	 * count indicates the number of elements successfully processed.
	 */

	struct cr_img *img;
	uint32_t key_size, value_size, max_entries, count;
	void *keys = NULL, *values = NULL;
	void *in_batch = NULL, *out_batch = NULL;
	BpfmapDataEntry bde = BPFMAP_DATA_ENTRY__INIT;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);
	int ret;

	key_size = bpf->key_size;
	value_size = bpf->value_size;
	max_entries = bpf->max_entries;
	count = max_entries;

	keys = mmap(NULL, key_size * max_entries, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (keys == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map keys");
		goto err;
	}

	values = mmap(NULL, value_size * max_entries, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (values == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map values");
		goto err;
	}

	out_batch = mmap(NULL, key_size, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (out_batch == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map out_batch");
		goto err;
	}

	ret = bpf_map_lookup_batch(lfd, in_batch, out_batch, keys, values, &count, &opts);
	if (ret && errno != ENOENT) {
		pr_perror("Can't perform a batch lookup on BPF map");
		goto err;
	}

	img = img_from_set(glob_imgset, CR_FD_BPFMAP_DATA);

	bde.map_id = bpf->map_id;
	bde.keys_bytes = (key_size * count);
	bde.values_bytes = (value_size * count);
	bde.count = count;

	if (pb_write_one(img, &bde, PB_BPFMAP_DATA))
		goto err;

	if (write(img_raw_fd(img), keys, key_size * count) != (key_size * count)) {
		pr_perror("Can't write BPF map's keys");
		goto err;
	}
	if (write(img_raw_fd(img), values, value_size * count) != (value_size * count)) {
		pr_perror("Can't write BPF map's values");
		goto err;
	}

	munmap(keys, key_size * max_entries);
	munmap(values, value_size * max_entries);
	munmap(out_batch, key_size);
	return 0;

err:
	munmap(keys, key_size * max_entries);
	munmap(values, value_size * max_entries);
	munmap(out_batch, key_size);
	return -1;
}

static int dump_one_bpfmap(int lfd, u32 id, const struct fd_parms *p)
{
	BpfmapFileEntry bpf = BPFMAP_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	int ret;

	if (parse_fdinfo(lfd, FD_TYPES__BPFMAP, &bpf))
		return -1;

	switch (bpf.map_type) {

		case BPF_MAP_TYPE_HASH:
		case BPF_MAP_TYPE_ARRAY:
			bpf.id = id;
			bpf.flags = p->flags;
			bpf.fown = (FownEntry *)&p->fown;

			fe.type = FD_TYPES__BPFMAP;
			fe.id = bpf.id;
			fe.bpf = &bpf;

			pr_info_bpfmap("Dumping ", &bpf);
			if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE))
				return -1;
			pr_info_bpfmap("Dumping data for ", &bpf);
			ret = dump_one_bpfmap_data(&bpf, lfd, p);
			break;

		default:
			pr_err("CRIU does not currently support dumping BPF map type %u!\n", bpf.map_type);
			ret = -1;
	}

	return ret;
	
}

const struct fdtype_ops bpfmap_dump_ops = {
	.type		= FD_TYPES__BPFMAP,
	.dump		= dump_one_bpfmap,
};
