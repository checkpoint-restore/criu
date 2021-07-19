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
	pr_info("%sbpfmap: id %#08x map_id %#08x map_type %d flags %" PRIx32 "\n", action, bpf->id, bpf->map_id,
		bpf->map_type, bpf->map_flags);
}

struct bpfmap_data_rst *bpfmap_data_hash_table[BPFMAP_DATA_TABLE_SIZE];

static int bpfmap_data_read(struct cr_img *img, struct bpfmap_data_rst *r)
{
	unsigned long bytes = r->bde->keys_bytes + r->bde->values_bytes;
	if (!bytes)
		return 0;

	r->data = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (r->data == MAP_FAILED) {
		pr_perror("Can't map mem for bpfmap buffers");
		return -1;
	}

	return read_img_buf(img, r->data, bytes);
}

int do_collect_bpfmap_data(struct bpfmap_data_rst *r, ProtobufCMessage *msg, struct cr_img *img,
			   struct bpfmap_data_rst **bpf_hash_table)
{
	int ret;
	int table_index;

	r->bde = pb_msg(msg, BpfmapDataEntry);
	ret = bpfmap_data_read(img, r);
	if (ret < 0)
		return ret;

	table_index = r->bde->map_id & BPFMAP_DATA_HASH_MASK;
	r->next = bpf_hash_table[table_index];
	bpf_hash_table[table_index] = r;

	pr_info("Collected bpfmap data for %#x\n", r->bde->map_id);
	return 0;
}

int restore_bpfmap_data(int map_fd, uint32_t map_id, struct bpfmap_data_rst **bpf_hash_table)
{
	struct bpfmap_data_rst *map_data;
	BpfmapDataEntry *bde;
	void *keys = NULL;
	void *values = NULL;
	unsigned int count;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts, .elem_flags = 0, .flags = 0, );

	for (map_data = bpf_hash_table[map_id & BPFMAP_DATA_HASH_MASK]; map_data != NULL; map_data = map_data->next) {
		if (map_data->bde->map_id == map_id)
			break;
	}

	if (!map_data || map_data->bde->count == 0) {
		pr_info("No data for BPF map %#x\n", map_id);
		return 0;
	}

	bde = map_data->bde;
	count = bde->count;

	keys = mmap(NULL, bde->keys_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (keys == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map keys");
		goto err;
	}
	memcpy(keys, map_data->data, bde->keys_bytes);

	values = mmap(NULL, bde->values_bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (values == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map values");
		goto err;
	}
	memcpy(values, map_data->data + bde->keys_bytes, bde->values_bytes);

	if (bpf_map_update_batch(map_fd, keys, values, &count, &opts)) {
		pr_perror("Can't load key-value pairs to BPF map");
		goto err;
	}
	munmap(keys, bde->keys_bytes);
	munmap(values, bde->values_bytes);
	return 0;

err:
	munmap(keys, bde->keys_bytes);
	munmap(values, bde->values_bytes);
	return -1;
}

static int collect_bpfmap_data(void *obj, ProtobufCMessage *msg, struct cr_img *img)
{
	return do_collect_bpfmap_data(obj, msg, img, bpfmap_data_hash_table);
}

struct collect_image_info bpfmap_data_cinfo = {
	.fd_type = CR_FD_BPFMAP_DATA,
	.pb_type = PB_BPFMAP_DATA,
	.priv_size = sizeof(struct bpfmap_data_rst),
	.collect = collect_bpfmap_data,
};

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
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts, .elem_flags = 0, .flags = 0, );
	int ret;

	key_size = bpf->key_size;
	value_size = bpf->value_size;
	max_entries = bpf->max_entries;
	count = max_entries;

	keys = mmap(NULL, key_size * max_entries, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (keys == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map keys");
		goto err;
	}

	values = mmap(NULL, value_size * max_entries, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (values == MAP_FAILED) {
		pr_perror("Can't map memory for BPF map values");
		goto err;
	}

	out_batch = mmap(NULL, key_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
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
	struct bpf_map_info map_info;
	uint32_t info_len = sizeof(struct bpf_map_info);
	int ret;

	if (parse_fdinfo(lfd, FD_TYPES__BPFMAP, &bpf))
		return -1;

	ret = bpf_obj_get_info_by_fd(lfd, &map_info, &info_len);
	if (ret) {
		pr_perror("Could not get BPF map info");
		return -1;
	}

	switch (bpf.map_type) {
	case BPF_MAP_TYPE_HASH:
	case BPF_MAP_TYPE_ARRAY:
		bpf.id = id;
		bpf.flags = p->flags;
		bpf.fown = (FownEntry *)&p->fown;
		bpf.map_name = xstrdup(map_info.name);
		bpf.ifindex = map_info.ifindex;

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
	.type = FD_TYPES__BPFMAP,
	.dump = dump_one_bpfmap,
};

static int bpfmap_open(struct file_desc *d, int *new_fd)
{
	struct bpfmap_file_info *info;
	BpfmapFileEntry *bpfe;
	struct bpf_create_map_attr xattr;
	int bpfmap_fd;

	info = container_of(d, struct bpfmap_file_info, d);
	bpfe = info->bpfe;

	xattr.name = xstrdup(bpfe->map_name);
	xattr.map_type = bpfe->map_type;
	xattr.map_flags = bpfe->map_flags;
	xattr.key_size = bpfe->key_size;
	xattr.value_size = bpfe->value_size;
	xattr.max_entries = bpfe->max_entries;
	xattr.numa_node = 0;
	xattr.btf_fd = 0;
	xattr.btf_key_type_id = 0;
	xattr.btf_value_type_id = 0;
	xattr.map_ifindex = bpfe->ifindex;
	xattr.inner_map_fd = 0;

	pr_info_bpfmap("Creating and opening ", bpfe);
	bpfmap_fd = bpf_create_map_xattr(&xattr);
	if (bpfmap_fd < 0) {
		pr_perror("Can't create bpfmap %#08x", bpfe->id);
		return -1;
	}

	if (restore_bpfmap_data(bpfmap_fd, bpfe->map_id, bpfmap_data_hash_table))
		return -1;

	if (bpfe->frozen) {
		if (bpf_map_freeze(bpfmap_fd)) {
			pr_perror("Can't freeze bpfmap %#08x", bpfe->id);
			goto err_close;
		}
	}

	if (rst_file_params(bpfmap_fd, bpfe->fown, bpfe->flags)) {
		pr_perror("Can't restore params on bpfmap %#08x", bpfe->id);
		goto err_close;
	}

	*new_fd = bpfmap_fd;
	return 0;

err_close:
	close(bpfmap_fd);
	return -1;
}

static struct file_desc_ops bpfmap_desc_ops = {
	.type = FD_TYPES__BPFMAP,
	.open = bpfmap_open,
};

static int collect_one_bpfmap(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct bpfmap_file_info *info = obj;

	info->bpfe = pb_msg(msg, BpfmapFileEntry);
	pr_info_bpfmap("Collected ", info->bpfe);
	return file_desc_add(&info->d, info->bpfe->id, &bpfmap_desc_ops);
}

struct collect_image_info bpfmap_cinfo = {
	.fd_type = CR_FD_BPFMAP_FILE,
	.pb_type = PB_BPFMAP_FILE,
	.priv_size = sizeof(struct bpfmap_file_info),
	.collect = collect_one_bpfmap,
};
