#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "bpfmap_zdtm.h"

const char *test_doc	= "Check that data and meta-data for BPF_MAP_TYPE_HASH"
							"is correctly restored";
const char *test_author	= "Abhishek Vijeev <abhishek.vijeev@gmail.com>";

static int map_batch_update(int map_fd, uint32_t max_entries, int *keys, int *values)
{
	int ret;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

	for (int i = 0; i < max_entries; i++) {
		keys[i] = i + 1;
		values[i] = i + 2;
	}

	ret = bpf_map_update_batch(map_fd, keys, values, &max_entries, &opts);
	if (ret && errno != ENOENT) {
		pr_perror("Can't load key-value pairs to BPF map");
		return -1;
	}
	return 0;
}

static int map_batch_verify(int *visited, uint32_t max_entries, int *keys, int *values)
{
	memset(visited, 0, max_entries * sizeof(*visited));
	for (int i = 0; i < max_entries; i++) {
		
		if (keys[i] + 1 != values[i]) {
			pr_err("Key/value checking error: i=%d, key=%d, value=%d\n", i, keys[i], values[i]);
			return -1;
		}
		visited[i] = 1;
	}
	for (int i = 0; i < max_entries; i++) {
		if (visited[i] != 1) {
			pr_err("Visited checking error: keys array at index %d missing\n", i);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	uint32_t batch, count;
	int map_fd;
	int *keys = NULL, *values = NULL, *visited = NULL;
	const uint32_t max_entries = 10;
	int ret;
	struct bpf_map_info old_map_info = {};
	struct bpf_map_info new_map_info = {};
	struct bpfmap_fdinfo_obj old_fdinfo = {};
	struct bpfmap_fdinfo_obj new_fdinfo = {};
	uint32_t info_len = sizeof(struct bpf_map_info);
	struct bpf_create_map_attr xattr = {
		.name = "hash_test_map",
		.map_type = BPF_MAP_TYPE_HASH,
		.key_size = sizeof(int),
		.value_size = sizeof(int),
		.max_entries = max_entries,
		.map_flags = BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE,
	};
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, opts,
		.elem_flags = 0,
		.flags = 0,
	);

	keys = mmap(NULL, max_entries * sizeof(int), 
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);	
	values = mmap(NULL, max_entries * sizeof(int), 
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	visited = mmap(NULL, max_entries * sizeof(int), 
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	
	if ((keys == MAP_FAILED) || (values == MAP_FAILED) || (visited == MAP_FAILED)) {
		pr_perror("Can't mmap()");
		goto err;
	}

	test_init(argc, argv);

	map_fd = bpf_create_map_xattr(&xattr);
	if (!map_fd) {
		pr_perror("Can't create BPF map");
		goto err;
	}

	if (map_batch_update(map_fd, max_entries, keys, values))
		goto err;

	ret = bpf_map_freeze(map_fd);
	if (ret) {
		pr_perror("Could not freeze map");
		goto err;
	}

	ret = bpf_obj_get_info_by_fd(map_fd, &old_map_info, &info_len);
	if (ret) {
		pr_perror("Could not get old map info");
		goto err;
	}

	ret = parse_bpfmap_fdinfo(map_fd, &old_fdinfo, 8);
	if (ret) {
		pr_perror("Could not parse old map fdinfo from procfs");
		goto err;
	}

	test_daemon();

	test_waitsig();

	ret = bpf_obj_get_info_by_fd(map_fd, &new_map_info, &info_len);
	if (ret) {
		pr_perror("Could not get new map info");
		goto err;
	}

	ret = parse_bpfmap_fdinfo(map_fd, &new_fdinfo, 8);
	if (ret) {
		pr_perror("Could not parse new map fdinfo from procfs");
		goto err;
	}
	
	if (cmp_bpf_map_info(&old_map_info, &new_map_info)) {
		pr_err("bpf_map_info mismatch\n");
		goto err;
	}

	if (cmp_bpfmap_fdinfo(&old_fdinfo, &new_fdinfo)) {
		pr_err("bpfmap fdinfo mismatch\n");
		goto err;
	}

	memset(keys, 0, max_entries * sizeof(*keys));
	memset(values, 0, max_entries * sizeof(*values));

	ret = bpf_map_lookup_batch(map_fd, NULL, &batch, keys, values, &count, &opts);
	if (ret && errno != ENOENT) {
		pr_perror("Can't perform a batch lookup on BPF map");
		goto err;
	}

	if (map_batch_verify(visited, max_entries, keys, values))
		goto err;

	munmap(keys, max_entries * sizeof(int));
	munmap(values, max_entries * sizeof(int));
	munmap(visited, max_entries * sizeof(int));

	pass();
	return 0;

err:
	munmap(keys, max_entries * sizeof(int));
	munmap(values, max_entries * sizeof(int));
	munmap(visited, max_entries * sizeof(int));
	
	fail();
	return 1;
}