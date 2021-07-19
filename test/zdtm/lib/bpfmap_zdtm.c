#include "bpfmap_zdtm.h"

int parse_bpfmap_fdinfo(int fd, struct bpfmap_fdinfo_obj *obj, uint32_t expected_to_meet)
{
	uint32_t met = 0;
	char str[512];
	FILE *f;

	sprintf(str, "/proc/self/fdinfo/%d", fd);
	f = fopen(str, "r");
	if (!f) {
		pr_perror("Can't open fdinfo to parse");
		return -1;
	}

	while (fgets(str, sizeof(str), f)) {
		if (fdinfo_field(str, "map_type")) {
			if (sscanf(str, "map_type: %u", &obj->map_type) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "key_size")) {
			if (sscanf(str, "key_size: %u", &obj->key_size) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "value_size")) {
			if (sscanf(str, "value_size: %u", &obj->value_size) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "max_entries")) {
			if (sscanf(str, "max_entries: %u", &obj->max_entries) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "map_flags")) {
			if (sscanf(str, "map_flags: %" PRIx32 "", &obj->map_flags) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "memlock")) {
			if (sscanf(str, "memlock: %" PRIu64 "", &obj->memlock) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "map_id")) {
			if (sscanf(str, "map_id: %u", &obj->map_id) != 1)
				goto parse_err;
			met++;
			continue;
		}
		if (fdinfo_field(str, "frozen")) {
			if (sscanf(str, "frozen: %d", &obj->frozen) != 1)
				goto parse_err;
			met++;
			continue;
		}
	}

	if (expected_to_meet != met) {
		pr_err("Expected to meet %d entries but got %d\n", expected_to_meet, met);
		return -1;
	}

	fclose(f);
	return 0;

parse_err:
	pr_perror("Can't parse '%s'", str);
	fclose(f);
	return -1;
}

int cmp_bpf_map_info(struct bpf_map_info *old, struct bpf_map_info *new)
{
	/*
	 * We skip the check for old->id and new->id because every time a new BPF
	 * map is created, it is internally allocated a new map id. Therefore,
	 * the new BPF map created by CRIU (during restore) will have a different
	 * map id than the old one
	 */
	if ((old->type != new->type) || (old->key_size != new->key_size) || (old->value_size != new->value_size) ||
	    (old->max_entries != new->max_entries) || (old->map_flags != new->map_flags) ||
	    (old->ifindex != new->ifindex) || (old->netns_dev != new->netns_dev) ||
	    (old->netns_ino != new->netns_ino) || (old->btf_id != new->btf_id) ||
	    (old->btf_key_type_id != new->btf_key_type_id) || (old->btf_value_type_id != new->btf_value_type_id))
		return -1;

	if (strcmp(old->name, new->name) != 0)
		return -1;

	return 0;
}

int cmp_bpfmap_fdinfo(struct bpfmap_fdinfo_obj *old, struct bpfmap_fdinfo_obj *new)
{
	/*
	 * We skip the check for old->map_id and new->map_id because every time a
	 * new BPF map is created, it is internally allocated a new map id. Therefore,
	 * the new BPF map created by CRIU (during restore) will have a different map
	 * id than the old one
	 */
	if ((old->map_type != new->map_type) || (old->key_size != new->key_size) ||
	    (old->value_size != new->value_size) || (old->max_entries != new->max_entries) ||
	    (old->map_flags != new->map_flags) || (old->memlock != new->memlock) || (old->frozen != new->frozen))
		return -1;

	return 0;
}
