#include <bpf/bpf.h>
#include <inttypes.h>

#include "zdtmtst.h"

#define fdinfo_field(str, field) !strncmp(str, field ":", sizeof(field))

struct bpfmap_fdinfo_obj {
	uint32_t map_type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t map_flags;
	uint64_t memlock;
	uint32_t map_id;
	uint32_t frozen;
};

extern int parse_bpfmap_fdinfo(int, struct bpfmap_fdinfo_obj *, uint32_t);
extern int cmp_bpf_map_info(struct bpf_map_info *, struct bpf_map_info *);
extern int cmp_bpfmap_fdinfo(struct bpfmap_fdinfo_obj *, struct bpfmap_fdinfo_obj *);