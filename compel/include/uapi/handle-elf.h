#ifndef __COMPEL_UAPI_HANDLE_ELF__
#define __COMPEL_UAPI_HANDLE_ELF__

#define COMPEL_TYPE_INT		(1u << 0)
#define COMPEL_TYPE_LONG	(1u << 1)
#define COMPEL_TYPE_GOTPCREL	(1u << 2)

typedef struct {
	unsigned int	offset;
	unsigned int	type;
	long		addend;
	long		value;
} compel_reloc_t;

/*
 * Helpers for compel hgen command results. The pref should match
 * the -p|--sym-prefix argument value.
 */
#define COMPEL_H_PARASITE_HEAD(pref)	pref##__export_parasite_head_start
#define COMPEL_H_PARASITE_CMD(pref)	pref##__export_parasite_cmd
#define COMPEL_H_PARASITE_ARGS(pref)	pref##__export_parasite_args

#endif
