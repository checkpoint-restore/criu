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

#endif
