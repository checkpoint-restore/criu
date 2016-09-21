#ifndef UAPI_COMPEL_H__
#define UAPI_COMPEL_H__

#include <errno.h>

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
 * FIXME: Backward compat layer for CRIU. Need to
 * drop it later, before the release.
 */

#define elf_reloc_t		compel_reloc_t
#define PIEGEN_TYPE_INT		COMPEL_TYPE_INT
#define PIEGEN_TYPE_LONG	COMPEL_TYPE_LONG
#define PIEGEN_TYPE_GOTPCREL	COMPEL_TYPE_GOTPCREL

#endif /* UAPI_COMPEL_H__ */
