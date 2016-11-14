#ifndef UAPI_COMPEL_H__
#define UAPI_COMPEL_H__

#include <errno.h>
#include <stdarg.h>

#include <compel/asm/infect-types.h>

#define COMPEL_TYPE_INT		(1u << 0)
#define COMPEL_TYPE_LONG	(1u << 1)
#define COMPEL_TYPE_GOTPCREL	(1u << 2)

typedef struct {
	unsigned int	offset;
	unsigned int	type;
	long		addend;
	long		value;
} compel_reloc_t;

#include <compel/log.h>
#include <compel/infect-util.h>
#include <compel/infect-rpc.h>
#include <compel/infect.h>

#endif /* UAPI_COMPEL_H__ */
