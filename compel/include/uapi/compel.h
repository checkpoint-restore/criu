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

/*
 * Logging
 */
typedef void (*compel_log_fn)(unsigned int lvl, const char *fmt, va_list parms);
extern void compel_log_init(compel_log_fn log_fn, unsigned int level);
extern unsigned int compel_log_get_loglevel(void);

#include <compel/infect-util.h>
#include <compel/infect-rpc.h>
#include <compel/infect.h>

#endif /* UAPI_COMPEL_H__ */
