#ifndef __PIE_RELOCS_H__
#define __PIE_RELOCS_H__

#include <compel/compel.h>

#include "common/compiler.h"
#include "config.h"

#ifdef CONFIG_PIEGEN

#define pie_size(__pie_name)	(round_up(sizeof(__pie_name##_blob) + \
			__pie_name ## _nr_gotpcrel * sizeof(long), page_size()))
#define ELF_RELOCS_APPLY(__pie_name, __mem, __vbase)			\
	compel_relocs_apply(__mem, __vbase, sizeof(__pie_name##_blob),	\
			 __pie_name##_relocs, ARRAY_SIZE(__pie_name##_relocs))

#else

#define pie_size(__pie_name)	(round_up(sizeof(__pie_name##_blob), page_size()))
#define ELF_RELOCS_APPLY(__pie_name, __mem, __vbase)

#endif

#endif /* __PIE_RELOCS_H__ */
