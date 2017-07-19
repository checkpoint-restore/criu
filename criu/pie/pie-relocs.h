#ifndef __PIE_RELOCS_H__
#define __PIE_RELOCS_H__

#include <compel/compel.h>

#include "common/config.h"
#include "common/compiler.h"

#define pie_size(__pie_name)	(round_up(sizeof(__pie_name##_blob) + \
			__pie_name ## _nr_gotpcrel * sizeof(long), page_size()))

#endif /* __PIE_RELOCS_H__ */
