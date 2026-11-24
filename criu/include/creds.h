#ifndef __CR_CREDS_H__
#define __CR_CREDS_H__

#include <stddef.h>
#include <stdbool.h>
#include "images/creds.pb-c.h"
#include "int.h"

void copy_caps(u32 *out_caps, const u32 *in_caps, size_t n_words, unsigned int last_cap);

bool valid_ambient_caps(const CredsEntry *ce);

#endif
