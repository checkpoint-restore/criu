#include <string.h>

#include "creds.h"
#include "image.h"

void copy_caps(u32 *out_caps, const u32 *in_caps, size_t n_words, unsigned int last_cap)
{
	size_t last_word = last_cap / 32;
	size_t count = min(n_words, last_word + 1);
	size_t i;

	for (i = last_cap + 1; i / 32 < n_words; i++) {
		if (in_caps[i / 32] & (1U << (i % 32)))
			pr_warn("Dropping unsupported capability %zu > %u\n", i, last_cap);
	}

	if (count)
		memcpy(out_caps, in_caps, count * sizeof(*out_caps));
	memset(out_caps + count, 0, (CR_CAP_SIZE - count) * sizeof(*out_caps));
	out_caps[last_word] &= ~0U >> (31 - last_cap % 32);
}
