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

/* Missing words in older images represent an empty set of bits. */
bool valid_ambient_caps(const CredsEntry *ce)
{
	size_t i;

	for (i = 0; i < ce->n_cap_amb; i++) {
		u32 permitted = i < ce->n_cap_prm ? ce->cap_prm[i] : 0;
		u32 inheritable = i < ce->n_cap_inh ? ce->cap_inh[i] : 0;

		if (ce->cap_amb[i] & ~(permitted & inheritable))
			return false;
	}
	return true;
}
