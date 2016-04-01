#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "rst-malloc.h"
#include "bug.h"
#include "asm/types.h"

struct rst_mem_type_s {
	bool remapable;
	bool enabled;
	unsigned long free_bytes;
	void *free_mem;
	int (*grow)(struct rst_mem_type_s *, unsigned long size);
	unsigned long last;

	void *buf;
	unsigned long size;
};

static inline unsigned long rst_mem_grow(unsigned long need_size)
{
	int rst_mem_batch = 2 * page_size();

	need_size = round_up(need_size, page_size());
	if (likely(need_size < rst_mem_batch))
		need_size = rst_mem_batch;
	else
		pr_debug("Growing rst memory %lu pages\n", need_size / page_size());
	return need_size;
}

static int grow_shared(struct rst_mem_type_s *t, unsigned long size)
{
	void *aux;

	size = rst_mem_grow(size);

	/*
	 * This buffer will not get remapped into
	 * restorer, thus we can just forget the
	 * previous chunk location and allocate a
	 * new one
	 */
	aux = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, 0, 0);
	if (aux == MAP_FAILED)
		return -1;

	t->free_mem = aux;
	t->free_bytes = size;
	t->last = 0;

	return 0;
}

static int grow_remap(struct rst_mem_type_s *t, int flag, unsigned long size)
{
	void *aux;

	size = rst_mem_grow(size);

	if (!t->buf)
		/*
		 * Can't call mremap with NULL address :(
		 */
		aux = mmap(NULL, size, PROT_READ | PROT_WRITE,
				flag | MAP_ANON, 0, 0);
	else
		/*
		 * We'll have to remap all objects into restorer
		 * address space and get their new addresses. Since
		 * we allocate many objects as one linear array, it's
		 * simpler just to grow the buffer and let callers
		 * find out new array addresses, rather than allocate
		 * a completely new one and force callers use objects'
		 * cpos-s.
		 */
		aux = mremap(t->buf, t->size,
				t->size + size, MREMAP_MAYMOVE);
	if (aux == MAP_FAILED)
		return -1;

	t->free_mem += (aux - t->buf);
	t->free_bytes += size;
	t->size += size;
	t->buf = aux;

	return 0;
}

static int grow_shremap(struct rst_mem_type_s *t, unsigned long size)
{
	return grow_remap(t, MAP_SHARED, size);
}

static int grow_private(struct rst_mem_type_s *t, unsigned long size)
{
	return grow_remap(t, MAP_PRIVATE, size);
}

static struct rst_mem_type_s rst_mems[RST_MEM_TYPES] = {
	[RM_SHARED] = {
		.grow = grow_shared,
		.remapable = false,
		.enabled = true,
	},
	[RM_SHREMAP] = {
		.grow = grow_shremap,
		.remapable = true,
		.enabled = true,
	},
	[RM_PRIVATE] = {
		.grow = grow_private,
		.remapable = true,
		.enabled = false,
	},
};

void rst_mem_switch_to_private(void)
{
	rst_mems[RM_SHARED].enabled = false;
	rst_mems[RM_SHREMAP].enabled = false;
	rst_mems[RM_PRIVATE].enabled = true;
}

void rst_mem_align(int type)
{
	struct rst_mem_type_s *t = &rst_mems[type];
	void *ptr;

	ptr = (void *) round_up((unsigned long)t->free_mem, sizeof(void *));
	t->free_bytes -= (ptr - t->free_mem);
	t->free_mem = ptr;
}

unsigned long rst_mem_align_cpos(int type)
{
	struct rst_mem_type_s *t = &rst_mems[type];
	BUG_ON(!t->remapable || !t->enabled);

	rst_mem_align(type);

	return t->free_mem - t->buf;
}

void *rst_mem_remap_ptr(unsigned long pos, int type)
{
	struct rst_mem_type_s *t = &rst_mems[type];
	BUG_ON(!t->remapable);
	return t->buf + pos;
}

void *rst_mem_alloc(unsigned long size, int type)
{
	struct rst_mem_type_s *t = &rst_mems[type];
	void *ret;

	BUG_ON(!t->enabled);

	if ((t->free_bytes < size) && t->grow(t, size)) {
		pr_perror("Can't grow rst mem");
		return NULL;
	}

	ret = t->free_mem;
	t->free_mem += size;
	t->free_bytes -= size;
	t->last = size;

	return ret;
}

void rst_mem_free_last(int type)
{
	struct rst_mem_type_s *t = &rst_mems[type];

	BUG_ON(!t->enabled);

	t->free_mem -= t->last;
	t->free_bytes += t->last;
	t->last = 0; /* next free_last would be no-op */
}

unsigned long rst_mem_lock(void)
{
	/*
	 * Don't allow further allocations from rst_mem since we're
	 * going to get the bootstrap area and remap all the stuff
	 * into it. The SHREMAP and SHARED should be already locked
	 * in the rst_mem_switch_to_private().
	 */
	rst_mems[RM_PRIVATE].enabled = false;
	return rst_mems[RM_PRIVATE].size + rst_mems[RM_SHREMAP].size;
}

static int rst_mem_remap_one(struct rst_mem_type_s *t, void *to)
{
	void *aux;

	BUG_ON(!t->remapable || t->enabled);

	if (!t->buf)
		/*
		 * No allocations happenned from this buffer.
		 * It's safe just to do nothing.
		 */
		return 0;

	pr_debug("\tcall mremap(%p, %lu, %lu, MAYMOVE | FIXED, %p)\n",
			t->buf, t->size, t->size, to);
	aux = mremap(t->buf, t->size, t->size, MREMAP_MAYMOVE | MREMAP_FIXED, to);
	if (aux == MAP_FAILED) {
		pr_perror("Can't mremap rst mem");
		return -1;
	}

	t->buf = aux;
	return 0;
}

int rst_mem_remap(void *to)
{
	int ret;

	ret = rst_mem_remap_one(&rst_mems[RM_PRIVATE], to);
	if (!ret) {
		to += rst_mems[RM_PRIVATE].size;
		ret = rst_mem_remap_one(&rst_mems[RM_SHREMAP], to);
	}

	return ret;
}
