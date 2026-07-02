#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#include "clone/unmapped-tracker.h"
#include "clone/clone-conf.h"
#include "int.h"
#include "page.h"
#include "criu-log.h"
#include "xmalloc.h"
#include "common/list.h"

#undef LOG_PREFIX
#define LOG_PREFIX "unmapped-tracker: "

/*
 * Hash table to track unmapped pages.
 * Smaller than the page buffer since unmapped ranges are typically fewer.
 * Lock-count and bucket-count constants live in clone-conf.h.
 */
#define UNMAPPED_HASH_BITS 16
#define UNMAPPED_HASH_SIZE (1 << UNMAPPED_HASH_BITS)  /* 64K buckets */

/*
 * Unrolled list node - holds multiple entries per node for cache efficiency.
 */
#define UNMAPPED_NODE_ENTRIES 32

struct unmapped_node {
	unsigned long vaddrs[UNMAPPED_NODE_ENTRIES];
	int count;
	struct hlist_node hash;
};

static struct {
	struct hlist_head *hash_table;
	pthread_spinlock_t locks[CLONE_NUM_UNMAPPED_LOCKS];
	unsigned long nr_pages;
	bool initialized;
} g_unmapped = { .initialized = false };

static inline unsigned int unmapped_hash(unsigned long vaddr)
{
	return (vaddr >> PAGE_SHIFT) & (UNMAPPED_HASH_SIZE - 1);
}

static inline int lock_index(unsigned int hash)
{
	return hash / CLONE_UNMAPPED_BUCKETS_PER_LOCK;
}

int unmapped_tracker_init(void)
{
	int i;

	if (g_unmapped.initialized)
		return 0;

	g_unmapped.hash_table = xzalloc(UNMAPPED_HASH_SIZE *
					sizeof(struct hlist_head));
	if (!g_unmapped.hash_table)
		return -1;

	for (i = 0; i < UNMAPPED_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&g_unmapped.hash_table[i]);

	for (i = 0; i < CLONE_NUM_UNMAPPED_LOCKS; i++)
		pthread_spin_init(&g_unmapped.locks[i], PTHREAD_PROCESS_PRIVATE);

	g_unmapped.nr_pages = 0;
	g_unmapped.initialized = true;

	pr_debug("Unmapped tracker initialized (hash size=%d)\n",
		 UNMAPPED_HASH_SIZE);
	return 0;
}

void unmapped_tracker_destroy(void)
{
	struct unmapped_node *node;
	struct hlist_node *tmp;
	int i;

	if (!g_unmapped.initialized)
		return;

	for (i = 0; i < UNMAPPED_HASH_SIZE; i++) {
		int lock_idx = lock_index(i);

		pthread_spin_lock(&g_unmapped.locks[lock_idx]);
		hlist_for_each_entry_safe(node, tmp,
					  &g_unmapped.hash_table[i], hash) {
			hlist_del(&node->hash);
			xfree(node);
		}
		pthread_spin_unlock(&g_unmapped.locks[lock_idx]);
	}

	for (i = 0; i < CLONE_NUM_UNMAPPED_LOCKS; i++)
		pthread_spin_destroy(&g_unmapped.locks[i]);

	xfree(g_unmapped.hash_table);
	g_unmapped.hash_table = NULL;
	g_unmapped.initialized = false;

	pr_debug("Unmapped tracker destroyed (tracked %lu pages)\n",
		 g_unmapped.nr_pages);
}

/* Add a single page to the unmapped set */
static void unmapped_tracker_add(unsigned long vaddr)
{
	unsigned int hash = unmapped_hash(vaddr);
	int lock_idx = lock_index(hash);
	struct unmapped_node *node;

	pthread_spin_lock(&g_unmapped.locks[lock_idx]);

	/* Try to find space in existing node */
	hlist_for_each_entry(node, &g_unmapped.hash_table[hash], hash) {
		if (node->count < UNMAPPED_NODE_ENTRIES) {
			node->vaddrs[node->count++] = vaddr;
			pthread_spin_unlock(&g_unmapped.locks[lock_idx]);
			__sync_fetch_and_add(&g_unmapped.nr_pages, 1);
			return;
		}
	}

	pthread_spin_unlock(&g_unmapped.locks[lock_idx]);

	/* Need new node */
	node = xmalloc(sizeof(*node));
	if (!node) {
		pr_err("Failed to allocate unmapped node for 0x%lx\n", vaddr);
		return;
	}

	node->vaddrs[0] = vaddr;
	node->count = 1;
	INIT_HLIST_NODE(&node->hash);

	pthread_spin_lock(&g_unmapped.locks[lock_idx]);
	hlist_add_head(&node->hash, &g_unmapped.hash_table[hash]);
	pthread_spin_unlock(&g_unmapped.locks[lock_idx]);

	__sync_fetch_and_add(&g_unmapped.nr_pages, 1);
}

void unmapped_tracker_mark_range(unsigned long start, unsigned long len)
{
	unsigned long vaddr, end;

	if (!g_unmapped.initialized)
		return;

	end = start + len;
	for (vaddr = start; vaddr < end; vaddr += PAGE_SIZE)
		unmapped_tracker_add(vaddr);

	pr_debug("Marked range 0x%lx-0x%lx as unmapped (%lu pages)\n",
		 start, end, len / PAGE_SIZE);
}

bool unmapped_tracker_is_unmapped(unsigned long vaddr)
{
	unsigned int hash;
	int lock_idx;
	struct unmapped_node *node;
	int i;
	bool found = false;

	if (!g_unmapped.initialized)
		return false;

	hash = unmapped_hash(vaddr);
	lock_idx = lock_index(hash);

	pthread_spin_lock(&g_unmapped.locks[lock_idx]);

	hlist_for_each_entry(node, &g_unmapped.hash_table[hash], hash) {
		for (i = 0; i < node->count; i++) {
			if (node->vaddrs[i] == vaddr) {
				found = true;
				break;
			}
		}
		if (found)
			break;
	}

	pthread_spin_unlock(&g_unmapped.locks[lock_idx]);

	return found;
}

void unmapped_tracker_clear(unsigned long vaddr)
{
	unsigned int hash;
	int lock_idx;
	struct unmapped_node *node;
	int i;

	if (!g_unmapped.initialized)
		return;

	hash = unmapped_hash(vaddr);
	lock_idx = lock_index(hash);

	pthread_spin_lock(&g_unmapped.locks[lock_idx]);

	hlist_for_each_entry(node, &g_unmapped.hash_table[hash], hash) {
		for (i = 0; i < node->count; i++) {
			if (node->vaddrs[i] == vaddr) {
				/* Swap with last and decrement count */
				node->vaddrs[i] = node->vaddrs[node->count - 1];
				node->count--;
				pthread_spin_unlock(&g_unmapped.locks[lock_idx]);
				__sync_fetch_and_sub(&g_unmapped.nr_pages, 1);
				return;
			}
		}
	}

	pthread_spin_unlock(&g_unmapped.locks[lock_idx]);
}
