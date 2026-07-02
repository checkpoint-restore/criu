#include "clone/page-state-tracker.h"

#ifdef CONFIG_PAGE_STATE_TRACKER

#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <limits.h>

#include "int.h"
#include "page.h"
#include "criu-log.h"
#include "xmalloc.h"
#include "common/list.h"
#include "common/bug.h"
#include "util.h"
#include "clone/clone-conf.h"

#undef LOG_PREFIX
#define LOG_PREFIX "page-state: "

/*
 * Comprehensive page state tracking implementation.
 * Uses hash table for O(1) lookup with millions of pages.
 * Thread-safe: uses per-bucket spinlocks for fine-grained locking.
 * Stores full history of state changes with timestamps for debugging.
 * Hash table configuration constants are in clone-conf.h.
 */

struct page_state_history {
	enum page_state state;
	struct timespec timestamp;
};

struct page_state_entry {
	unsigned long vaddr;
	enum page_state state;
	struct timespec last_change;
	struct hlist_node hash;
	/* History of state changes */
	struct page_state_history history[CLONE_PAGE_STATE_HISTORY_SIZE];
	int history_count;
	/* CRC tracking for debugging dirty page races */
	u32 last_crc;           /* CRC of page data when last buffered */
	u32 buffer_count;       /* How many times page was buffered */
};

struct page_state_bucket {
	struct hlist_head head;
	pthread_spinlock_t lock;
};

static struct {
	struct page_state_bucket *buckets;
	/* Statistics protected by dedicated lock (less contention) */
	pthread_spinlock_t stats_lock;
	unsigned long total_pages;
	unsigned long transitions[CLONE_PAGE_STATE_MAX][CLONE_PAGE_STATE_MAX];
	unsigned long illegal_transitions;
	bool initialized;
} g_page_state = { .initialized = false };

static const char *state_names[] = {
	[PAGE_STATE_UNKNOWN]        = "UNKNOWN",
	[PAGE_STATE_IN_BUFFER]      = "IN_BUFFER",
	[PAGE_STATE_PF_PENDING]     = "PF_PENDING",
	[PAGE_STATE_DRAIN_PENDING]  = "DRAIN_PENDING",
	[PAGE_STATE_URGENT_PENDING] = "URGENT_PENDING",
	[PAGE_STATE_EAGAIN_QUEUED]  = "EAGAIN_QUEUED",
	[PAGE_STATE_COPIED]         = "COPIED",
	[PAGE_STATE_DIRTY]          = "DIRTY",
	[PAGE_STATE_DISCARDED]      = "DISCARDED",
	[PAGE_STATE_UNMAPPED]       = "UNMAPPED",
};

const char *page_state_name(enum page_state state)
{
	if (state >= CLONE_PAGE_STATE_MAX)
		return "INVALID";
	return state_names[state];
}

static inline unsigned int page_state_hash(unsigned long vaddr)
{
	return (vaddr >> PAGE_SHIFT) & (CLONE_PAGE_STATE_HASH_SIZE - 1);
}

/*
 * Simple CRC32 for page data verification.
 * Used to detect dirty page races during debugging.
 */
static u32 simple_crc32(const void *data, size_t len)
{
	const u8 *p = data;
	u32 crc = 0xFFFFFFFF;
	size_t i;
	int j;

	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
	}
	return ~crc;
}

/*
 * Valid state transitions:
 * UNKNOWN -> IN_BUFFER, URGENT_PENDING, PF_PENDING, DRAIN_PENDING, COPIED, DISCARDED
 * IN_BUFFER -> PF_PENDING, DRAIN_PENDING, DISCARDED
 * PF_PENDING -> COPIED, DISCARDED, EAGAIN_QUEUED
 * DRAIN_PENDING -> COPIED, DISCARDED, EAGAIN_QUEUED
 * URGENT_PENDING -> COPIED, EAGAIN_QUEUED, DISCARDED
 * EAGAIN_QUEUED -> COPIED, DISCARDED, DRAIN_PENDING, PF_PENDING (retry after EAGAIN)
 * COPIED -> DIRTY (source re-sends with newer data)
 * DISCARDED -> DIRTY (source re-sends with newer data)
 * DIRTY -> IN_BUFFER, COPIED, EAGAIN_QUEUED (re-receive the dirty page)
 * UNMAPPED -> (terminal, region no longer exists)
 */
static bool is_valid_transition(enum page_state from, enum page_state to)
{
	switch (from) {
	case PAGE_STATE_UNKNOWN:
		/* Can transition to any initial state */
		return true;
	case PAGE_STATE_IN_BUFFER:
		return to == PAGE_STATE_IN_BUFFER ||  /* Dirty page update overwrites existing */
		       to == PAGE_STATE_PF_PENDING ||
		       to == PAGE_STATE_DRAIN_PENDING ||
		       to == PAGE_STATE_DIRTY ||
		       to == PAGE_STATE_DISCARDED ||
		       to == PAGE_STATE_UNMAPPED;
	case PAGE_STATE_PF_PENDING:
		return to == PAGE_STATE_COPIED ||
		       to == PAGE_STATE_DISCARDED ||
		       to == PAGE_STATE_EAGAIN_QUEUED ||
		       to == PAGE_STATE_UNMAPPED;
	case PAGE_STATE_DRAIN_PENDING:
		return to == PAGE_STATE_COPIED ||
		       to == PAGE_STATE_DISCARDED ||
		       to == PAGE_STATE_EAGAIN_QUEUED ||
		       to == PAGE_STATE_UNMAPPED ||
		       to == PAGE_STATE_PF_PENDING;
	case PAGE_STATE_URGENT_PENDING:
		return to == PAGE_STATE_COPIED ||
		       to == PAGE_STATE_EAGAIN_QUEUED ||
		       to == PAGE_STATE_DISCARDED ||
		       to == PAGE_STATE_UNMAPPED;
	case PAGE_STATE_EAGAIN_QUEUED:
		return to == PAGE_STATE_COPIED ||
		       to == PAGE_STATE_DISCARDED ||
		       to == PAGE_STATE_UNMAPPED ||
		       to == PAGE_STATE_DRAIN_PENDING ||
		       to == PAGE_STATE_PF_PENDING;
	case PAGE_STATE_COPIED:
		/* COPIED pages can become DIRTY if source re-sends with newer data */
		return to == PAGE_STATE_DIRTY;
	case PAGE_STATE_DISCARDED:
		/* DISCARDED pages can become DIRTY if source re-sends with newer data */
		return to == PAGE_STATE_DIRTY;
	case PAGE_STATE_UNMAPPED:
		/* Truly terminal - region no longer exists */
		return false;
	case PAGE_STATE_DIRTY:
		/* Dirty pages can be:
		 * - Re-buffered (IN_BUFFER) if arriving pre-convergence
		 * - Directly copied (COPIED) during convergence phase
		 * - Queued for retry (EAGAIN_QUEUED) if copy gets EAGAIN
		 */
		return to == PAGE_STATE_IN_BUFFER ||
		       to == PAGE_STATE_COPIED ||
		       to == PAGE_STATE_EAGAIN_QUEUED;
	default:
		return false;
	}
}

int page_state_init(void)
{
	int i;

	if (g_page_state.initialized)
		return 0;

	g_page_state.buckets = xmalloc(CLONE_PAGE_STATE_HASH_SIZE *
				       sizeof(struct page_state_bucket));
	if (!g_page_state.buckets)
		return -1;

	for (i = 0; i < CLONE_PAGE_STATE_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&g_page_state.buckets[i].head);
		pthread_spin_init(&g_page_state.buckets[i].lock,
				  PTHREAD_PROCESS_PRIVATE);
	}

	pthread_spin_init(&g_page_state.stats_lock, PTHREAD_PROCESS_PRIVATE);
	g_page_state.total_pages = 0;
	g_page_state.illegal_transitions = 0;
	memset(g_page_state.transitions, 0, sizeof(g_page_state.transitions));
	g_page_state.initialized = true;

	pr_info("Page state tracker initialized (hash size=%d, per-bucket locks)\n",
		CLONE_PAGE_STATE_HASH_SIZE);
	return 0;
}

/* Must be called with bucket lock held */
static struct page_state_entry *page_state_find_in_bucket(struct page_state_bucket *bucket,
							  unsigned long vaddr)
{
	struct page_state_entry *entry;

	hlist_for_each_entry(entry, &bucket->head, hash) {
		if (entry->vaddr == vaddr)
			return entry;
	}
	return NULL;
}

/* Add a state change to the entry's history */
static void page_state_add_history(struct page_state_entry *entry,
				   enum page_state state,
				   struct timespec *ts)
{
	int idx;

	if (entry->history_count < CLONE_PAGE_STATE_HISTORY_SIZE) {
		idx = entry->history_count++;
	} else {
		/* History full - shift left and add at end */
		memmove(&entry->history[0], &entry->history[1],
			(CLONE_PAGE_STATE_HISTORY_SIZE - 1) * sizeof(entry->history[0]));
		idx = CLONE_PAGE_STATE_HISTORY_SIZE - 1;
	}

	entry->history[idx].state = state;
	entry->history[idx].timestamp = *ts;
}

/* Format timestamp as HH:MM:SS.mmm relative to first entry */
static void format_timestamp(struct timespec *ts, struct timespec *base, char *buf, size_t len)
{
	long delta_sec = ts->tv_sec - base->tv_sec;
	long delta_nsec = ts->tv_nsec - base->tv_nsec;
	long ms;

	if (delta_nsec < 0) {
		delta_sec--;
		delta_nsec += 1000000000;
	}

	ms = delta_nsec / 1000000;

	snprintf(buf, len, "+%ld.%03ld", delta_sec, ms);
}

/*
 * Print the full history of state changes for a page.
 * Call this when an error occurs to understand what happened.
 */
void page_state_print_history(unsigned long vaddr)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	unsigned int hash;
	int i;
	char ts_buf[32];

	if (!g_page_state.initialized) {
		pr_debug("PAGE_HISTORY 0x%lx: tracker not initialized\n", vaddr);
		return;
	}

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);

	entry = page_state_find_in_bucket(bucket, vaddr);
	if (!entry) {
		pthread_spin_unlock(&bucket->lock);
		pr_debug("PAGE_HISTORY 0x%lx: no history (page not tracked)\n", vaddr);
		return;
	}

	pr_debug("PAGE_HISTORY 0x%lx: %d transitions, current=%s\n",
	       vaddr, entry->history_count, page_state_name(entry->state));

	if (entry->history_count > 0) {
		struct timespec *base = &entry->history[0].timestamp;

		for (i = 0; i < entry->history_count; i++) {
			format_timestamp(&entry->history[i].timestamp, base,
					 ts_buf, sizeof(ts_buf));
			pr_debug("  [%d] %s sec: %s\n", i, ts_buf,
			       page_state_name(entry->history[i].state));
		}
	}

	pthread_spin_unlock(&bucket->lock);
}

/*
 * Returns true if this page's history ever passed through a page-fault
 * or urgent-request state. Such pages are owned by the target process
 * after UFFDIO_COPY and may legitimately diverge from the source's
 * snapshot by the time compare runs — callers can use this to suppress
 * expected diffs.
 */
bool page_state_was_pf_served(unsigned long vaddr)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	unsigned int hash;
	bool served = false;
	int i;

	if (!g_page_state.initialized)
		return false;

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);
	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry) {
		for (i = 0; i < entry->history_count; i++) {
			enum page_state s = entry->history[i].state;

			if (s == PAGE_STATE_PF_PENDING ||
			    s == PAGE_STATE_URGENT_PENDING) {
				served = true;
				break;
			}
		}
	}
	pthread_spin_unlock(&bucket->lock);

	return served;
}

int page_state_set(unsigned long vaddr, enum page_state new_state)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	enum page_state old_state;
	unsigned int hash;
	struct timespec now;

	if (!g_page_state.initialized)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &now);

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);

	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry) {
		old_state = entry->state;

		/* Validate transition */
		if (!is_valid_transition(old_state, new_state)) {
			pr_err("BUG: PAGE_STATE ILLEGAL_TRANSITION: 0x%lx %s -> %s\n",
			       vaddr, page_state_name(old_state),
			       page_state_name(new_state));
			/*
			 * Print history while holding lock to ensure consistent
			 * state before crashing.
			 */
			pr_err("PAGE_HISTORY 0x%lx: %d transitions, current=%s\n",
			       vaddr, entry->history_count,
			       page_state_name(entry->state));
			pthread_spin_unlock(&bucket->lock);
			pr_err("Stack trace:\n");
			print_stack_trace(0);
			BUG();
		}

		entry->state = new_state;
		entry->last_change = now;

		/* Record in history */
		page_state_add_history(entry, new_state, &now);

		pthread_spin_unlock(&bucket->lock);

		/* Update stats with dedicated lock (less contention) */
		pthread_spin_lock(&g_page_state.stats_lock);
		g_page_state.transitions[old_state][new_state]++;
		pthread_spin_unlock(&g_page_state.stats_lock);
	} else {
		/* New entry */
		entry = xmalloc(sizeof(*entry));
		if (!entry) {
			pthread_spin_unlock(&bucket->lock);
			return -1;
		}

		entry->vaddr = vaddr;
		entry->state = new_state;
		entry->last_change = now;
		entry->history_count = 0;
		entry->last_crc = 0;
		entry->buffer_count = 0;
		INIT_HLIST_NODE(&entry->hash);

		/* Add initial state to history */
		page_state_add_history(entry, new_state, &now);

		hlist_add_head(&entry->hash, &bucket->head);

		pthread_spin_unlock(&bucket->lock);

		/* Update stats with dedicated lock */
		pthread_spin_lock(&g_page_state.stats_lock);
		g_page_state.total_pages++;
		g_page_state.transitions[PAGE_STATE_UNKNOWN][new_state]++;
		pthread_spin_unlock(&g_page_state.stats_lock);
	}

	pr_debug("PAGE_STATE: 0x%lx -> %s\n", vaddr, page_state_name(new_state));
	return 0;
}

enum page_state page_state_get(unsigned long vaddr)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	enum page_state state = PAGE_STATE_UNKNOWN;
	unsigned int hash;

	if (!g_page_state.initialized)
		return PAGE_STATE_UNKNOWN;

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);
	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry)
		state = entry->state;
	pthread_spin_unlock(&bucket->lock);

	return state;
}

void page_state_mark_range_unmapped(unsigned long start, unsigned long len)
{
	unsigned long vaddr, end;
	struct page_state_entry *entry;
	struct page_state_bucket *bucket = NULL;
	struct timespec now;
	unsigned int hash, last_hash = UINT_MAX;
	unsigned long transitions_count = 0;

	if (!g_page_state.initialized)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);
	end = start + len;

	/*
	 * Process pages, batching by bucket to minimize lock operations.
	 * We hold each bucket lock while processing all pages in that bucket.
	 */
	for (vaddr = start; vaddr < end; vaddr += PAGE_SIZE) {
		hash = page_state_hash(vaddr);

		/* Switch buckets when hash changes */
		if (hash != last_hash) {
			if (last_hash != UINT_MAX)
				pthread_spin_unlock(&g_page_state.buckets[last_hash].lock);
			bucket = &g_page_state.buckets[hash];
			pthread_spin_lock(&bucket->lock);
			last_hash = hash;
		}

		entry = page_state_find_in_bucket(bucket, vaddr);
		if (!entry)
			continue;

		/* Only transition non-terminal states to UNMAPPED */
		if (entry->state != PAGE_STATE_UNKNOWN &&
		    entry->state != PAGE_STATE_COPIED &&
		    entry->state != PAGE_STATE_DISCARDED &&
		    entry->state != PAGE_STATE_UNMAPPED) {
			page_state_add_history(entry, PAGE_STATE_UNMAPPED, &now);
			entry->state = PAGE_STATE_UNMAPPED;
			entry->last_change = now;
			transitions_count++;
		}
	}

	if (last_hash != UINT_MAX)
		pthread_spin_unlock(&g_page_state.buckets[last_hash].lock);

	/* Batch update stats */
	if (transitions_count > 0) {
		pthread_spin_lock(&g_page_state.stats_lock);
		/* We don't track per-state transitions here for simplicity */
		pthread_spin_unlock(&g_page_state.stats_lock);
	}
}

void page_state_mark_dirty_ranges(unsigned long *ranges, unsigned int nr_ranges)
{
	unsigned int i;
	unsigned long marked = 0;
	struct page_state_entry *entry;
	struct page_state_bucket *bucket = NULL;
	struct timespec now;
	unsigned int hash, last_hash;

	if (!g_page_state.initialized || !ranges || nr_ranges == 0)
		return;

	clock_gettime(CLOCK_MONOTONIC, &now);

	for (i = 0; i < nr_ranges; i++) {
		unsigned long start = ranges[i * 2];
		unsigned long len = ranges[i * 2 + 1];
		unsigned long vaddr, end = start + len;

		last_hash = UINT_MAX;

		/*
		 * Process pages, batching by bucket to minimize lock operations.
		 */
		for (vaddr = start; vaddr < end; vaddr += PAGE_SIZE) {
			hash = page_state_hash(vaddr);

			/* Switch buckets when hash changes */
			if (hash != last_hash) {
				if (last_hash != UINT_MAX)
					pthread_spin_unlock(&g_page_state.buckets[last_hash].lock);
				bucket = &g_page_state.buckets[hash];
				pthread_spin_lock(&bucket->lock);
				last_hash = hash;
			}

			entry = page_state_find_in_bucket(bucket, vaddr);
			if (!entry)
				continue;

			/*
			 * Mark COPIED/DISCARDED pages as expecting re-send.
			 * These pages were already delivered to the application,
			 * but the source has newer data that will arrive.
			 */
			if (entry->state == PAGE_STATE_COPIED ||
			    entry->state == PAGE_STATE_DISCARDED) {
				page_state_add_history(entry, PAGE_STATE_DIRTY, &now);
				entry->state = PAGE_STATE_DIRTY;
				entry->last_change = now;
				marked++;
			}
		}

		if (last_hash != UINT_MAX)
			pthread_spin_unlock(&g_page_state.buckets[last_hash].lock);
	}

	pr_info("Marked %lu COPIED/DISCARDED pages as DIRTY for re-receive\n", marked);
}

void page_state_print_stats(void)
{
	int i, j;
	unsigned long state_counts[CLONE_PAGE_STATE_MAX] = {0};
	unsigned long total_pages, illegal_trans;
	unsigned long transitions[CLONE_PAGE_STATE_MAX][CLONE_PAGE_STATE_MAX];
	struct page_state_entry *entry;

	if (!g_page_state.initialized) {
		pr_info("Page state tracker not initialized\n");
		return;
	}

	/* Snapshot stats first (quick lock) */
	pthread_spin_lock(&g_page_state.stats_lock);
	total_pages = g_page_state.total_pages;
	illegal_trans = g_page_state.illegal_transitions;
	memcpy(transitions, g_page_state.transitions, sizeof(transitions));
	pthread_spin_unlock(&g_page_state.stats_lock);

	/* Suppress unused-variable warnings when pr_info is a no-op */
	(void)total_pages;
	(void)illegal_trans;

	/* Count pages in each state - lock one bucket at a time */
	for (i = 0; i < CLONE_PAGE_STATE_HASH_SIZE; i++) {
		pthread_spin_lock(&g_page_state.buckets[i].lock);
		hlist_for_each_entry(entry, &g_page_state.buckets[i].head, hash) {
			if (entry->state < CLONE_PAGE_STATE_MAX)
				state_counts[entry->state]++;
		}
		pthread_spin_unlock(&g_page_state.buckets[i].lock);
	}

	pr_info("PAGE STATE TRACKER STATS\n");
	pr_info("Total pages tracked: %lu\n", total_pages);
	pr_info("Illegal transitions: %lu\n", illegal_trans);

	pr_info("Current state counts:\n");
	for (i = 0; i < CLONE_PAGE_STATE_MAX; i++) {
		if (state_counts[i] > 0)
			pr_info("  %s: %lu\n", state_names[i], state_counts[i]);
	}

	pr_info("State transitions:\n");
	for (i = 0; i < CLONE_PAGE_STATE_MAX; i++) {
		for (j = 0; j < CLONE_PAGE_STATE_MAX; j++) {
			if (transitions[i][j] > 0) {
				pr_info("  %s -> %s: %lu\n",
					state_names[i], state_names[j],
					transitions[i][j]);
			}
		}
	}
}

/*
 * Verify all tracked pages reached terminal states (COPIED, DISCARDED, UNMAPPED).
 * Call at end of run to ensure no pages were left in intermediate states.
 * Returns 0 on success, -1 if any pages are in non-terminal states.
 */
int page_state_verify_all_terminal(void)
{
	struct page_state_entry *entry;
	int i;
	unsigned long non_terminal = 0;
	unsigned long first_bad_vaddr = 0;
	enum page_state first_bad_state = PAGE_STATE_UNKNOWN;

	if (!g_page_state.initialized)
		return 0;

	for (i = 0; i < CLONE_PAGE_STATE_HASH_SIZE; i++) {
		pthread_spin_lock(&g_page_state.buckets[i].lock);
		hlist_for_each_entry(entry, &g_page_state.buckets[i].head, hash) {
			/* Terminal states: COPIED, DISCARDED, UNMAPPED */
			if (entry->state != PAGE_STATE_COPIED &&
			    entry->state != PAGE_STATE_DISCARDED &&
			    entry->state != PAGE_STATE_UNMAPPED) {
				if (non_terminal == 0) {
					first_bad_vaddr = entry->vaddr;
					first_bad_state = entry->state;
				}
				non_terminal++;
			}
		}
		pthread_spin_unlock(&g_page_state.buckets[i].lock);
	}

	if (non_terminal > 0) {
		pr_err("BUG: %lu pages in non-terminal states!\n", non_terminal);
		pr_err("  First: vaddr=0x%lx state=%s\n",
		       first_bad_vaddr, page_state_name(first_bad_state));
		page_state_print_history(first_bad_vaddr);
		BUG();
	}

	pr_info("Page state verification passed: all %lu pages in terminal states\n",
		g_page_state.total_pages);
	return 0;
}

/*
 * Set page state with CRC tracking.
 * Call when adding page to buffer to track data fingerprint.
 * Logs if page data changed (dirty page arrived).
 */
int page_state_set_with_crc(unsigned long vaddr, enum page_state new_state,
			    const void *data)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	unsigned int hash;
	u32 new_crc;

	if (!g_page_state.initialized)
		return -1;

	new_crc = simple_crc32(data, PAGE_SIZE);

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);

	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry) {
		u32 old_crc = entry->last_crc;
		u32 old_count = entry->buffer_count;

		entry->buffer_count++;

		/* Detect dirty page overwrites */
		if (old_crc != 0 && old_crc != new_crc) {
			pr_debug("PAGE_CRC_CHANGE: 0x%lx old_crc=0x%08x new_crc=0x%08x "
			       "buffer_count=%u->%u state=%s (dirty page arrived)\n",
			       vaddr, old_crc, new_crc, old_count, entry->buffer_count,
			       page_state_name(entry->state));
		} else if (old_crc != 0 && old_crc == new_crc && old_count > 0) {
			pr_debug("PAGE_CRC_SAME: 0x%lx crc=0x%08x buffer_count=%u->%u "
			       "state=%s (same data re-buffered)\n",
			       vaddr, new_crc, old_count, entry->buffer_count,
			       page_state_name(entry->state));
		}

		entry->last_crc = new_crc;
	}

	pthread_spin_unlock(&bucket->lock);

	/* Call regular page_state_set for state transition */
	return page_state_set(vaddr, new_state);
}

/*
 * Check if CRC matches stored value before UFFDIO_COPY.
 * Returns true if CRC matches or no stored CRC.
 * Returns false if mismatch (dirty page race detected).
 * Stores the previous CRC in *stored_crc if not NULL.
 */
bool page_state_check_crc(unsigned long vaddr, const void *data, u32 *stored_crc)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	unsigned int hash;
	u32 current_crc, saved_crc = 0;
	bool match = true;

	if (!g_page_state.initialized)
		return true;

	current_crc = simple_crc32(data, PAGE_SIZE);

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);

	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry && entry->last_crc != 0) {
		saved_crc = entry->last_crc;
		if (saved_crc != current_crc) {
			pr_warn("CRC_MISMATCH_AT_COPY: 0x%lx stored=0x%08x current=0x%08x "
			       "buffer_count=%u state=%s - DATA CHANGED!\n",
			       vaddr, saved_crc, current_crc, entry->buffer_count,
			       page_state_name(entry->state));
			match = false;
		}
	}

	pthread_spin_unlock(&bucket->lock);

	if (stored_crc)
		*stored_crc = saved_crc;

	return match;
}

/*
 * Get the buffer count for a page (how many times it was buffered).
 */
u32 page_state_get_buffer_count(unsigned long vaddr)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	unsigned int hash;
	u32 count = 0;

	if (!g_page_state.initialized)
		return 0;

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);

	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry)
		count = entry->buffer_count;

	pthread_spin_unlock(&bucket->lock);

	return count;
}

/*
 * Get stored CRC for a page.
 */
u32 page_state_get_crc(unsigned long vaddr)
{
	struct page_state_entry *entry;
	struct page_state_bucket *bucket;
	unsigned int hash;
	u32 crc = 0;

	if (!g_page_state.initialized)
		return 0;

	hash = page_state_hash(vaddr);
	bucket = &g_page_state.buckets[hash];

	pthread_spin_lock(&bucket->lock);

	entry = page_state_find_in_bucket(bucket, vaddr);
	if (entry)
		crc = entry->last_crc;

	pthread_spin_unlock(&bucket->lock);

	return crc;
}

void page_state_destroy(void)
{
	struct page_state_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!g_page_state.initialized)
		return;

	/* Print final stats before destroying */
	page_state_print_stats();

	for (i = 0; i < CLONE_PAGE_STATE_HASH_SIZE; i++) {
		pthread_spin_lock(&g_page_state.buckets[i].lock);
		hlist_for_each_entry_safe(entry, tmp,
					  &g_page_state.buckets[i].head, hash) {
			hlist_del(&entry->hash);
			xfree(entry);
		}
		pthread_spin_unlock(&g_page_state.buckets[i].lock);
		pthread_spin_destroy(&g_page_state.buckets[i].lock);
	}

	xfree(g_page_state.buckets);
	g_page_state.buckets = NULL;
	g_page_state.initialized = false;

	pthread_spin_destroy(&g_page_state.stats_lock);

	pr_info("Page state tracker destroyed\n");
}

#endif /* CONFIG_PAGE_STATE_TRACKER */
