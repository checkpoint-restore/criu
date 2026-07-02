#include "clone/hung-page-tracker.h"

#ifdef CONFIG_HUNG_PAGE_TRACKER

#include <time.h>
#include <pthread.h>

#include "criu-log.h"
#include "xmalloc.h"
#include "common/list.h"

#undef LOG_PREFIX
#define LOG_PREFIX "hung-pf: "

/*
 * Hung page (page fault) tracker implementation.
 * Tracks pending page faults and their age to identify stuck requests.
 * Thread-safe: uses a hash table with per-bucket spinlocks.
 */

#define PF_TRACKER_HASH_BITS 12
#define PF_TRACKER_HASH_SIZE (1 << PF_TRACKER_HASH_BITS)

struct pf_tracker_entry {
	struct hlist_node hash;
	unsigned long long address;
	unsigned long nr_pages;
	int pid;
	enum pf_state state;
	struct timespec created;
	bool is_pf; /* true = page fault, false = background xfer */
};

struct pf_tracker_bucket {
	struct hlist_head head;
	pthread_spinlock_t lock;
};

static struct {
	struct pf_tracker_bucket *buckets;
	bool initialized;
} g_pf_tracker = { .initialized = false };

static inline unsigned int pf_tracker_hash(unsigned long long address)
{
	/* Hash based on page-aligned address */
	return (address >> 12) & (PF_TRACKER_HASH_SIZE - 1);
}

int pf_tracker_init(void)
{
	int i;

	if (g_pf_tracker.initialized)
		return 0;

	g_pf_tracker.buckets = xmalloc(PF_TRACKER_HASH_SIZE *
				       sizeof(struct pf_tracker_bucket));
	if (!g_pf_tracker.buckets)
		return -1;

	for (i = 0; i < PF_TRACKER_HASH_SIZE; i++) {
		INIT_HLIST_HEAD(&g_pf_tracker.buckets[i].head);
		pthread_spin_init(&g_pf_tracker.buckets[i].lock,
				  PTHREAD_PROCESS_PRIVATE);
	}

	g_pf_tracker.initialized = true;
	pr_info("Hung page tracker initialized (hash size=%d)\n",
		PF_TRACKER_HASH_SIZE);
	return 0;
}

void pf_tracker_destroy(void)
{
	struct pf_tracker_entry *entry;
	struct hlist_node *tmp;
	int i;

	if (!g_pf_tracker.initialized)
		return;

	for (i = 0; i < PF_TRACKER_HASH_SIZE; i++) {
		pthread_spin_lock(&g_pf_tracker.buckets[i].lock);
		hlist_for_each_entry_safe(entry, tmp,
					  &g_pf_tracker.buckets[i].head, hash) {
			hlist_del(&entry->hash);
			xfree(entry);
		}
		pthread_spin_unlock(&g_pf_tracker.buckets[i].lock);
		pthread_spin_destroy(&g_pf_tracker.buckets[i].lock);
	}

	xfree(g_pf_tracker.buckets);
	g_pf_tracker.buckets = NULL;
	g_pf_tracker.initialized = false;
	pr_info("Hung page tracker destroyed\n");
}

/* Must be called with bucket lock held */
static struct pf_tracker_entry *pf_tracker_find_locked(struct pf_tracker_bucket *bucket,
						       unsigned long long address)
{
	struct pf_tracker_entry *entry;

	hlist_for_each_entry(entry, &bucket->head, hash) {
		if (entry->address == address && entry->state != PF_STATE_COMPLETED)
			return entry;
	}

	return NULL;
}

void pf_tracker_add(unsigned long long address, unsigned long nr_pages, int pid, bool is_pf)
{
	struct pf_tracker_entry *entry;
	struct pf_tracker_bucket *bucket;
	unsigned int hash;

	if (!g_pf_tracker.initialized)
		return;

	entry = xmalloc(sizeof(*entry));
	if (!entry) {
		pr_err("Failed to allocate pf_tracker_entry\n");
		return;
	}

	entry->address = address;
	entry->nr_pages = nr_pages;
	entry->pid = pid;
	entry->state = PF_STATE_PENDING_SERVER;
	entry->is_pf = is_pf;
	clock_gettime(CLOCK_MONOTONIC, &entry->created);
	INIT_HLIST_NODE(&entry->hash);

	hash = pf_tracker_hash(address);
	bucket = &g_pf_tracker.buckets[hash];

	pthread_spin_lock(&bucket->lock);
	hlist_add_head(&entry->hash, &bucket->head);
	pthread_spin_unlock(&bucket->lock);
}

void pf_tracker_set_state(unsigned long long address, enum pf_state state)
{
	struct pf_tracker_entry *entry;
	struct pf_tracker_bucket *bucket;
	unsigned int hash;

	if (!g_pf_tracker.initialized)
		return;

	hash = pf_tracker_hash(address);
	bucket = &g_pf_tracker.buckets[hash];

	pthread_spin_lock(&bucket->lock);
	entry = pf_tracker_find_locked(bucket, address);
	if (!entry) {
		pthread_spin_unlock(&bucket->lock);
		if (state == PF_STATE_COMPLETED)
			pr_debug("PF_TRACKER: UFFDIO_COPY succeeded for untracked address 0x%llx\n",
				(unsigned long long)address);
		return;
	}

	entry->state = state;
	pthread_spin_unlock(&bucket->lock);
}

void pf_tracker_print_stats(void)
{
	struct pf_tracker_entry *pft;
	struct hlist_node *tmp;
	unsigned long pending_server = 0, pending_eagain = 0;
	unsigned long completed = 0;
	unsigned long oldest_server_ms = 0, oldest_eagain_ms = 0;
	struct timespec ts_now;
	int i;

	if (!g_pf_tracker.initialized)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts_now);

	/* First pass: gather statistics */
	for (i = 0; i < PF_TRACKER_HASH_SIZE; i++) {
		pthread_spin_lock(&g_pf_tracker.buckets[i].lock);
		hlist_for_each_entry(pft, &g_pf_tracker.buckets[i].head, hash) {
			unsigned long age_ms = (ts_now.tv_sec - pft->created.tv_sec) * 1000 +
				(ts_now.tv_nsec - pft->created.tv_nsec) / 1000000;

			switch (pft->state) {
			case PF_STATE_PENDING_SERVER:
				pending_server++;
				if (age_ms > oldest_server_ms)
					oldest_server_ms = age_ms;
				break;
			case PF_STATE_PENDING_EAGAIN:
				pending_eagain++;
				if (age_ms > oldest_eagain_ms)
					oldest_eagain_ms = age_ms;
				break;
			case PF_STATE_COMPLETED:
				completed++;
				break;
			}
		}
		pthread_spin_unlock(&g_pf_tracker.buckets[i].lock);
	}

	if (pending_server > 0 || pending_eagain > 0) {
		pr_debug("  PF_TRACKER: pending_server=%lu (oldest=%lu ms) pending_eagain=%lu (oldest=%lu ms) completed=%lu\n",
			pending_server, oldest_server_ms,
			pending_eagain, oldest_eagain_ms,
			completed);

		/* Print details of long-hung entries (>2 seconds) */
		for (i = 0; i < PF_TRACKER_HASH_SIZE; i++) {
			pthread_spin_lock(&g_pf_tracker.buckets[i].lock);
			hlist_for_each_entry(pft, &g_pf_tracker.buckets[i].head, hash) {
				unsigned long age_ms = (ts_now.tv_sec - pft->created.tv_sec) * 1000 +
					(ts_now.tv_nsec - pft->created.tv_nsec) / 1000000;

				if (age_ms > 2000 && pft->state != PF_STATE_COMPLETED) {
					pr_warn("    HUNG: pid=%d addr=0x%llx pages=%lu state=%s age=%lu ms %s\n",
						pft->pid, pft->address, pft->nr_pages,
						pft->state == PF_STATE_PENDING_SERVER ? "PENDING_SERVER" : "PENDING_EAGAIN",
						age_ms,
						pft->is_pf ? "PF" : "BG");
				}
			}
			pthread_spin_unlock(&g_pf_tracker.buckets[i].lock);
		}
	}

	/* Clean up completed entries */
	for (i = 0; i < PF_TRACKER_HASH_SIZE; i++) {
		pthread_spin_lock(&g_pf_tracker.buckets[i].lock);
		hlist_for_each_entry_safe(pft, tmp, &g_pf_tracker.buckets[i].head, hash) {
			if (pft->state == PF_STATE_COMPLETED) {
				hlist_del(&pft->hash);
				xfree(pft);
			}
		}
		pthread_spin_unlock(&g_pf_tracker.buckets[i].lock);
	}
}

#endif /* CONFIG_HUNG_PAGE_TRACKER */
