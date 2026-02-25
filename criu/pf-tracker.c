#include <string.h>
#include <time.h>

#include "int.h"
#include "criu-log.h"
#include "xmalloc.h"
#include "common/list.h"
#include "pf-tracker.h"

#undef LOG_PREFIX
#define LOG_PREFIX "pf-tracker: "

struct pf_tracker_entry {
	struct list_head l;
	unsigned long long address;
	unsigned long nr_pages;
	int pid;
	enum pf_state state;
	struct timespec created;
	bool is_pf; /* true = page fault, false = background xfer */
};

static LIST_HEAD(pf_tracker);

static struct pf_tracker_entry *pf_tracker_find(unsigned long long address)
{
	struct pf_tracker_entry *entry;

	list_for_each_entry(entry, &pf_tracker, l) {
		if (entry->address == address && entry->state != PF_STATE_COMPLETED)
			return entry;
	}

	return NULL;
}

void pf_tracker_add(unsigned long long address, unsigned long nr_pages, int pid, bool is_pf)
{
	struct pf_tracker_entry *entry;

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
	INIT_LIST_HEAD(&entry->l);

	list_add_tail(&entry->l, &pf_tracker);
}

void pf_tracker_set_state(unsigned long long address, enum pf_state state)
{
	struct pf_tracker_entry *entry;

	entry = pf_tracker_find(address);
	if (!entry) {
		if (state == PF_STATE_COMPLETED)
			pr_warn("PF_TRACKER: UFFDIO_COPY succeeded for untracked address 0x%llx\n",
				(unsigned long long)address);
		return;
	}

	entry->state = state;
}

void pf_tracker_print_stats(void)
{
	struct pf_tracker_entry *pft, *pft_next;
	unsigned long pending_server = 0, pending_eagain = 0;
	unsigned long completed = 0;
	unsigned long oldest_server_ms = 0, oldest_eagain_ms = 0;
	struct timespec ts_now;

	clock_gettime(CLOCK_MONOTONIC, &ts_now);

	list_for_each_entry(pft, &pf_tracker, l) {
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

	if (pending_server > 0 || pending_eagain > 0) {
		pr_err("  PF_TRACKER: pending_server=%lu (oldest=%lu ms) pending_eagain=%lu (oldest=%lu ms) completed=%lu\n",
			pending_server, oldest_server_ms,
			pending_eagain, oldest_eagain_ms,
			completed);

		/* Print details of long-hung entries (>2 seconds) */
		list_for_each_entry(pft, &pf_tracker, l) {
			unsigned long age_ms = (ts_now.tv_sec - pft->created.tv_sec) * 1000 +
				(ts_now.tv_nsec - pft->created.tv_nsec) / 1000000;

			if (age_ms > 2000 && pft->state != PF_STATE_COMPLETED) {
				pr_err("    HUNG: pid=%d addr=0x%llx pages=%lu state=%s age=%lu ms %s\n",
					pft->pid, pft->address, pft->nr_pages,
					pft->state == PF_STATE_PENDING_SERVER ? "PENDING_SERVER" : "PENDING_EAGAIN",
					age_ms,
					pft->is_pf ? "PF" : "BG");
			}
		}
	}

	/* Clean up completed entries */
	list_for_each_entry_safe(pft, pft_next, &pf_tracker, l) {
		if (pft->state == PF_STATE_COMPLETED) {
			list_del(&pft->l);
			xfree(pft);
		}
	}
}