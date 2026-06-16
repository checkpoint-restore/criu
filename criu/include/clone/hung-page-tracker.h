#ifndef __CR_HUNG_PAGE_TRACKER_H__
#define __CR_HUNG_PAGE_TRACKER_H__

#include <stdbool.h>
#include "int.h"
#include "clone/clone-conf.h"  /* CONFIG_HUNG_PAGE_TRACKER */

/*
 * Hung page (page fault) tracker for debugging slow/stuck page requests.
 * Tracks pending page faults and their age to identify issues.
 */
enum pf_state {
	PF_STATE_PENDING_SERVER,  /* Waiting for page data from server */
	PF_STATE_PENDING_EAGAIN,  /* UFFDIO_COPY got EAGAIN, queued for retry */
	PF_STATE_COMPLETED,       /* UFFDIO_COPY succeeded */
};

#ifdef CONFIG_HUNG_PAGE_TRACKER

extern int pf_tracker_init(void);
extern void pf_tracker_destroy(void);
extern void pf_tracker_add(unsigned long long address, unsigned long nr_pages, int pid, bool is_pf);
extern void pf_tracker_set_state(unsigned long long address, enum pf_state state);
extern void pf_tracker_print_stats(void);

#else /* !CONFIG_HUNG_PAGE_TRACKER */

static inline int pf_tracker_init(void) { return 0; }
static inline void pf_tracker_destroy(void) { }

static inline void pf_tracker_add(unsigned long long address, unsigned long nr_pages,
				  int pid, bool is_pf)
{
	(void)address;
	(void)nr_pages;
	(void)pid;
	(void)is_pf;
}

static inline void pf_tracker_set_state(unsigned long long address, enum pf_state state)
{
	(void)address;
	(void)state;
}

static inline void pf_tracker_print_stats(void) { }

#endif /* CONFIG_HUNG_PAGE_TRACKER */

#endif /* __CR_HUNG_PAGE_TRACKER_H__ */
