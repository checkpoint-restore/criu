#ifndef __CR_PF_TRACKER_H__
#define __CR_PF_TRACKER_H__

#include <stdbool.h>
#include "int.h"

enum pf_state {
	PF_STATE_PENDING_SERVER,  /* Waiting for page data from server */
	PF_STATE_PENDING_EAGAIN,  /* UFFDIO_COPY got EAGAIN, queued for retry */
	PF_STATE_COMPLETED,       /* UFFDIO_COPY succeeded */
};

extern void pf_tracker_add(unsigned long long address, unsigned long nr_pages, int pid, bool is_pf);
extern void pf_tracker_set_state(unsigned long long address, enum pf_state state);
extern void pf_tracker_print_stats(void);

#endif /* __CR_PF_TRACKER_H__ */