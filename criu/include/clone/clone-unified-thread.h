#ifndef __CR_CLONE_UNIFIED_THREAD_H__
#define __CR_CLONE_UNIFIED_THREAD_H__

#include <stdbool.h>
#include "types.h"

/*
 * CLONE unified page server thread.
 *
 * Source-side CLONE page transfer driver: starts P3 bulk sender threads
 * to transfer pages to the target.
 */

#ifdef CONFIG_HAS_LZ4

/* Page server thread functions */
extern void clone_wait_for_page_server_thread(void);
extern int clone_page_server_get_all_pages(int sk, u64 dst_id);

#else /* !CONFIG_HAS_LZ4 */

static inline void clone_wait_for_page_server_thread(void) { }
static inline int clone_page_server_get_all_pages(int sk, u64 dst_id)
{
	(void)sk; (void)dst_id;
	return -1;
}

#endif /* CONFIG_HAS_LZ4 */

#endif /* __CR_CLONE_UNIFIED_THREAD_H__ */
