#ifndef __CR_PF_TRACKER_H__
#define __CR_PF_TRACKER_H__

/*
 * Backward compatibility header - includes both tracker headers.
 * New code should include the specific header it needs:
 *   - page-state-tracker.h for page state tracking
 *   - hung-page-tracker.h for hung page fault tracking
 */

#include "clone/page-state-tracker.h"
#include "clone/hung-page-tracker.h"

#endif /* __CR_PF_TRACKER_H__ */
