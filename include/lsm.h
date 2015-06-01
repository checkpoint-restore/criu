#ifndef __CR_LSM_H__
#define __CR_LSM_H__

#include "protobuf/inventory.pb-c.h"
#include "protobuf/creds.pb-c.h"

/*
 * Get the Lsmtype for the current host.
 */
extern Lsmtype host_lsm_type(void);

/*
 * Initilize the Lsmtype for the current host
 */
extern void kerndat_lsm(void);

/*
 * Read the LSM profile for the pstree item
 */
extern int collect_lsm_profile(pid_t, CredsEntry *);

/*
 * Validate that the LSM profiles can be correctly applied (must happen after
 * pstree is set up).
 */
int validate_lsm(CredsEntry *ce);

/*
 * Render the profile name in the way that the LSM wants it written to
 * /proc/<pid>/attr/current.
 */
int render_lsm_profile(char *profile, char **val);

#endif /* __CR_LSM_H__ */
