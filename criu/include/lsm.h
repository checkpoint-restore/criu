#ifndef __CR_LSM_H__
#define __CR_LSM_H__

#include "images/inventory.pb-c.h"
#include "images/creds.pb-c.h"
#include "images/fdinfo.pb-c.h"

#define AA_SECURITYFS_PATH "/sys/kernel/security/apparmor"

/*
 * Get the Lsmtype for the current host.
 */
extern Lsmtype host_lsm_type(void);

/*
 * Initialize the Lsmtype for the current host
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
int validate_lsm(char *profile);

/*
 * Render the profile name in the way that the LSM wants it written to
 * /proc/<pid>/attr/current.
 */
int render_lsm_profile(char *profile, char **val);

extern int lsm_check_opts(void);

#ifdef CONFIG_HAS_SELINUX
int dump_xattr_security_selinux(int fd, FdinfoEntry *e);
int run_setsockcreatecon(FdinfoEntry *e);
int reset_setsockcreatecon();
#else
static inline int dump_xattr_security_selinux(int fd, FdinfoEntry *e) {
	return 0;
}
static inline int run_setsockcreatecon(FdinfoEntry *e) {
	return 0;
}
static inline int reset_setsockcreatecon() {
	return 0;
}
#endif

#endif /* __CR_LSM_H__ */
