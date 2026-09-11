#ifndef __CR_MNTNS_BROKER_H__
#define __CR_MNTNS_BROKER_H__

/*
 * One-shot helper for mount(2)/umount2(2) when the restore task cannot run the
 * operation directly. The child enters the target user and mount namespaces,
 * sets target-namespace creds, and passes mount options through unchanged.
 */

extern int mntns_broker_mount(int pid, const char *src, const char *target,
			      const char *fstype, unsigned long flags,
			      const char *data);

#endif /* __CR_MNTNS_BROKER_H__ */
