#ifndef __CR_UTIL_CAPS_H__
#define __CR_UTIL_CAPS_H__

#include <sys/capability.h>

#ifndef CAP_CHECKPOINT_RESTORE
#define CAP_CHECKPOINT_RESTORE 40
#endif

static inline bool has_capability(int cap, u32 *cap_eff)
{
	int mask = CAP_TO_MASK(cap);
	int index = CAP_TO_INDEX(cap);
	u32 effective;

	effective = cap_eff[index];

	if (!(mask & effective)) {
		pr_debug("Effective capability %d missing\n", cap);
		return false;
	}

	return true;
}

static inline bool has_cap_checkpoint_restore(u32 *cap_eff)
{
	/*
	 * Everything guarded by CAP_CHECKPOINT_RESTORE is also
	 * guarded by CAP_SYS_ADMIN. Check for both capabilities.
	 */
	if (has_capability(CAP_CHECKPOINT_RESTORE, cap_eff) || has_capability(CAP_SYS_ADMIN, cap_eff))
		return true;

	return false;
}

static inline bool has_cap_net_admin(u32 *cap_eff)
{
	return has_capability(CAP_NET_ADMIN, cap_eff);
}

static inline bool has_cap_sys_chroot(u32 *cap_eff)
{
	return has_capability(CAP_SYS_CHROOT, cap_eff);
}

static inline bool has_cap_setuid(u32 *cap_eff)
{
	return has_capability(CAP_SETUID, cap_eff);
}

static inline bool has_cap_sys_resource(u32 *cap_eff)
{
	return has_capability(CAP_SYS_RESOURCE, cap_eff);
}

#endif /* __CR_UTIL_CAPS_H__ */
