#ifndef __CR_USERNS_BROKER_H__
#define __CR_USERNS_BROKER_H__

/*
 * Enter the target process user namespace (userns-first broker step).
 * EINVAL from setns(CLONE_NEWUSER) is accepted only after comparing the
 * current and requested namespace identities.
 */

extern int userns_broker_drop_groups(const char *broker_name, const char *op_name);
extern int userns_broker_enter_creds(const char *broker_name, const char *op_name);
extern int userns_broker_enter(int pid, const char *op_name);

#endif /* __CR_USERNS_BROKER_H__ */
