#ifndef __CR_APPARMOR_H__
#define __CR_APPARMOR_H__

int collect_aa_namespace(char *profile);
int dump_aa_namespaces(void);

/*
 * This is an operation similar to PTRACE_O_SUSPEND_SECCOMP but for apparmor,
 * done entirely from userspace. All the namespaces to be dumped should be
 * collected via collect_aa_namespaces() before calling this.
 */
int suspend_aa(void);
int unsuspend_aa(void);

bool check_aa_ns_dumping(void);

int prepare_apparmor_namespaces(void);

int render_aa_profile(char **out, const char *cur);

#endif /* __CR_APPARMOR_H__ */
