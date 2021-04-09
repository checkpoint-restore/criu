#ifndef __CR_APPARMOR_H__
#define __CR_APPARMOR_H__

int collect_aa_namespace(char *profile);
int dump_aa_namespaces(void);

bool check_aa_ns_dumping(void);

int prepare_apparmor_namespaces(void);

int render_aa_profile(char **out, const char *cur);

#endif /* __CR_APPARMOR_H__ */
