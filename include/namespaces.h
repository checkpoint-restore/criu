#ifndef __CR_NS_H__
#define __CR_NS_H__
int dump_namespaces(int pid, unsigned int ns_flags);
int prepare_namespace(int pid, unsigned long clone_flags);
int try_show_namespaces(int pid);
int switch_ns(int pid, int type, char *ns);
#endif
