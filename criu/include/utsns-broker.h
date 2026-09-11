#ifndef __CR_UTSNS_BROKER_H__
#define __CR_UTSNS_BROKER_H__

/*
 * One-shot helper for sethostname(2)/setdomainname(2) when the direct sysctl
 * restore path is not permitted. The child enters the target user and UTS
 * namespaces, then applies hostname/domainname values from the checkpoint
 * image.
 */

extern int utsns_broker_set_hostname(int pid, const char *nodename,
				     const char *domainname);

#endif /* __CR_UTSNS_BROKER_H__ */
