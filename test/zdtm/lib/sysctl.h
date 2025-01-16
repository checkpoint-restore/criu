#ifndef __ZDTM_SYSCTL__
#define __ZDTM_SYSCTL__

extern int sysctl_read_int(const char *name, int *data);
extern int sysctl_write_int(const char *name, int val);
extern int sysctl_read_str(const char *name, char *data, size_t size);
extern int sysctl_write_str(const char *name, char *data);

#endif
