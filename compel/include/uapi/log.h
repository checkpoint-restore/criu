#ifndef __COMPEL_UAPI_LOG_H__
#define __COMPEL_UAPI_LOG_H__

#include <stdarg.h>
#include <compel/loglevels.h>

typedef void (*compel_log_fn)(unsigned int lvl, const char *fmt, va_list parms);
extern void compel_log_init(compel_log_fn log_fn, unsigned int level);
extern void compel_relativetimestamps_init(int relative_timestamps);
extern unsigned int compel_log_get_loglevel(void);
extern int compel_get_relativetimestamps(void);

#endif
