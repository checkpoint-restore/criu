#include "soccr.h"

static void (*log)(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
static unsigned int log_level = 0;

void libsoccr_set_log(unsigned int level, void (*fn)(unsigned int level, const char *fmt, ...))
{
	log_level = level;
	log = fn;
}

#define loge(msg, ...) do { if (log && (log_level >= SOCCR_LOG_ERR)) log(SOCCR_LOG_ERR, msg, ##__VA_ARGS__); } while (0)
#define logd(msg, ...) do { if (log && (log_level >= SOCCR_LOG_DBG)) log(SOCCR_LOG_DBG, msg, ##__VA_ARGS__); } while (0)
