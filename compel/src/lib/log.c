#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

static unsigned int current_loglevel = COMPEL_DEFAULT_LOGLEVEL;
static compel_log_fn logfn;

void compel_log_init(compel_log_fn log_fn, unsigned int level)
{
	logfn = log_fn;
	current_loglevel = level;
}

unsigned int compel_log_get_loglevel(void)
{
	return current_loglevel;
}

void compel_print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;
	compel_log_fn fn = logfn;

	if (fn != NULL && !pr_quelled(loglevel)) {
		va_start(params, format);
		fn(loglevel, format, params);
		va_end(params);
	}
}
