#ifndef UAPI_COMPEL_LOGLEVELS_H__
#define UAPI_COMPEL_LOGLEVELS_H__

/*
 * Log levels used by compel itself (see compel_log_init()),
 * also by log functions in the std plugin.
 */

enum __compel_log_levels
{
	COMPEL_LOG_MSG,		/* Print message regardless of log level */
	COMPEL_LOG_ERROR,	/* Errors only, when we're in trouble */
	COMPEL_LOG_WARN,	/* Warnings */
	COMPEL_LOG_INFO,	/* Informative, everything is fine */
	COMPEL_LOG_DEBUG,	/* Debug only */

	COMPEL_DEFAULT_LOGLEVEL	= COMPEL_LOG_WARN
};

#endif /* UAPI_COMPEL_LOGLEVELS_H__ */
