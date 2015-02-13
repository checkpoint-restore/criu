/*
    This file defines types and macros for CRIU plugins.
    Copyright (C) 2013 Parallels, Inc

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __CRIU_LOG_H__
#define __CRIU_LOG_H__

#ifndef CR_NOGLIBC

#include <string.h>
#include <errno.h>

#endif /* CR_NOGLIBC */

#define LOG_UNSET	(-1)
#define LOG_MSG		(0) /* Print message regardless of log level */
#define LOG_ERROR	(1) /* Errors only, when we're in trouble */
#define LOG_WARN	(2) /* Warnings, dazen and confused but trying to continue */
#define LOG_INFO	(3) /* Informative, everything is fine */
#define LOG_DEBUG	(4) /* Debug only */

extern void print_on_level(unsigned int loglevel, const char *format, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

#ifndef LOG_PREFIX
# define LOG_PREFIX
#endif

#define pr_msg(fmt, ...)						\
	print_on_level(LOG_MSG,						\
		       fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...)						\
	print_on_level(LOG_INFO,					\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#define pr_err(fmt, ...)						\
	print_on_level(LOG_ERROR,					\
		       "Error (%s:%d): " LOG_PREFIX fmt,		\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_err_once(fmt, ...)						\
	do {								\
		static bool __printed;					\
		if (!__printed) {					\
			pr_err(fmt, ##__VA_ARGS__);			\
			__printed = 1;					\
		}							\
	} while (0)

#define pr_warn(fmt, ...)						\
	print_on_level(LOG_WARN,					\
		       "Warn  (%s:%d): " LOG_PREFIX fmt,		\
		       __FILE__, __LINE__, ##__VA_ARGS__)

#define pr_warn_once(fmt, ...)						\
	do {								\
		static bool __printed;					\
		if (!__printed) {					\
			pr_warn(fmt, ##__VA_ARGS__);			\
			__printed = 1;					\
		}							\
	} while (0)

#define pr_debug(fmt, ...)						\
	print_on_level(LOG_DEBUG,					\
		       LOG_PREFIX fmt, ##__VA_ARGS__)

#ifndef CR_NOGLIBC

#define pr_perror(fmt, ...)						\
	pr_err(fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#endif /* CR_NOGLIBC */

#endif /* __CR_LOG_LEVELS_H__ */
