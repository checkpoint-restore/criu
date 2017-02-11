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

#include "log.h"

struct timeval;

extern int log_init(const char *output);
extern void log_fini(void);
extern int log_init_by_pid(pid_t pid);
extern void log_closedir(void);
extern int log_keep_err(void);
extern char *log_first_err(void);

extern void log_set_fd(int fd);
extern int log_get_fd(void);

extern void log_set_loglevel(unsigned int loglevel);
extern unsigned int log_get_loglevel(void);
struct timeval;
extern void log_get_logstart(struct timeval *);

extern int write_pidfile(int pid);

#define DEFAULT_LOG_FILENAME "criu.log"

static inline int pr_quelled(unsigned int loglevel)
{
	return log_get_loglevel() < loglevel && loglevel != LOG_MSG;
}
#endif /* __CR_LOG_LEVELS_H__ */
