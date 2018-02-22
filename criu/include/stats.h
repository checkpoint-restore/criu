#ifndef __CR_STATS_H__
#define __CR_STATS_H__

#include "images/stats.pb-c.h"

enum {
	TIME_FREEZING,
	TIME_FROZEN,
	TIME_MEMDUMP,
	TIME_MEMWRITE,
	TIME_IRMAP_RESOLVE,
	TIME_DUMP_UPTIME,

	DUMP_TIME_NR_STATS,
};

enum {
	TIME_FORK,
	TIME_RESTORE,

	RESTORE_TIME_NS_STATS,
};

extern void timing_start(int t);
extern void timing_stop(int t);
extern int timing_uptime(int t);

extern StatsEntry *get_parent_stats(void);

enum {
	CNT_PAGES_SCANNED,
	CNT_PAGES_SKIPPED_PARENT,
	CNT_PAGES_WRITTEN,
	CNT_PAGES_LAZY,
	CNT_PAGE_PIPES,
	CNT_PAGE_PIPE_BUFS,

	DUMP_CNT_NR_STATS,
};

enum {
	CNT_PAGES_COMPARED,
	CNT_PAGES_SKIPPED_COW,
	CNT_PAGES_RESTORED,

	RESTORE_CNT_NR_STATS,
};

extern void cnt_add(int c, unsigned long val);

#define DUMP_STATS	1
#define RESTORE_STATS	2

extern int init_stats(int what);
extern void write_stats(int what);

#endif /* __CR_STATS_H__ */
