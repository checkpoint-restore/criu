#ifndef __CR_STATS_H__
#define __CR_STATS_H__

enum {
	TIME_FREEZING,
	TIME_FROZEN,
	TIME_MEMDUMP,
	TIME_MEMWRITE,

	DUMP_TIME_NR_STATS,
};

enum {
	TIME_FORK,
	TIME_RESTORE,

	RESTORE_TIME_NS_STATS,
};

extern void timing_start(int t);
extern void timing_stop(int t);

enum {
	CNT_PAGES_SCANNED,
	CNT_PAGES_SKIPPED_PARENT,
	CNT_PAGES_WRITTEN,

	DUMP_CNT_NR_STATS,
};

enum {
	CNT_PAGES_COMPARED,
	CNT_PAGES_SKIPPED_COW,

	RESTORE_CNT_NR_STATS,
};

extern void cnt_add(int c, unsigned long val);

#define DUMP_STATS	1
#define RESTORE_STATS	2

extern int init_stats(int what);
extern void write_stats(int what);

#endif /* __CR_STATS_H__ */
