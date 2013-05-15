#ifndef __CR_STATS_H__
#define __CR_STATS_H__
void show_stats(int fd);

enum {
	TIME_FREEZING,
	TIME_FROZEN,
	TIME_MEMDUMP,
	TIME_MEMWRITE,

	TIME_NR_STATS,
};

void timing_start(int t);
void timing_stop(int t);

enum {
	CNT_PAGES_SCANNED,
	CNT_PAGES_SKIPPED_PARENT,
	CNT_PAGES_WRITTEN,

	CNT_NR_STATS,
};

void cnt_add(int c, unsigned long val);

#define DUMP_STATS	1
void write_stats(int what);

#endif
