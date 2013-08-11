#include <unistd.h>
#include <sys/time.h>
#include "protobuf.h"
#include "stats.h"
#include "crtools.h"
#include "protobuf/stats.pb-c.h"

struct timing {
	struct timeval start;
	struct timeval total;
};

struct dump_stats {
	struct timing	timings[DUMP_TIME_NR_STATS];
	unsigned long	counts[DUMP_CNT_NR_STATS];
};

struct restore_stats {
	atomic_t	counts[RESTORE_CNT_NR_STATS];
};

struct dump_stats *dstats;
struct restore_stats *rstats;

void cnt_add(int c, unsigned long val)
{
	if (dstats != NULL) {
		BUG_ON(c >= DUMP_CNT_NR_STATS);
		dstats->counts[c] += val;
	} else if (rstats != NULL) {
		BUG_ON(c >= RESTORE_CNT_NR_STATS);
		atomic_add(&rstats->counts[c], val);
	} else
		BUG();
}

static void timeval_accumulate(const struct timeval *from, const struct timeval *to,
		struct timeval *res)
{
	suseconds_t usec;

	res->tv_sec += to->tv_sec - from->tv_sec;
	usec = to->tv_usec;
	if (usec < from->tv_usec) {
		usec += USEC_PER_SEC;
		res->tv_sec -= 1;
	}
	res->tv_usec += usec - from->tv_usec;
	if (res->tv_usec > USEC_PER_SEC) {
		res->tv_usec -= USEC_PER_SEC;
		res->tv_sec += 1;
	}
}

void timing_start(int t)
{
	BUG_ON(t >= DUMP_TIME_NR_STATS);
	gettimeofday(&dstats->timings[t].start, NULL);
}

void timing_stop(int t)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	timeval_accumulate(&dstats->timings[t].start, &now, &dstats->timings[t].total);
}

void show_stats(int fd)
{
	do_pb_show_plain(fd, PB_STATS, 1, NULL,
			"1.1:%u 1.2:%u 1.3:%u 1.4:%u 1.5:%Lu 1.6:%Lu 1.7:%Lu");
}

static void encode_time(int t, u_int32_t *to)
{
	*to = dstats->timings[t].total.tv_sec * USEC_PER_SEC + dstats->timings[t].total.tv_usec;
}

void write_stats(int what)
{
	StatsEntry stats = STATS_ENTRY__INIT;
	DumpStatsEntry ds_entry = DUMP_STATS_ENTRY__INIT;
	RestoreStatsEntry rs_entry = RESTORE_STATS_ENTRY__INIT;
	char *name;
	int fd;

	pr_info("Writing stats\n");
	if (what == DUMP_STATS) {
		stats.dump = &ds_entry;

		encode_time(TIME_FREEZING, &ds_entry.freezing_time);
		encode_time(TIME_FROZEN, &ds_entry.frozen_time);
		encode_time(TIME_MEMDUMP, &ds_entry.memdump_time);
		encode_time(TIME_MEMWRITE, &ds_entry.memwrite_time);

		ds_entry.pages_scanned = dstats->counts[CNT_PAGES_SCANNED];
		ds_entry.pages_skipped_parent = dstats->counts[CNT_PAGES_SKIPPED_PARENT];
		ds_entry.pages_written = dstats->counts[CNT_PAGES_WRITTEN];

		name = "dump";
	} else if (what == RESTORE_STATS) {
		stats.restore = &rs_entry;

		name = "restore";
	} else
		return;

	fd = open_image(CR_FD_STATS, O_DUMP, name);
	if (fd >= 0) {
		pb_write_one(fd, &stats, PB_STATS);
		close(fd);
	}
}

int init_stats(int what)
{
	if (what == DUMP_STATS) {
		dstats = xmalloc(sizeof(*dstats));
		return dstats ? 0 : -1;
	}

	rstats = shmalloc(sizeof(struct restore_stats));
	return rstats ? 0 : -1;
}
