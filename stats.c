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

static struct timing timings[TIME_NR_STATS];

static unsigned long counts[CNT_NR_STATS];

void cnt_add(int c, unsigned long val)
{
	BUG_ON(c >= CNT_NR_STATS);
	counts[c] += val;
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
	BUG_ON(t >= TIME_NR_STATS);
	gettimeofday(&timings[t].start, NULL);
}

void timing_stop(int t)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	timeval_accumulate(&timings[t].start, &now, &timings[t].total);
}

void show_stats(int fd)
{
	do_pb_show_plain(fd, PB_STATS, 1, NULL,
			"1.1:%u 1.2:%u 1.3:%u 1.4:%u 1.5:%Lu 1.6:%Lu 1.7:%Lu");
}

static void encode_time(int t, u_int32_t *to)
{
	*to = timings[t].total.tv_sec * USEC_PER_SEC + timings[t].total.tv_usec;
}

void write_stats(int what)
{
	StatsEntry stats = STATS_ENTRY__INIT;
	DumpStatsEntry dstats = DUMP_STATS_ENTRY__INIT;
	char *name;
	int fd;

	pr_info("Writing stats\n");
	if (what == DUMP_STATS) {
		stats.dump = &dstats;

		encode_time(TIME_FREEZING, &dstats.freezing_time);
		encode_time(TIME_FROZEN, &dstats.frozen_time);
		encode_time(TIME_MEMDUMP, &dstats.memdump_time);
		encode_time(TIME_MEMWRITE, &dstats.memwrite_time);

		dstats.pages_scanned = counts[CNT_PAGES_SCANNED];
		dstats.pages_skipped_parent = counts[CNT_PAGES_SKIPPED_PARENT];
		dstats.pages_written = counts[CNT_PAGES_WRITTEN];

		name = "dump";
	} else
		return;

	fd = open_image(CR_FD_STATS, O_DUMP, name);
	if (fd >= 0) {
		pb_write_one(fd, &stats, PB_STATS);
		close(fd);
	}
}
