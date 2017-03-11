#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include "int.h"
#include "atomic.h"
#include "cr_options.h"
#include "rst-malloc.h"
#include "protobuf.h"
#include "stats.h"
#include "util.h"
#include "image.h"
#include "images/stats.pb-c.h"

struct timing {
	struct timeval start;
	struct timeval total;
};

struct dump_stats {
	struct timing	timings[DUMP_TIME_NR_STATS];
	unsigned long	counts[DUMP_CNT_NR_STATS];
};

struct restore_stats {
	struct timing	timings[RESTORE_TIME_NS_STATS];
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
		atomic_add(val, &rstats->counts[c]);
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

static struct timing *get_timing(int t)
{
	if (dstats != NULL) {
		BUG_ON(t >= DUMP_TIME_NR_STATS);
		return &dstats->timings[t];
	} else if (rstats != NULL) {
		/*
		 * FIXME -- this does _NOT_ work when called
		 * from different tasks.
		 */
		BUG_ON(t >= RESTORE_TIME_NS_STATS);
		return &rstats->timings[t];
	}

	BUG();
	return NULL;
}

void timing_start(int t)
{
	struct timing *tm;

	tm = get_timing(t);
	gettimeofday(&tm->start, NULL);
}

void timing_stop(int t)
{
	struct timing *tm;
	struct timeval now;

	tm = get_timing(t);
	gettimeofday(&now, NULL);
	timeval_accumulate(&tm->start, &now, &tm->total);
}

static void encode_time(int t, u_int32_t *to)
{
	struct timing *tm;

	tm = get_timing(t);
	*to = tm->total.tv_sec * USEC_PER_SEC + tm->total.tv_usec;
}

static void display_stats(int what, StatsEntry *stats)
{
	if (what == DUMP_STATS) {
		pr_msg("Displaying dump stats:\n");
		pr_msg("Freezing time: %d us\n", stats->dump->freezing_time);
		pr_msg("Frozen time: %d us\n", stats->dump->frozen_time);
		pr_msg("Memory dump time: %d us\n", stats->dump->memdump_time);
		pr_msg("Memory write time: %d us\n", stats->dump->memwrite_time);
		if (stats->dump->has_irmap_resolve)
			pr_msg("IRMAP resolve time: %d us\n", stats->dump->irmap_resolve);
		pr_msg("Memory pages scanned: %" PRIu64 " (0x%" PRIx64 ")\n", stats->dump->pages_scanned,
				stats->dump->pages_scanned);
		pr_msg("Memory pages skipped from parent: %" PRIu64 " (0x%" PRIx64 ")\n",
				stats->dump->pages_skipped_parent,
				stats->dump->pages_skipped_parent);
		pr_msg("Memory pages written: %" PRIu64 " (0x%" PRIx64 ")\n", stats->dump->pages_written,
				stats->dump->pages_written);
		pr_msg("Lazy memory pages: %" PRIu64 " (0x%" PRIx64 ")\n", stats->dump->pages_lazy,
				stats->dump->pages_lazy);
	} else if (what == RESTORE_STATS) {
		pr_msg("Displaying restore stats:\n");
		pr_msg("Pages compared: %" PRIu64 " (0x%" PRIx64 ")\n", stats->restore->pages_compared,
				stats->restore->pages_compared);
		pr_msg("Pages skipped COW: %" PRIu64 " (0x%" PRIx64 ")\n", stats->restore->pages_skipped_cow,
				stats->restore->pages_skipped_cow);
		if (stats->restore->has_pages_restored)
			pr_msg("Pages restored: %" PRIu64 " (0x%" PRIx64 ")\n", stats->restore->pages_restored,
					stats->restore->pages_restored);
		pr_msg("Restore time: %d us\n", stats->restore->restore_time);
		pr_msg("Forking time: %d us\n", stats->restore->forking_time);
	} else
		return;
}

void write_stats(int what)
{
	StatsEntry stats = STATS_ENTRY__INIT;
	DumpStatsEntry ds_entry = DUMP_STATS_ENTRY__INIT;
	RestoreStatsEntry rs_entry = RESTORE_STATS_ENTRY__INIT;
	char *name;
	struct cr_img *img;

	pr_info("Writing stats\n");
	if (what == DUMP_STATS) {
		stats.dump = &ds_entry;

		encode_time(TIME_FREEZING, &ds_entry.freezing_time);
		encode_time(TIME_FROZEN, &ds_entry.frozen_time);
		encode_time(TIME_MEMDUMP, &ds_entry.memdump_time);
		encode_time(TIME_MEMWRITE, &ds_entry.memwrite_time);
		ds_entry.has_irmap_resolve = true;
		encode_time(TIME_IRMAP_RESOLVE, &ds_entry.irmap_resolve);

		ds_entry.pages_scanned = dstats->counts[CNT_PAGES_SCANNED];
		ds_entry.pages_skipped_parent = dstats->counts[CNT_PAGES_SKIPPED_PARENT];
		ds_entry.pages_written = dstats->counts[CNT_PAGES_WRITTEN];
		ds_entry.pages_lazy = dstats->counts[CNT_PAGES_LAZY];

		name = "dump";
	} else if (what == RESTORE_STATS) {
		stats.restore = &rs_entry;

		rs_entry.pages_compared = atomic_read(&rstats->counts[CNT_PAGES_COMPARED]);
		rs_entry.pages_skipped_cow = atomic_read(&rstats->counts[CNT_PAGES_SKIPPED_COW]);
		rs_entry.has_pages_restored = true;
		rs_entry.pages_restored = atomic_read(&rstats->counts[CNT_PAGES_RESTORED]);

		encode_time(TIME_FORK, &rs_entry.forking_time);
		encode_time(TIME_RESTORE, &rs_entry.restore_time);

		name = "restore";
	} else
		return;

	img = open_image_at(AT_FDCWD, CR_FD_STATS, O_DUMP, name);
	if (img) {
		pb_write_one(img, &stats, PB_STATS);
		close_image(img);
	}

	if (opts.display_stats)
		display_stats(what, &stats);
}

int init_stats(int what)
{
	if (what == DUMP_STATS) {
		dstats = xzalloc(sizeof(*dstats));
		return dstats ? 0 : -1;
	}

	rstats = shmalloc(sizeof(struct restore_stats));
	return rstats ? 0 : -1;
}
