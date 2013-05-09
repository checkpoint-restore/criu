#include <unistd.h>
#include "protobuf.h"
#include "stats.h"
#include "crtools.h"
#include "protobuf/stats.pb-c.h"

void show_stats(int fd)
{
	pb_show_vertical(fd, PB_STATS);
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
		name = "dump";
	} else
		return;

	fd = open_image(CR_FD_STATS, O_DUMP, name);
	if (fd >= 0) {
		pb_write_one(fd, &stats, PB_STATS);
		close(fd);
	}
}
