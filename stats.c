#include <unistd.h>
#include "protobuf.h"
#include "stats.h"

void show_stats(int fd)
{
	pb_show_vertical(fd, PB_STATS);
}
