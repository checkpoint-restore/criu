#include <time.h>
#include <sched.h>

#include "types.h"
#include "proc_parse.h"
#include "namespaces.h"
#include "timens.h"
#include "cr_options.h"

#include "protobuf.h"
#include "images/timens.pb-c.h"

int dump_time_ns(int ns_id)
{
	struct cr_img *img;
	TimensEntry te = TIMENS_ENTRY__INIT;
	Timespec b = TIMESPEC__INIT, m = TIMESPEC__INIT;
	struct timespec ts;
	int ret;

	img = open_image(CR_FD_TIMENS, O_DUMP, ns_id);
	if (!img)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	te.monotonic = &m;
	te.monotonic->tv_sec = ts.tv_sec;
	te.monotonic->tv_nsec = ts.tv_nsec;
	clock_gettime(CLOCK_BOOTTIME, &ts);
	te.boottime = &b;
	te.boottime->tv_sec = ts.tv_sec;
	te.boottime->tv_nsec = ts.tv_nsec;

	ret = pb_write_one(img, &te, PB_TIMENS);
	close_image(img);

	return ret < 0 ? -1 : 0;
}

static void normalize_timespec(struct timespec *ts)
{
	while (ts->tv_nsec >= NSEC_PER_SEC) {
		ts->tv_nsec -= NSEC_PER_SEC;
		++ts->tv_sec;
	}
	while (ts->tv_nsec < 0) {
		ts->tv_nsec += NSEC_PER_SEC;
		--ts->tv_sec;
	}
}

int prepare_timens(int id)
{
	int exit_code = -1;
	int ret, fd = -1;
	struct cr_img *img;
	TimensEntry *te;
	struct timespec ts;
	struct timespec prev_moff = {}, prev_boff = {};

	if (opts.unprivileged)
		return 0;

	img = open_image(CR_FD_TIMENS, O_RSTR, id);
	if (!img)
		return -1;

	if (id == 0 && empty_image(img)) {
		pr_warn("Clocks values have not been dumped\n");
		close_image(img);
		return 0;
	}

	ret = pb_read_one(img, &te, PB_TIMENS);
	close_image(img);
	if (ret < 0)
		goto err;

	if (unshare(CLONE_NEWTIME)) {
		pr_perror("Unable to create a new time namespace");
		return -1;
	}

	if (parse_timens_offsets(&prev_boff, &prev_moff))
		goto err;

	fd = open_proc_rw(PROC_SELF, "timens_offsets");
	if (fd < 0)
		goto err;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec = ts.tv_sec - prev_moff.tv_sec;
	ts.tv_nsec = ts.tv_nsec - prev_moff.tv_nsec;

	ts.tv_sec = te->monotonic->tv_sec - ts.tv_sec;
	ts.tv_nsec = te->monotonic->tv_nsec - ts.tv_nsec;
	normalize_timespec(&ts);

	pr_debug("timens: monotonic %" PRId64 " %ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);
	if (dprintf(fd, "%d %" PRId64 " %ld\n", CLOCK_MONOTONIC, (int64_t)ts.tv_sec, ts.tv_nsec) < 0) {
		pr_perror("Unable to set a monotonic clock offset");
		goto err;
	}

	clock_gettime(CLOCK_BOOTTIME, &ts);

	ts.tv_sec = ts.tv_sec - prev_boff.tv_sec;
	ts.tv_nsec = ts.tv_nsec - prev_boff.tv_nsec;

	ts.tv_sec = te->boottime->tv_sec - ts.tv_sec;
	ts.tv_nsec = te->boottime->tv_nsec - ts.tv_nsec;
	normalize_timespec(&ts);

	pr_debug("timens: boottime %" PRId64 " %ld\n", (int64_t)ts.tv_sec, ts.tv_nsec);
	if (dprintf(fd, "%d %" PRId64 " %ld\n", CLOCK_BOOTTIME, (int64_t)ts.tv_sec, ts.tv_nsec) < 0) {
		pr_perror("Unable to set a boottime clock offset");
		goto err;
	}

	timens_entry__free_unpacked(te, NULL);
	close_safe(&fd);

	fd = open_proc(PROC_SELF, "ns/time_for_children");
	if (fd < 0) {
		pr_perror("Unable to open ns/time_for_children");
		goto err;
	}
	if (switch_ns_by_fd(fd, &time_ns_desc, NULL))
		goto err;
	exit_code = 0;
err:
	close_safe(&fd);
	return exit_code;
}
struct ns_desc time_ns_desc = NS_DESC_ENTRY(CLONE_NEWTIME, "time");
struct ns_desc time_for_children_ns_desc = NS_DESC_ENTRY(CLONE_NEWTIME, "time_for_children");
