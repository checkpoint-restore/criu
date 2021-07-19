#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <sys/timerfd.h>

#include "zdtmtst.h"

const char *test_doc = "Checks timerfd survives checkpoint/restore\n";
const char *test_author = "Cyrill Gorcunov <gorcunov@openvz.org>";

#define TIMERFD_VNSEC 50000
#define TIMERFD_ISEC  4

struct timerfd_status {
	int clockid;
	uint64_t ticks;
	int settime_flags;
	struct itimerspec v;
};

static void show_timerfd(char *prefix, struct timerfd_status *s)
{
	test_msg("\t%s clockid %d ticks %llu settime_flags %d it_value(%llu, %llu) it_interval(%llu, %llu)\n", prefix,
		 s->clockid, (unsigned long long)s->ticks, s->settime_flags, (unsigned long long)s->v.it_value.tv_sec,
		 (unsigned long long)s->v.it_value.tv_nsec, (unsigned long long)s->v.it_interval.tv_sec,
		 (unsigned long long)s->v.it_interval.tv_nsec);
}

static int parse_self_fdinfo(int fd, struct timerfd_status *s)
{
	char buf[256];
	int ret = -1;
	FILE *f;

	sprintf(buf, "/proc/self/fdinfo/%d", fd);
	f = fopen(buf, "r");
	if (!f) {
		pr_perror("Can't open %s to parse", buf);
		return -1;
	}

	memset(s, 0, sizeof(*s));

	/*
	 * clockid: 0
	 * ticks: 0
	 * settime flags: 01
	 * it_value: (0, 49406829)
	 * it_interval: (1, 0)
	 */
	while (fgets(buf, sizeof(buf), f)) {
		if (strncmp(buf, "clockid:", 8))
			continue;

		if (sscanf(buf, "clockid: %d", &s->clockid) != 1)
			goto parse_err;

		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;
		if (sscanf(buf, "ticks: %llu", (unsigned long long *)&s->ticks) != 1)
			goto parse_err;

		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;
		if (sscanf(buf, "settime flags: 0%o", &s->settime_flags) != 1)
			goto parse_err;

		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;
		if (sscanf(buf, "it_value: (%llu, %llu)", (unsigned long long *)&s->v.it_value.tv_sec,
			   (unsigned long long *)&s->v.it_value.tv_nsec) != 2)
			goto parse_err;

		if (!fgets(buf, sizeof(buf), f))
			goto parse_err;
		if (sscanf(buf, "it_interval: (%llu, %llu)", (unsigned long long *)&s->v.it_interval.tv_sec,
			   (unsigned long long *)&s->v.it_interval.tv_nsec) != 2)
			goto parse_err;

		ret = 0;
		break;
	}

	if (ret)
		goto parse_err;
err:
	fclose(f);
	return ret;

parse_err:
	pr_perror("Format error");
	goto err;
}

static int check_timerfd(int fd, struct timerfd_status *old)
{
	struct timerfd_status new;

	if (parse_self_fdinfo(fd, &new))
		return -1;
	show_timerfd("restored", &new);

	if (old->clockid != new.clockid || old->settime_flags != new.settime_flags || old->ticks > new.ticks ||
	    old->v.it_value.tv_sec > new.v.it_value.tv_sec || old->v.it_interval.tv_sec != new.v.it_interval.tv_sec)
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	struct timerfd_status old = {
		.clockid	= CLOCK_MONOTONIC,
		.ticks		= 0,
		.settime_flags	= 0,
		.v		= {
			.it_value = {
				.tv_sec	= 0,
				.tv_nsec= TIMERFD_VNSEC,
			},
			.it_interval = {
				.tv_sec	= TIMERFD_ISEC,
				.tv_nsec= 0,
			},
		},
	};
	int timerfd = 0, ret;

	test_init(argc, argv);

	timerfd = timerfd_create(old.clockid, 0);
	if (timerfd < 0) {
		pr_perror("timerfd_create failed");
		return -1;
	}

	show_timerfd("setup", &old);
	if (timerfd_settime(timerfd, old.settime_flags, &old.v, NULL)) {
		pr_perror("timerfd_settime failed");
		return -1;
	}
	sleep(1);

	test_daemon();
	test_waitsig();

	ret = check_timerfd(timerfd, &old);
	if (ret)
		fail();
	else
		pass();
	return ret;
}
