#include <stdio.h>
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>

#include "zdtmtst.h"

#define TEST_HZ	 4
#define NR_FAILS 10

int main(int argc, char **argv)
{
	unsigned long data;
	long delta;
	int fd, fail = NR_FAILS, to_pass = NR_FAILS;
	struct timeval start, end;

	test_init(argc, argv);

	fd = open("/dev/rtc", O_RDWR);
	if (fd < 0) {
		pr_perror("open");
		return 1;
	}

	if (ioctl(fd, RTC_IRQP_SET, TEST_HZ) == -1) {
		pr_perror("RTC_IRQP_SET");
		return 1;
	}

	if (ioctl(fd, RTC_PIE_ON, 0) == -1) {
		pr_perror("RTC_PIE_ON");
		return 1;
	}

	test_daemon();

	gettimeofday(&start, NULL);
	start.tv_usec += start.tv_sec * 1000000;
	while (test_go() || to_pass--) {
		if (read(fd, &data, sizeof(unsigned long)) == -1)
			return 1;
		gettimeofday(&end, NULL);
		end.tv_usec += end.tv_sec * 1000000;
		delta = end.tv_usec - start.tv_usec;
		if (labs(delta - 1000000 / TEST_HZ) > 100000) {
			pr_perror("delta = %ld", delta);
			fail--;
			if (fail == 0)
				return 1;
		}
		start = end;
	}
	pass();

	return 0;
}
