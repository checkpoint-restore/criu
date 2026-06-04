#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc = "Check SO_SNDTIMEO and SO_RCVTIMEO socket options";
const char *test_author = "Rocker Zhang <zhang.rocker.liyuan@gmail.com>";

/*
 * Whole-second timeouts are used on purpose. The kernel stores
 * SO_SNDTIMEO/SO_RCVTIMEO with jiffy granularity, so setsockopt() may
 * round a sub-second tv_usec to the nearest tick depending on HZ. Such a
 * value would still survive checkpoint/restore (CRIU saves and restores
 * whatever the kernel reports), but a literal sub-second expectation in
 * this test could fail to match the rounded value. Whole seconds avoid
 * that ambiguity. Distinct send/receive values catch a possible mix-up
 * between the two options.
 */
static int check_timeo(int sk, int opt, const char *name, const struct timeval *want)
{
	struct timeval got = { 0, 0 };
	socklen_t optlen = sizeof(got);

	if (getsockopt(sk, SOL_SOCKET, opt, &got, &optlen) < 0) {
		pr_perror("getsockopt %s", name);
		return -1;
	}

	if (got.tv_sec != want->tv_sec || got.tv_usec != want->tv_usec) {
		fail("%s has incorrect value (%ld.%06ld != %ld.%06ld)", name, (long)got.tv_sec, (long)got.tv_usec,
		     (long)want->tv_sec, (long)want->tv_usec);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int sk;
	struct timeval sndtimeo = { 7, 0 }, rcvtimeo = { 11, 0 };

	test_init(argc, argv);

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create socket");
		return 1;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, &sndtimeo, sizeof(sndtimeo)) < 0) {
		pr_perror("setsockopt SO_SNDTIMEO");
		return 1;
	}

	if (setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &rcvtimeo, sizeof(rcvtimeo)) < 0) {
		pr_perror("setsockopt SO_RCVTIMEO");
		return 1;
	}

	test_daemon();
	test_waitsig();

	if (check_timeo(sk, SO_SNDTIMEO, "SO_SNDTIMEO", &sndtimeo))
		return 1;

	if (check_timeo(sk, SO_RCVTIMEO, "SO_RCVTIMEO", &rcvtimeo))
		return 1;

	pass();
	return 0;
}
