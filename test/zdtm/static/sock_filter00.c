#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <linux/in.h>

#include "zdtmtst.h"

const char *test_doc = "Check socket filter";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

#ifndef SO_GET_FILTER
#define SO_GET_FILTER SO_ATTACH_FILTER
#endif

#ifdef SOCK_FILTER01
#define SFLEN 4
#else
#define SFLEN 14
#endif

int main(int argc, char **argv)
{
	int sk;
	struct sock_fprog p;
#ifdef SOCK_FILTER01
	struct sock_filter f[SFLEN] = {
		{ 0x6, 0, 0, 0x0000ffff },
		{ 0x6, 0, 0, 0x0000ffff },
		{ 0x6, 0, 0, 0x0000ffff },
		{ 0x6, 0, 0, 0x0000ffff },
	};
#else
	struct sock_filter f[SFLEN] = {
		{ 0x28, 0, 0, 0x0000000c }, { 0x15, 0, 4, 0x00000800 }, { 0x20, 0, 0, 0x0000001a },
		{ 0x15, 8, 0, 0x7f000001 }, { 0x20, 0, 0, 0x0000001e }, { 0x15, 6, 7, 0x7f000001 },
		{ 0x15, 1, 0, 0x00000806 }, { 0x15, 0, 5, 0x00008035 }, { 0x20, 0, 0, 0x0000001c },
		{ 0x15, 2, 0, 0x7f000001 }, { 0x20, 0, 0, 0x00000026 }, { 0x15, 0, 1, 0x7f000001 },
		{ 0x6, 0, 0, 0x0000ffff },  { 0x6, 0, 0, 0x00000000 },
	};
#endif
	struct sock_filter f2[SFLEN], f3[SFLEN];
	socklen_t len;

	test_init(argc, argv);

	sk = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sk < 0) {
		pr_perror("No socket");
		return 1;
	}

	p.len = SFLEN;
	p.filter = f;

	if (setsockopt(sk, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p))) {
		pr_perror("No filter");
		return 1;
	}

	len = 0;
	if (getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, NULL, &len)) {
		pr_perror("No len");
		return 1;
	}

	if (len != SFLEN) {
		pr_perror("Len mismatch");
		return 1;
	}

	memset(f2, 0, sizeof(f2));
	if (getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, f2, &len)) {
		perror("No filter");
		return 1;
	}

	if (len != SFLEN) {
		pr_perror("Len mismatch2");
		return 1;
	}

	test_daemon();
	test_waitsig();

	len = 0;
	if (getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, NULL, &len)) {
		fail("No len");
		return 1;
	}

	if (len != SFLEN) {
		fail("Len mismatch");
		return 1;
	}

	memset(f3, 0, sizeof(f3));
	if (getsockopt(sk, SOL_SOCKET, SO_GET_FILTER, f3, &len)) {
		fail("No filter");
		return 1;
	}

	if (len != SFLEN) {
		fail("Len mismatch2");
		return 1;
	}

	if (memcmp(f2, f3, sizeof(f2))) {
		fail("Filters mismatch");
		return 1;
	}

	pass();

	return 0;
}
