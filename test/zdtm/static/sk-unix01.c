#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that deleted unix sockets with dirs are restored correctly";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

static int sk_alloc_bind(int type, struct sockaddr_un *addr)
{
	int sk;

	sk = socket(PF_UNIX, type, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	if (addr && bind(sk, (const struct sockaddr *)addr, sizeof(*addr))) {
		pr_perror("bind %s", addr->sun_path);
		close(sk);
		return -1;
	}

	return sk;
}

static int sk_alloc_connect(int type, struct sockaddr_un *addr)
{
	int sk;

	sk = socket(PF_UNIX, type, 0);
	if (sk < 0) {
		pr_perror("socket");
		return -1;
	}

	if (connect(sk, (const struct sockaddr *)addr, sizeof(*addr))) {
		pr_perror("connect %s", addr->sun_path);
		close(sk);
		return -1;
	}

	return sk;
}

#define write_int(__f, __p)					\
	({							\
		ssize_t __r = write(__f, __p, sizeof(*(__p)));	\
		(__r == sizeof(*(__p))) ? 0 : -1;		\
	})

#define read_int(__f, __p)					\
	({							\
		ssize_t __r = read(__f, __p, sizeof(*(__p)));	\
		(__r == sizeof(*(__p))) ? 0 : -1;		\
	})

int main(int argc, char **argv)
{
	int c1 = 1, c2 = 0, c3 = 3, c4 = 0;
	int c5 = 5, c6 = 0, c7 = 7, c8 = 0;
	int c9 = 8, c10 = 0;
	char filename[PATH_MAX];
	char subdir_dg[PATH_MAX];
	char subdir_st[PATH_MAX];
	struct sockaddr_un addr_from;
	struct sockaddr_un addr;
	int sk_dgram_pair[2];
	int sk_dgram[9];
	socklen_t len;
	int sk_st[5];
	DIR *dir;

	test_init(argc, argv);

	/*
	 * All sockets are under dir to not clash
	 * with other tests.
	 */
	if (mkdir(dirname, 0755) < 0) {
		if (errno != EEXIST) {
			pr_perror("Can't create %s", dirname);
			return 1;
		}
	}

	/*
	 * Subdir for dgram sockets.
	 */
	ssprintf(subdir_dg, "%s/%s", dirname, "dg");
	if (mkdir(subdir_dg, 0755) < 0) {
		if (errno != EEXIST) {
			pr_perror("Can't create %s", subdir_dg);
			return 1;
		}
	}

	/*
	 * Subdir for stream sockets.
	 */
	ssprintf(subdir_st, "%s/%s", dirname, "st");
	if (mkdir(subdir_st, 0755) < 0) {
		if (errno != EEXIST) {
			pr_perror("Can't create %s", subdir_st);
			return 1;
		}
	}

	/*
	 * DGRAM sockets
	 *
	 *  - create 2 sockets
	 *  - bind first to subdired
	 *  - connect second to it
	 *  - delete socket on fs
	 *  - do the same for second pair with same name
	 *  - delete socket on fs
	 *  - create 3 more sockets
	 *  - bind /connect to same name, where one is deleted
	 */

	ssprintf(filename, "%s/%s", subdir_dg, "sk-dt");
	if (unix_fill_sock_name(&addr, filename))
		return 1;

	unlink(addr.sun_path);

	sk_dgram[0] = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk_dgram[0] < 0)
		return 1;
	test_msg("sk-dt: alloc/bind %d %s\n", sk_dgram[0], addr.sun_path);

	sk_dgram[1] = sk_alloc_connect(SOCK_DGRAM, &addr);
	if (sk_dgram[1] < 0)
		return 1;
	unlink(addr.sun_path);
	test_msg("sk-dt: alloc/connect/unlink %d %s\n", sk_dgram[1], addr.sun_path);

	sk_dgram[2] = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk_dgram[2] < 0)
		return 1;
	test_msg("sk-dt: alloc/bind %d %s\n", sk_dgram[2], addr.sun_path);

	sk_dgram[3] = sk_alloc_connect(SOCK_DGRAM, &addr);
	if (sk_dgram[3] < 0)
		return 1;
	unlink(addr.sun_path);
	test_msg("sk-dt: alloc/connect/unlink %d %s\n", sk_dgram[3], addr.sun_path);

	ssprintf(filename, "%s/%s", dirname, "sole");
	if (unix_fill_sock_name(&addr, filename))
		return 1;

	unlink(addr.sun_path);

	sk_dgram[4] = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk_dgram[4] < 0)
		return 1;
	test_msg("sk-dt: alloc/bind %d %s\n", sk_dgram[4], addr.sun_path);

	sk_dgram[5] = sk_alloc_connect(SOCK_DGRAM, &addr);
	if (sk_dgram[5] < 0)
		return 1;
	unlink(addr.sun_path);
	test_msg("sk-dt: alloc/connect/unlink %d %s\n", sk_dgram[5], addr.sun_path);

	sk_dgram[6] = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk_dgram[6] < 0)
		return 1;
	test_msg("sk-dt: alloc/bind %d %s\n", sk_dgram[6], addr.sun_path);

	sk_dgram[7] = sk_alloc_connect(SOCK_DGRAM, &addr);
	if (sk_dgram[7] < 0)
		return 1;
	unlink(addr.sun_path);
	test_msg("sk-dt: alloc/connect/unlink %d %s\n", sk_dgram[7], addr.sun_path);

	sk_dgram[8] = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk_dgram[8] < 0)
		return 1;
	test_msg("sk-dt: alloc/bind %d %s\n", sk_dgram[8], addr.sun_path);

	if (dup2(sk_dgram[4], 110) < 0 || dup2(sk_dgram[6], 100) < 0) {
		pr_perror("Can't move socket");
		return 1;
	}
	close(sk_dgram[4]);
	sk_dgram[4] = 110;
	close(sk_dgram[6]);
	sk_dgram[6] = 100;

	/*
	 * DGRAM paired sockets. Just bind both to the same name.
	 */
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sk_dgram_pair)) {
		pr_perror("Can't create dgram pair");
		return 1;
	}
	test_msg("sk-dgp: sockpair %d %d\n",
		 sk_dgram_pair[0], sk_dgram_pair[1]);
	ssprintf(filename, "%s/%s", subdir_dg, "sk-dtp");

	if (unix_fill_sock_name(&addr, filename)) {
		pr_err("%s is too long for socket\n", filename);
		return 1;
	}

	if (bind(sk_dgram_pair[0], (const struct sockaddr *)&addr, sizeof(addr))) {
		pr_perror("bind %d to %s", sk_dgram_pair[0], addr.sun_path);
		return -1;
	}
	unlink(addr.sun_path);
	if (bind(sk_dgram_pair[1], (const struct sockaddr *)&addr, sizeof(addr))) {
		pr_perror("bind %d to %s", sk_dgram_pair[1], addr.sun_path);
		return -1;
	}
	unlink(addr.sun_path);

	/*
	 * Drop subdirectory.
	 */
	rmdir(subdir_dg);

	/*
	 * STREAM sockets
	 *
	 *  - create server, bind to subdired
	 *  - create client
	 *  - connect to server
	 *  - delete socket on fs
	 *  - bind again to subdired
	 *  - connect to server
	 *  - delete socket on fs
	 */
	ssprintf(filename, "%s/%s", subdir_st, "sk-st");
	if (unix_fill_sock_name(&addr, filename))
		return 1;

	unlink(addr.sun_path);

	sk_st[0] = sk_alloc_bind(SOCK_STREAM, &addr);
	if (sk_st[0] < 0)
		return 1;
	test_msg("sk-st: alloc/bind/listen %d\n", sk_st[0]);

	if (listen(sk_st[0], 16)) {
		pr_perror("Can't listen on socket");
		return 1;
	}

	sk_st[1] = sk_alloc_connect(SOCK_STREAM, &addr);
	if (sk_st[1] < 0)
		return 1;
	test_msg("sk-st: alloc/connect %d\n", sk_st[1]);

	len = sizeof(addr_from);
	sk_st[2] = accept(sk_st[0], (struct sockaddr *)&addr_from, &len);
	if (sk_st[2] < 0) {
		pr_perror("Can't accept on socket");
		return 1;
	}
	test_msg("sk-st: accept %d\n", sk_st[2]);

	sk_st[3] = sk_alloc_connect(SOCK_STREAM, &addr);
	if (sk_st[3] < 0)
		return 1;
	test_msg("sk-st: alloc/connect %d\n", sk_st[3]);

	len = sizeof(addr_from);
	sk_st[4] = accept(sk_st[0], (struct sockaddr *)&addr_from, &len);
	if (sk_st[4] < 0) {
		pr_perror("Can't accept on socket");
		return 1;
	}
	test_msg("sk-st: accept %d\n", sk_st[4]);

	unlink(addr.sun_path);

	/*
	 * Drop subdirectory.
	 */
	rmdir(subdir_st);

	test_daemon();
	test_waitsig();

	if (write_int(sk_dgram[1], &c1)	|| read_int(sk_dgram[0], &c2) ||
	    write_int(sk_dgram[3], &c3)	|| read_int(sk_dgram[2], &c4)) {
		fail("Unable to send/receive a message on dgram");
		return 1;
	}

	if (c1 != c2 || c3 != c4) {
		fail("Vals mismatch on dgram: c1 %d c2 %d c3 %d c4 %d",
		     c1, c2, c3, c4);
		return 1;
	}

	if (write_int(sk_dgram_pair[1], &c9) ||
	    read_int(sk_dgram_pair[0], &c10)) {
		fail("Unable to send/receive a message on paired dgram");
		return 1;
	}

	if (c9 != c10) {
		fail("Vals mismatch on dgram: c9 %d c10 %d",
		     c9, c10);
		return 1;
	}

	if (write_int(sk_st[2], &c5) || read_int(sk_st[1], &c6) ||
	    write_int(sk_st[4], &c7) || read_int(sk_st[3], &c8)) {
		fail("Unable to send/receive a message on stream");
		return 1;
	}

	if (c5 != c6 || c7 != c8) {
		fail("Vals mismatch on stream: c5 %d c6 %d c7 %d c8 %d",
		     c5, c6, c7, c8);
		return 1;
	}

	dir = opendir(subdir_dg);
	if (dir != NULL || errno != ENOENT) {
		fail("Directory %s is not deteled", subdir_dg);
		return 1;
	}

	dir = opendir(subdir_st);
	if (dir != NULL || errno != ENOENT) {
		fail("Directory %s is not deteled", subdir_st);
		return 1;
	}

	pass();
	return 0;
}
