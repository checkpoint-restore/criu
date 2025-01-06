#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <limits.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Test in-flight unix sockets with data in them\n";
const char *test_author = "Andrei Vagin <avagin@gmail.com>";

#define SK_DATA "packet"

char *filename;
TEST_OPTION(filename, string, "socket file name", 1);

#define TEST_MODE 0640

#ifdef ZDTM_UNIX_SEQPACKET
#define SOCK_TYPE SOCK_SEQPACKET
#else
#define SOCK_TYPE SOCK_STREAM
#endif

int main(int argc, char *argv[])
{
	struct sockaddr_un addr;
	unsigned int addrlen;
	int ssk, sk;

	char path[PATH_MAX];
	char *cwd;
	int ret;

	test_init(argc, argv);

	cwd = get_current_dir_name();
	if (!cwd)
		return pr_perror("get_current_dir_name");

	snprintf(path, sizeof(path), "%s/%s", cwd, filename);
	unlink(path);

	addr.sun_family = AF_UNIX;
	addrlen = strlen(filename);
	if (addrlen > sizeof(addr.sun_path))
		return pr_err("address is too long");
	memcpy(addr.sun_path, filename, addrlen);
	addrlen += sizeof(addr.sun_family);

	ssk = socket(AF_UNIX, SOCK_TYPE, 0);
	if (ssk == -1)
		return pr_perror("socket");

	sk = socket(AF_UNIX, SOCK_TYPE, 0);
	if (sk < 0)
		return pr_perror("socket");

	ret = bind(ssk, (struct sockaddr *)&addr, addrlen);
	if (ret)
		return pr_perror("bind");

	ret = listen(ssk, 16);
	if (ret)
		return pr_perror("listen");

	if (connect(sk, (struct sockaddr *)&addr, addrlen))
		return pr_perror("connect");

#ifdef SK_UNIX_LISTEN02
	{
		char buf[64];
		memset(buf, 0, sizeof(buf));
		write(sk, SK_DATA, sizeof(SK_DATA));
	}
#endif

#ifdef SK_UNIX_LISTEN03
	close(sk);
	sk = -1;
#endif

	test_daemon();
	test_waitsig();

	if (sk != -1)
		close(sk);

	ret = accept(ssk, NULL, NULL);
	if (ret < 0)
		return fail("accept");

#ifdef SK_UNIX_LISTEN02
	{
		char buf[64];
		if (read(ret, &buf, sizeof(buf)) != sizeof(SK_DATA))
			return pr_perror("read");

		if (strcmp(buf, SK_DATA))
			return fail("data corrupted");
	}
#endif

	close(ssk);
	unlink(path);

	pass();
	return 0;
}
