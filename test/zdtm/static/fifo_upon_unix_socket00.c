#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Check that fifo upon ghost socket configuration is restored";
const char *test_author = "Andrey Zhadchenko <andrey.zhadchenko@virtuozzo.com>";

char *filename;
TEST_OPTION(filename, string, "socket name", 1);

#ifndef FIFO_UPON_UNIX01
static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	char *cwd;

	cwd = get_current_dir_name();
	if (strlen(filename) + strlen(cwd) + 1 >= sizeof(name->sun_path)) {
		pr_err("Name %s/%s is too long for socket\n", cwd, filename);
		return -1;
	}

	name->sun_family = AF_LOCAL;
	ssprintf(name->sun_path, "%s/%s", cwd, filename);
	return 0;
}
#else
static int fill_sock_name(struct sockaddr_un *name, const char *filename)
{
	if (strlen(filename) + 1 >= sizeof(name->sun_path)) {
		pr_err("Name %s is too long for socket\n", filename);
		return -1;
	}

	name->sun_family = AF_LOCAL;
	ssprintf(name->sun_path, "%s", filename);
	return 0;
}
#endif

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

static int check_fd(int fdin, int fdout)
{
	int ret;
	char c = 0;

	ret = write(fdin, &c, 1);
	if (ret != 1)
		goto err;

	ret = read(fdout, &c, 1);
	if (ret != 1)
		goto err;

	return 0;

err:
	pr_perror("broken fd pair %d %d", fdin, fdout);
	return -1;
}

int main(int argc, char **argv)
{
	int sk1, sk2, fd1, err;
	struct sockaddr_un addr;

	test_init(argc, argv);

	unlink(filename);

	if (fill_sock_name(&addr, filename))
		return 1;

	sk1 = sk_alloc_bind(SOCK_DGRAM, &addr);
	if (sk1 < 0) {
		pr_perror("Can't create sk");
		return 1;
	}

	sk2 = sk_alloc_connect(SOCK_DGRAM, &addr);
	if (sk2 < 0) {
		pr_perror("Can't connect to sk");
		return 1;
	}

	if (unlink(filename) < 0) {
		fail("can't unlink %s", filename);
		return 1;
	}

	if (mkfifo(filename, 0666)) {
		pr_perror("can't make fifo \"%s\"", filename);
		return 1;
	}

	fd1 = open(filename, O_RDWR);
	if (fd1 < 0) {
		pr_perror("can't open %s", filename);
		return 1;
	}

#ifdef FIFO_UPON_UNIX01
	chdir("/");
#endif

	test_daemon();
	test_waitsig();

	unlink(filename);

	err = check_fd(sk2, sk1) || check_fd(fd1, fd1);
	if (err)
		fail();
	else
		pass();

	close(sk1);
	close(sk2);
	close(fd1);

	return 0;
}
