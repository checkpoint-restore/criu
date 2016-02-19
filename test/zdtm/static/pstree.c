#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that environment didn't change";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

int main(int argc, char **argv)
{
	char x;
	int pid, ppid;
	int sp[2], fp[2], rp[2];

	test_init(argc, argv);

	if (pipe(sp) || pipe(fp) || pipe(rp)) {
		pr_perror("pipe");
		return 1;
	}

	pid = fork();
	if (pid == 0) {
		close(sp[0]);
		close(fp[1]);
		close(rp[0]);

		pid = getpid();
		ppid = getppid();

		close(sp[1]);
		if (read(fp[0], &x, 1)) {
			pr_perror("read");
			return 1;
		}
		close(fp[0]);

		if (pid != getpid())
			x = 'p';
		else if (ppid != getppid())
			x = 'P';
		else
			x = '0';

		if (write(rp[1], &x, 1) != 1) {
			pr_perror("write");
			return 1;
		}
		close(rp[1]);
		_exit(0);
	}

	x = 'X';
	close(sp[1]);
	close(fp[0]);
	close(rp[1]);

	if (read(sp[0], &x, 1)) {
		pr_perror("read");
		return 1;
	}

	test_daemon();
	test_waitsig();

	close(fp[1]);
	if (read(rp[0], &x, 1) != 1) {
		pr_perror("read");
		return 1;
	}
	close(rp[0]);

	if (x == 'X')
		fail("Sync failed");
	else if (x == 'p')
		fail("Pid failed");
	else if (x == 'P')
		fail("PPid failed");
	else if (x != '0')
		fail("Shit happened");
	else
		pass();

	return 0;
}
