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

	pipe(sp);
	pipe(fp);
	pipe(rp);

	pid = fork();
	if (pid == 0) {
		close(sp[0]);
		close(fp[1]);
		close(rp[0]);

		pid = getpid();
		ppid = getppid();

		close(sp[1]);
		read(fp[0], &x, 1);
		close(fp[0]);

		if (pid != getpid())
			x = 'p';
		else if (ppid != getppid())
			x = 'P';
		else
			x = '0';

		write(rp[1], &x, 1);
		close(rp[1]);
		_exit(0);
	}

	x = 'X';
	close(sp[1]);
	close(fp[0]);
	close(rp[1]);

	read(sp[1], &x, 1);

	test_daemon();
	test_waitsig();

	close(fp[1]);
	read(rp[0], &x, 1);
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
