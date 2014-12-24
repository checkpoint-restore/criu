#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that removed and opened cwd are kept";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	int cwd, fd, pid, p[2], aux;
	struct stat std, stf;

	test_init(argc, argv);

	pipe(p);
	pid = fork();
	if (pid == 0) {
		close(p[1]);
		read(p[0], &aux, sizeof(aux));
		aux = rmdir(dirname);
		exit(aux ? 1 : 0);
	}

	cwd = open(".", O_DIRECTORY | O_RDONLY);
	if (cwd == -1) {
		err("Unable to open the current dir");
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		err("can't make directory %s: %m\n", dirname);
		exit(1);
	}

	if ((fd = open(dirname, O_DIRECTORY)) < 0) {
		err("can't open dir %s: %m\n", dirname);
		goto cleanup;
	}

	if (chdir(dirname)) {
		err("can't change directory to %s: %m\n", dirname);
		goto cleanup;
	}

	close(p[1]);
	close(p[0]);
	waitpid(pid, &aux, 0);
	if (!WIFEXITED(aux) || WEXITSTATUS(aux) != 0) {
		err("can't remove dir\n");
		goto cleanup;
	}

	test_daemon();
	test_waitsig();

	if (fstat(fd, &stf) < 0) {
		fail("dir fd closed\n");
		goto cleanup;
	}

	if (stat("/proc/self/cwd", &std) < 0) {
		fail("cwd is not OK\n");
		goto cleanup;
	}

	if (stf.st_ino != std.st_ino ||
			stf.st_dev != stf.st_dev) {
		fail("cwd and opened fd are not the same\n");
		goto cleanup;
	}

	pass();

cleanup:
	/* return to the initial dir before writing out results */
	if (fchdir(cwd)) {
		err("can't restore cwd");
		exit(1);
	}

	rmdir(dirname);
	return 0;
}
