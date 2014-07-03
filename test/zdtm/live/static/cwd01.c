#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that removed cwd works";
const char *test_author	= "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char cwd0[256], cwd1[256], cwd2[256];
	int pid, p[2], aux;

	test_init(argc, argv);

	pipe(p);
	pid = fork();
	if (pid == 0) {
		close(p[1]);
		read(p[0], &aux, sizeof(aux));
		aux = rmdir(dirname);
		exit(aux ? 1 : 0);
	}

	if (!getcwd(cwd0, sizeof(cwd0))) {
		err("can't get cwd: %m\n");
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		err("can't make directory %s: %m\n", dirname);
		exit(1);
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

	aux = readlink("/proc/self/cwd", cwd1, sizeof(cwd1));
	if (aux < 0) {
		err("can't get cwd: %m\n");
		goto cleanup;
	}

	cwd1[aux] = '\0';

	test_daemon();
	test_waitsig();

	if (readlink("/proc/self/cwd", cwd2, sizeof(cwd2)) < 0) {
		fail("can't get cwd: %m\n");
		goto cleanup;
	}

	/* FIXME -- criu adds a suffix to removed cwd */
	if (strncmp(cwd1, cwd2, aux))
		fail("%s != %s\n", cwd1, cwd2);
	else
		pass();
cleanup:
	/* return to the initial dir before writing out results */
	if (chdir(cwd0)) {
		err("can't change directory to %s: %m\n", cwd0);
		exit(1);
	}

	rmdir(dirname);
	return 0;
}
