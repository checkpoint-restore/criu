#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <fcntl.h>

#include "zdtmtst.h"

const char *test_doc = "Check that removed cwd works";
const char *test_author = "Pavel Emelianov <xemul@parallels.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

int main(int argc, char **argv)
{
	char cwd1[PATH_MAX], cwd2[PATH_MAX];
	int pid, p[2], aux, aux2, fd;

	test_init(argc, argv);

	pipe(p);
	pid = fork();
	if (pid == 0) {
		close(p[1]);
		read(p[0], &aux, sizeof(aux));
		aux = rmdir(dirname);
		exit(aux ? 1 : 0);
	}

	fd = open(".", O_DIRECTORY | O_RDONLY);
	if (fd == -1) {
		pr_perror("Unable to open the current dir");
		exit(1);
	}

	if (mkdir(dirname, 0700)) {
		pr_perror("can't make directory %s", dirname);
		exit(1);
	}

	if (chdir(dirname)) {
		pr_perror("can't change directory to %s", dirname);
		goto cleanup;
	}

	close(p[1]);
	close(p[0]);
	waitpid(pid, &aux, 0);
	if (!WIFEXITED(aux) || WEXITSTATUS(aux) != 0) {
		pr_perror("can't remove dir");
		goto cleanup;
	}

	aux = readlink("/proc/self/cwd", cwd1, sizeof(cwd1));
	if (aux < 0) {
		pr_perror("can't get cwd");
		goto cleanup;
	}
	if (aux == sizeof(cwd1)) {
		pr_perror("A buffer is too small");
		goto cleanup;
	}

	cwd1[aux] = '\0';

	test_daemon();
	test_waitsig();

	aux2 = readlink("/proc/self/cwd", cwd2, sizeof(cwd2));
	if (aux2 < 0) {
		fail("can't get cwd");
		goto cleanup;
	}
	if (aux2 == sizeof(cwd2)) {
		pr_perror("A buffer is too small");
		goto cleanup;
	}

	cwd2[aux2] = '\0';

	/* FIXME -- criu adds a suffix to removed cwd */
	if (strncmp(cwd1, cwd2, aux))
		fail("%s != %s", cwd1, cwd2);
	else
		pass();
cleanup:
	/* return to the initial dir before writing out results */
	if (fchdir(fd)) {
		pr_perror("can't restore cwd");
		exit(1);
	}

	rmdir(dirname);
	return 0;
}
