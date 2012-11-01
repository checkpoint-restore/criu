#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include "zdtmtst.h"

const char *test_doc	= "Check that tree prior to files opening";
const char *test_author	= "Stanislav Kinsbursky <skinsbursky@paralles.com";

int main(int argc, char ** argv)
{
	int pid, err = 0;
	int proc_fd;
	char name[64];

	test_init(argc, argv);

	pid = test_fork();
	if (pid < 0) {
		err("Can't fork");
		exit(1);
	}

	if (!pid) {
		test_waitsig();
		return 0;
	}

	sprintf(name, "/proc/%d/stat", pid);
	proc_fd = open(name, O_RDONLY);
	if (proc_fd == -1) {
		err("can't open %s: %m\n", name);
		err++;
		goto out;
	}
	test_daemon();
	test_waitsig();

	if (close(proc_fd) == -1) {
		err("Failed to close %s\n", name);
		err++;
	}
out:
	if (kill(pid, SIGTERM) == -1) {
		err("Failed to terminate child\n");
		err++;
	} else {
		if (waitpid(pid, NULL, 0) != pid) {
			err("Failed to collect killed child\n");
			err++;
		}
	}

	if (!err)
		pass();

	return err;
}
