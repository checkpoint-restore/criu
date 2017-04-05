#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "zdtmtst.h"

const char *test_doc	= "Test that sid, pgid are restored";
const char *test_author	= "Andrey Vagin <avagin@openvz.org>";

#define DETACH		1
#define NEWSID		2
#define CHANGESID	4
#define DOUBLE_CHANGESID	8

struct testcase {
	int flags;
	pid_t pid;
	pid_t sid;
};

static struct testcase testcases[] = {
			{DETACH, },
			{NEWSID, },
			{0, },
			{DETACH|NEWSID, },
			{CHANGESID, },
			{DOUBLE_CHANGESID | CHANGESID, }
		};
/*
    2     2 session00
    4     4  \_ session00               # {NEWSID, },
    2     5  \_ session00               # {0, },
    8     8  \_ session00
    2     9  |   \_ session00           # {CHANGESID, }
   10    10  \_ session00
   11    11      \_ session00
    2    12          \_ session00       # {DOUBLE_CHANGESID | CHANGESID, }
    2     3 session00                   # {DETACH, },
    6     7 session00                   # {DETACH|NEWSID, },
*/

#define NUM_CASES (sizeof(testcases) / sizeof(struct testcase))

static int fork_child(int i)
{
	int p[2];
	int status, ret;
	pid_t pid, sid;

	ret = pipe(p);
	if (ret) {
		pr_perror("pipe() failed");
		return 1;
	}

	pid = test_fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		return 1;
	}

	if (pid == 0) {
		if (testcases[i].flags & NEWSID) {
			sid = setsid();
			if (sid == -1) {
				pr_perror("setsid failed");
				write(p[1], &sid, sizeof(sid));
				exit(1);
			}
		}

		if (testcases[i].flags & (DETACH | CHANGESID)) {
			pid = test_fork();
			if (pid < 0) {
				write(p[1], &pid, sizeof(pid));
				exit(1);
			}
		}

		if (pid != 0) {
			if (!(testcases[i].flags & CHANGESID))
				exit(0);

			sid = setsid();
			if (sid == -1) {
				pr_perror("setsid failed");
				write(p[1], &sid, sizeof(sid));
				exit(1);
			}

			close(p[1]);
			wait(NULL);
			if (getsid(getpid()) != sid) {
				fail("The process %d (%x) has SID=%d (expected %d)",
					pid, testcases[i].flags, sid, testcases[i].sid);
				exit(1);
			}
			exit(0);
		}

		if (testcases[i].flags & DOUBLE_CHANGESID) {
			pid = fork();
			if (pid < 0) {
				write(p[1], &pid, sizeof(pid));
				exit(1);
			}

			if (pid == 0)
				goto child;

			sid = setsid();
			if (sid == -1) {
				pr_perror("setsid failed");
				write(p[1], &sid, sizeof(sid));
				exit(1);
			}

			close(p[1]);
			wait(NULL);
			if (getsid(getpid()) != sid) {
				fail("The process %d (%x) has SID=%d (expected %d)",
					pid, testcases[i].flags, sid, testcases[i].sid);
				exit(1);
			}
			exit(0);
		}

child:
		pid = getpid();
		write(p[1], &pid, sizeof(pid));
		close(p[1]);

		test_waitsig();
		pass();
		exit(0);
	}

	close(p[1]);

	if (testcases[i].flags & DETACH) {
		pid_t ret;
		ret = wait(&status);
		if (ret != pid) {
			pr_perror("wait return %d instead of %d", ret, pid);
			kill(pid, SIGKILL);
			return 1;
		}
	}

	ret = read(p[0], &testcases[i].pid, sizeof(pid));
	if (ret != sizeof(ret)) {
		pr_perror("read failed");
		return 1;
	}
	/* wait when a child closes fd */
	ret = read(p[0], &testcases[i].pid, sizeof(pid));
	if (ret != 0) {
		pr_perror("read failed");
		return 1;
	}

	close(p[0]);

	if (testcases[i].pid < 0) {
		pr_perror("child failed");
		return 1;
	}

	testcases[i].sid = getsid(testcases[i].pid);

	return 0;
}

int main(int argc, char ** argv)
{
	int i, ret, err = 0, status;
	pid_t pid;

	test_init(argc, argv);

	for (i = 0; i < NUM_CASES; i++)
		if (fork_child(i))
			break;

	if (i != NUM_CASES) {
		int j;
		for (j = 0; j < i; j++)
			kill(testcases[j].pid, SIGTERM);
		return 1;
	}

	test_daemon();

	test_waitsig();

	for (i = 0; i < NUM_CASES; i++) {
		pid_t pid = testcases[i].pid;
		pid_t sid = getsid(pid);

		if (sid != testcases[i].sid) {
			fail("The process %d (%x) has SID=%d (expected %d)",
				pid, testcases[i].flags, sid, testcases[i].sid);
			err++;
		}

		ret = kill(pid, SIGKILL);
		if (ret == -1) {
			pr_perror("kill failed");
			err++;
		}
		waitpid(pid, NULL, 0);

		if (testcases[i].flags & CHANGESID) {
			pid = wait(&status);
			if (pid == -1) {
				pr_perror("wait() failed");
				err++;
			}
			if (!WIFEXITED(status) || WEXITSTATUS(status)) {
				fail("The process with pid %d returns %d\n", pid, status);
				err++;
			}
		}
	}

	pid = wait(&status);
	if (pid != -1 || errno != ECHILD) {
		pr_perror("%d isn't waited", pid);
		err++;
	}

	if (!err)
		pass();

	return err > 0;
}
