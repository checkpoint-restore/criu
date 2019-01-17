#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "zdtmtst.h"
#include "lock.h"

const char *test_doc	= "Test that sid, pgid are restored";
const char *test_author	= "Andrey Vagin <avagin@openvz.org>";

struct master {
	pid_t pid;
	pid_t ppid;
	pid_t sid;
	pid_t pgid;
};

struct testcase {
	pid_t pid;
	pid_t ppid;
	pid_t sid;
	pid_t born_sid;
	pid_t pgid;
	int alive;
	struct master master;
	futex_t futex;
};

enum {
	TEST_FORK,
	TEST_PGID,
	TEST_WAIT,
	TEST_MASTER,
	TEST_CHECK,
	TEST_EXIT,
};

static struct testcase *testcases;
static futex_t *fstate;
static struct testcase __testcases[] = {
	{ 2,  1,  2,  1,  2, 1 },  /* session00			*/
	{ 4,  2,  4,  2,  4, 1 },  /*  |\_session00		*/
	{15,  4,  4,  4, 15, 1 },  /*  |  |\_session00		*/
	{16,  4,  4,  4, 15, 1 },  /*  |   \_session00		*/
	{17,  4,  4,  4, 17, 0 },  /*  |  |\_session00		*/
	{18,  4,  4,  4, 17, 1 },  /*  |   \_session00		*/
	{ 5,  2,  2,  2,  2, 1 },  /*  |\_session00		*/
	{ 8,  2,  8,  2,  8, 1 },  /*  |\_session00		*/
	{ 9,  8,  2,  2,  2, 1 },  /*  |   \_session00		*/
	{10,  2, 10,  2, 10, 1 },  /*  |\_session00		*/
	{11, 10, 11,  2, 11, 1 },  /*  |    \_session00		*/
	{12, 11,  2,  2,  2, 1 },  /*  |        \_session00	*/
	{13,  2,  2,  2,  2, 0 },  /*   \_session00		*/
	{ 3, 13,  2,  2,  2, 1 },  /* session00			*/
	{ 6,  2,  6,  2,  6, 0 },  /*   \_session00		*/
	{14,  6,  6,  6,  6, 1 },  /* session00			*/
};

#define TESTS (sizeof(__testcases) / sizeof(struct testcase))

#define check(n, a, b) do { if ((a) != (b)) { pr_perror("%s mismatch %d != %d", n, a, b); goto err; } } while (0)

static int child(const int c);
static int fork_children(struct testcase *t, int leader)
{
	int i;
	pid_t cid;

	for (i = 0; i < TESTS; i++) {
		if (t->pid != testcases[i].ppid)
			continue;

		if (leader ^ (t->pid == testcases[i].born_sid))
				continue;

		cid = test_fork_id(i);
		if (cid < 0)
			goto err;
		if (cid == 0) {
			test_msg("I'm %d with pid %d\n", i, getpid());
			child(i);
			exit(0);
		}

		testcases[i].master.pid = cid;
	}
	return 0;
err:
	return -1;
}

static int child(const int c)
{
	int i;
	struct testcase *t = &testcases[c];

	t->master.pid = getpid();

	if (fork_children(t, 0))
		goto err;

	if (t->pid == t->sid) {
		if (getpid() != getsid(0))
			if (setsid() < 0)
				goto err;
		if (fork_children(t, 1))
			goto err;
	}
	if (t->pid == t->pgid) {
		if (getpid() != getpgid(0))
			if (setpgid(getpid(), getpid()) < 0) {
				pr_perror("setpgid() failed");
				goto err;
			}
		t->master.pgid = t->master.pid;
	}

	futex_set_and_wake(&t->futex, c);

	if (c == 0)
		goto out;

	futex_wait_until(fstate, TEST_PGID);

	for (i = 0; i < TESTS; i++) {
		if (c == 0)
			break;
		if (t->pgid != testcases[i].pid)
			continue;
		if (getpgid(0) != testcases[i].master.pid)
			if (setpgid(getpid(), testcases[i].master.pid) < 0) {
				pr_perror("setpgid() failed (%d) (%d)", c, i);
				goto err;
			}

		t->master.pgid	= testcases[i].master.pid;
		break;
	}

	futex_set_and_wake(&t->futex, c);

	futex_wait_until(fstate, TEST_WAIT);

	for (i = 0; i < TESTS; i++) {
		if (t->pid != testcases[i].ppid)
			continue;
		if (testcases[i].alive)
			continue;
		test_msg("Wait porcess %d (pid %d)\n", i, testcases[i].master.pid);
		waitpid(testcases[i].master.pid, NULL, 0);
	}

	if (!t->alive)
		goto out;

	futex_set_and_wake(&t->futex, c);

	futex_wait_until(fstate, TEST_MASTER);

	/* Save the master copy */
	t->master.ppid	= getppid();
	t->master.sid	= getsid(0);

	futex_set_and_wake(&t->futex, c);

	futex_wait_until(fstate, TEST_CHECK);

	check("pid", t->master.pid,	getpid());
	check("ppid", t->master.ppid,	getppid());
	check("sid", t->master.sid,	getsid(0));
	check("pgid", t->master.pgid,	getpgid(0));

	futex_set_and_wake(&t->futex, c);

	/* Wait while all test cases check results */
	futex_wait_until(fstate, TEST_EXIT);
out:
	return 0;
err:
	futex_set_and_wake(&t->futex, -1);
	return 1;
}

int main(int argc, char ** argv)
{
	int i, err, ret;
	void *ptr;

	BUG_ON(sizeof(*fstate) + sizeof(__testcases) > 4096);

	ptr = mmap(NULL, 4096, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (ptr == MAP_FAILED)
		return 1;

	fstate = ptr;
	futex_set(fstate, TEST_FORK);
	testcases = ptr + sizeof(*fstate);

	memcpy(testcases, &__testcases, sizeof(__testcases));

	test_init(argc, argv);

	testcases[0].master.pid = getpid();
	if (child(0))
		goto err;

	for (i = 1; i < TESTS; i++) {
		ret = futex_wait_while(&testcases[i].futex, 0);
		if (ret < 0)
			return 1;
		futex_set(&testcases[i].futex, 0);
	}

	test_msg("TEST_PGID\n");
	futex_set_and_wake(fstate, TEST_PGID);
	for (i = 1; i < TESTS; i++) {
		ret = futex_wait_while(&testcases[i].futex, 0);
		if (ret < 0)
			goto err;
		futex_set(&testcases[i].futex, 0);
	}

	test_msg("TEST_WAIT\n");
	futex_set_and_wake(fstate, TEST_WAIT);
	for (i = 1; i < TESTS; i++) {
		if (!testcases[i].alive)
			continue;
		ret = futex_wait_while(&testcases[i].futex, 0);
		if (ret < 0)
			goto err;
		futex_set(&testcases[i].futex, 0);
	}

	for (i = 0; i < TESTS; i++) {
		if (testcases[0].pid != testcases[i].ppid)
			continue;
		if (testcases[i].alive)
			continue;
		test_msg("Wait porcess %d (pid %d)\n",
				i, testcases[i].master.pid);
		waitpid(testcases[i].master.pid, NULL, 0);
	}

	test_msg("TEST_MASTER\n");
	futex_set_and_wake(fstate, TEST_MASTER);
	for (i = 1; i < TESTS; i++) {
		if (!testcases[i].alive)
			continue;
		ret = futex_wait_while(&testcases[i].futex, 0);
		if (ret < 0)
			goto err;
		futex_set(&testcases[i].futex, 0);
		test_msg("The process %d initialized\n", ret);
	}

	test_daemon();

	test_waitsig();

	err = 0;
	for (i = 1; i < TESTS; i++) {
		int j;
		struct testcase *t = testcases + i;
		pid_t sid, pgid;

		if (!t->alive)
			continue;

		for (j = 0; j < TESTS; j++) {
			struct testcase *p = testcases + j;
			/* sanity check */
			if (p->pid == t->sid && t->master.sid != p->master.pid) {
				pr_perror("session mismatch (%d) %d != (%d) %d",
					i, t->master.sid, j, p->master.pid);
				err++;
			}
			if (p->pid == t->pgid && t->master.pgid != p->master.pid) {
				pr_perror("pgid mismatch (%d) %d != (%d) %d",
					i, t->master.pgid, j, p->master.pid);
				err++;
			}
		}

		sid = getsid(t->master.pid);
		if (t->master.sid != sid) {
			pr_perror("%d: session mismatch %d (expected %d)",
						i, sid, t->master.sid);
			err++;
		}

		pgid = getpgid(t->master.pid);
		if (t->master.pgid != pgid) {
			pr_perror("%d: pgid mismatch %d (expected %d)",
						i, t->master.pgid, pgid);
			err++;
		}
	}

	test_msg("TEST_CHECK\n");
	futex_set_and_wake(fstate, TEST_CHECK);

	for (i = 1; i < TESTS; i++) {
		if (!testcases[i].alive)
			continue;

		ret = futex_wait_while(&testcases[i].futex, 0);
		if (ret < 0)
			goto err;
		futex_set(&testcases[i].futex, 0);

		if (ret < 0) {
			fail("Someone failed");
			err++;
			continue;
		}
		test_msg("The process %u is restored correctly\n", (unsigned)ret);
	}

	test_msg("TEST_EXIT\n");
	futex_set_and_wake(fstate, TEST_EXIT);

	if (!err)
		pass();

	return 0;
err:
	for (i = 1; i < TESTS; i++) {
		pid_t pid = testcases[i].master.pid;
		if (pid > 0) {
			ret = kill(pid, SIGKILL);
			test_msg("kill %d %s\n", pid, strerror(ret == -1 ? errno : 0));
		}
	}
	return 1;
}
