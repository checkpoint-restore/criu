#include <sys/mman.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/user.h>

#include "zdtmtst.h"

const char *test_doc	= "Create a crazy process tree";
const char *test_author	= "Andrew Vagin <avagin@parallels.com>";

struct process
{
	pid_t pid;
	pid_t sid;
	int sks[2];
	int dead;
};

struct process *processes;
int nr_processes = 20;
int current = 0;

static void cleanup()
{
	int i;

	for (i = 0; i < nr_processes; i++) {
		if (processes[i].dead)
			continue;
		if (processes[i].pid <= 0)
			continue;

		kill(processes[i].pid, SIGKILL);
	}
}

enum commands
{
	TEST_FORK,
	TEST_WAIT,
	TEST_SUBREAPER,
	TEST_SETSID,
	TEST_DIE
};

struct command
{
	enum commands	cmd;
	int		arg1;
	int		arg2;
};

static void handle_command();

static void mainloop()
{
	while (1)
		handle_command();
}

#define CLONE_STACK_SIZE	4096
/* All arguments should be above stack, because it grows down */
struct clone_args {
	char stack[CLONE_STACK_SIZE] __stack_aligned__;
	char stack_ptr[0];
	int id;
};

static int clone_func(void *_arg)
{
	struct clone_args *args = (struct clone_args *) _arg;

	current = args->id;

	test_msg("%3d: Hello. My pid is %d\n", args->id, getpid());
	mainloop();
	exit(0);
}

static int make_child(int id, int flags)
{
	struct clone_args args;
	pid_t cid;

	args.id = id;

	cid = clone(clone_func, args.stack_ptr,
			flags | SIGCHLD, &args);

	if (cid < 0)
		pr_perror("clone(%d, %d)", id, flags);

	processes[id].pid = cid;

	return cid;
}

static void handle_command()
{
	int sk = processes[current].sks[0], ret, status = 0;
	struct command cmd;

	ret = read(sk, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		pr_perror("Unable to get command");
		goto err;
	}

	switch (cmd.cmd) {
	case TEST_FORK:
		{
			pid_t pid;

			pid = make_child(cmd.arg1, cmd.arg2);
			if (pid == -1) {
				status = -1;
				goto err;
			}

			test_msg("%3d: fork(%d, %x) = %d\n",
					current, cmd.arg1, cmd.arg2, pid);
			processes[cmd.arg1].pid = pid;
		}
		break;
	case TEST_WAIT:
		test_msg("%3d: wait(%d) = %d\n", current,
				cmd.arg1, processes[cmd.arg1].pid);

		if (waitpid(processes[cmd.arg1].pid, NULL, 0) == -1) {
			pr_perror("waitpid(%d)", processes[cmd.arg1].pid);
			status = -1;
		}
		break;
	case TEST_SUBREAPER:
		test_msg("%3d: subreaper(%d)\n", current, cmd.arg1);
		if (prctl(PR_SET_CHILD_SUBREAPER, cmd.arg1, 0, 0, 0) == -1) {
			pr_perror("PR_SET_CHILD_SUBREAPER");
			status = -1;
		}
		break;
	case TEST_SETSID:
		test_msg("%3d: setsid()\n", current);
		if(setsid() == -1) {
			pr_perror("setsid");
			status = -1;
		}
		break;
	case TEST_DIE:
		test_msg("%3d: die()\n", current);
		processes[current].dead = 1;
		shutdown(sk, SHUT_RDWR);
		exit(0);
	}

	ret = write(sk, &status, sizeof(status));
	if (ret != sizeof(status)) {
		pr_perror("Unable to answer");
		goto err;
	}

	if (status < 0)
		goto err;

	return;
err:
	shutdown(sk, SHUT_RDWR);
	exit(1);
}

static int send_command(int id, enum commands op, int arg1, int arg2)
{
	int sk = processes[id].sks[1], ret, status;
	struct command cmd = {op, arg1, arg2};

	if (op == TEST_FORK) {
		if (processes[arg1].pid) {
			pr_perror("%d is busy", arg1);
			return -1;
		}
	}

	ret = write(sk, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		pr_perror("Unable to send command");
		goto err;
	}

	status = 0;
	ret = read(sk, &status, sizeof(status));
	if (ret != sizeof(status) && !(status == 0 && op == TEST_DIE)) {
		pr_perror("Unable to get answer");
		goto err;
	}

	if (status) {
		pr_perror("The command(%d, %d, %d) failed", op, arg1, arg2);
		goto err;
	}

	return 0;
err:
	cleanup();
	exit(1);
}

int main(int argc, char ** argv)
{
	int pid, i;
	int fail_cnt = 0;

	test_init(argc, argv);

	processes = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
				MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (processes == NULL) {
		pr_perror("Unable to map share memory");
		return 1;
	}

	for (i = 0; i < nr_processes; i++) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, processes[i].sks) == -1) {
			pr_perror("socketpair");
			return 1;
		}
	}

	pid = make_child(0, 0);
	if (pid < 0)
		return -1;

	/*
	 *  5     5  \_ session02		( 0)
	 *  6     6      \_ session02		( 1)
	 *  8     7      |   \_ session02	( 3)
	 * 15    12      |   \_ session02	(10)
	 * 10    10      \_ session02		( 5)
	 * 11     7          \_ session02	( 6)
	 * 13    12          \_ session02	( 8)
	*/

	send_command(0, TEST_SUBREAPER,	1, 0);
	send_command(0, TEST_SETSID,	0, 0);

	send_command(0, TEST_FORK,	1, 0);
	send_command(1, TEST_FORK,	2, 0);

	send_command(2, TEST_SETSID,	0, 0);
	send_command(2, TEST_FORK,	3, CLONE_PARENT);
	send_command(2, TEST_DIE,	0, 0);
	send_command(1, TEST_WAIT,	2, 0);

	send_command(3, TEST_FORK,	4, 0);
	send_command(4, TEST_FORK,	5, 0);
	send_command(5, TEST_FORK,	6, 0);

	send_command(5, TEST_FORK,	7, 0);
	send_command(7, TEST_SETSID,	0, 0);
	send_command(7, TEST_FORK,	8, CLONE_PARENT);
	send_command(7, TEST_FORK,	9, CLONE_PARENT);
	send_command(7, TEST_DIE,	0, 0);
	send_command(5, TEST_WAIT,	7, 0);

	send_command(9, TEST_FORK,	10, 0);
	send_command(1, TEST_SUBREAPER,	1, 0);
	send_command(9, TEST_DIE,	0, 0);
	send_command(5, TEST_WAIT,	9, 0);
	send_command(1, TEST_SUBREAPER,	0, 0);

	send_command(4, TEST_DIE,	0, 0);
	send_command(3, TEST_WAIT,	4, 0);

	send_command(1, TEST_SETSID,	0, 0);
	send_command(5, TEST_SETSID,	0, 0);

	for (i = 0; i < nr_processes; i++) {
		if (processes[i].dead)
			continue;
		if (processes[i].pid == 0)
			continue;

		processes[i].sid = getsid(processes[i].pid);
		if (processes[i].sid == -1) {
			pr_perror("getsid(%d)", i);
			goto err;
		}
	}

	test_daemon();

	test_waitsig();

	for (i = 0; i < nr_processes; i++) {
		pid_t sid;

		if (processes[i].dead)
			continue;
		if (processes[i].pid == 0)
			continue;

		sid = getsid(processes[i].pid);
		if (sid == -1) {
			pr_perror("getsid(%d)", i);
			goto err;
		}

		if (sid != processes[i].sid) {
			fail("%d, %d: wrong sid %d (expected %d)",
				i, processes[i].pid, sid, processes[i].sid);
			fail_cnt++;
		}
	}

	if (fail_cnt)
		goto err;

	pass();

	return 0;
err:
	cleanup();
	return 1;
}
