#define _GNU_SOURCE
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
	int wait;
};

#define MEM_SIZE (2 * PAGE_SIZE)
#define PR_MAX (MEM_SIZE / sizeof(struct process))

struct process *processes;
int nr_processes = 0;
int current = 0;

static void sigchld_handler(int signal, siginfo_t *siginfo, void *data)
{
	pid_t pid = siginfo->si_pid;
	if (siginfo->si_status == 2)
		waitpid(pid, NULL, WNOHANG);
}

static void cleanup()
{
	int i, ret;

	for (i = 0; i < nr_processes; i++) {
		if (processes[i].dead)
			continue;
		if (processes[i].pid <= 0)
			continue;

		kill(processes[i].pid, SIGKILL);
	}

	while (1) {
		ret = wait(NULL);
		if (ret == -1) {
			if (errno == ECHILD)
				break;
			err("wait");
			exit(1);
		}
	}
}

enum commands
{
	TEST_FORK,
	TEST_DIE_WAIT,
	TEST_DIE,
	TEST_SUBREAPER,
	TEST_SETSID,
	TEST_MAX
};

int cmd_weght[TEST_MAX] = {10, 3, 1, 10, 7};
int sum_weight = 0;
static int get_rnd_op()
{
	int i, m;
	if (sum_weight == 0) {
		for (i = 0; i < TEST_MAX; i++)
			sum_weight += cmd_weght[i];
	}
	m = lrand48() % sum_weight;
	for (i = 0; i < TEST_MAX; i++) {
		if (m > cmd_weght[i]) {
			m -= cmd_weght[i];
			continue;
		}
		return i;
	}
	return -1;
}

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
	char stack[CLONE_STACK_SIZE];
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
		err("clone(%d, %d)", id, flags);

	processes[id].pid = cid;

	return cid;
}

static void handle_command()
{
	int sk = processes[current].sks[0], ret, status = 0;
	struct command cmd;

	ret = read(sk, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		err("Unable to get command");
		goto err;
	}

	switch (cmd.cmd) {
	case TEST_FORK:
		{
			pid_t pid;

			pid = make_child(cmd.arg1, cmd.arg2 ? CLONE_PARENT : 0);
			if (pid < 0) {
				status = -1;
				goto err;
			}

			test_msg("%3d: fork(%d, %x) = %d\n",
					current, cmd.arg1, cmd.arg2, pid);
			processes[cmd.arg1].pid = pid;
		}
		break;
	case TEST_SUBREAPER:
		test_msg("%3d: subreaper(%d)\n", current, cmd.arg1);
		if (prctl(PR_SET_CHILD_SUBREAPER, cmd.arg1, 0, 0, 0) == -1) {
			err("PR_SET_CHILD_SUBREAPER");
			status = -1;
		}
		break;
	case TEST_SETSID:
		if (getsid(getpid()) == getpid())
			break;
		test_msg("%3d: setsid()\n", current);
		if(setsid() == -1) {
			err("setsid");
			status = -1;
		}
		break;
	case TEST_DIE_WAIT:
		test_msg("%3d: wait()\n", current);
	case TEST_DIE:
		test_msg("%3d: die()\n", current);
		processes[current].dead = 1;
		shutdown(sk, SHUT_RDWR);
		if (cmd.cmd == TEST_DIE_WAIT)
			exit(2);
		exit(0);
	default:
		err("Unknown operation %d", cmd.cmd);
		status = -1;
		break;
	}

	ret = write(sk, &status, sizeof(status));
	if (ret != sizeof(status)) {
		err("Unable to answer");
		goto err;
	}

	if (status < 0)
		goto err;

	return;
err:
	shutdown(sk, SHUT_RDWR);
	exit(1);
}

static int send_command(int id, enum commands op, int arg)
{
	int sk = processes[id].sks[1], ret, status;
	struct command cmd = {op, arg};

	if (op == TEST_FORK) {
		cmd.arg1 = nr_processes;
		nr_processes++;
		if (nr_processes > PR_MAX)
			return -1;
		cmd.arg2 = arg;
	}

	ret = write(sk, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd)) {
		err("Unable to send command");
		goto err;
	}

	status = 0;
	ret = read(sk, &status, sizeof(status));
	if (ret != sizeof(status) &&
	    !(status == 0 && (op == TEST_DIE || op == TEST_DIE_WAIT))) {
		err("Unable to get answer");
		goto err;
	}

	if (status) {
		err("The command(%d, %d, %d) failed");
		goto err;
	}

	return 0;
err:
	cleanup();
	exit(1);
}

int main(int argc, char ** argv)
{
	struct sigaction act;
	int pid, i, ret;
	int fail_cnt = 0;

	test_init(argc, argv);

	if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == -1) {
		err("PR_SET_CHILD_SUBREAPER");
		return -1;
	}

	ret = sigaction(SIGCHLD, NULL, &act);
	if (ret < 0) {
		err("sigaction() failed\n");
		return -1;
	}

	act.sa_flags |= SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART;
	act.sa_sigaction = sigchld_handler;
	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCHLD);

	ret = sigaction(SIGCHLD, &act, NULL);
	if (ret < 0) {
		err("sigaction() failed\n");
		return -1;
	}

	processes = mmap(NULL, MEM_SIZE, PROT_WRITE | PROT_READ,
				MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (processes == NULL) {
		err("Unable to map share memory");
		return 1;
	}

	for (i = 0; i < PR_MAX; i++) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, processes[i].sks) == -1) {
			err("socketpair");
			return 1;
		}
	}

	nr_processes++;
	pid = make_child(0, 0);
	if (pid < 0)
		return -1;

	while(nr_processes < PR_MAX) {
		int op, id;
		int flags = lrand48() % 2;

		op = get_rnd_op();
		if (op == TEST_DIE || op == TEST_DIE_WAIT || op == TEST_SUBREAPER) {
			if (nr_processes == 1)
				continue;
			else
				id = lrand48() % (nr_processes - 1) + 1;
		} else if (op == TEST_FORK) {
			id = nr_processes * 9 / 10 + lrand48() % nr_processes / 10;
			while (processes[id].dead != 0)
				id--;
		} else
			id = lrand48() % nr_processes;

		if (processes[id].dead)
			continue;

		send_command(id, op, flags);
	}

	for (i = 0; i < nr_processes; i++) {
		if (processes[i].dead)
			continue;
		if (processes[i].pid == 0)
			continue;

		processes[i].sid = getsid(processes[i].pid);
		if (processes[i].sid == -1) {
			err("getsid(%d)", i);
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
			err("getsid(%d)", i);
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

	cleanup();
	return 0;
err:
	cleanup();
	return 1;
}
