#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sched.h>
#include <stdio.h>

#include "zdtmtst.h"

const char *test_doc = "Check sched policy to be preserved";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

static const int param = 3;

static int do_nothing(void)
{
	while (1)
		sleep(10);

	return -1;
}

int main(int argc, char **argv)
{
	int pid, ret, err = 0;
	struct sched_param p;
	int old_rt_runtime_us = -1;
	FILE *file;

	test_init(argc, argv);

	pid = fork();
	if (!pid)
		return do_nothing();

	file = fopen("/sys/fs/cgroup/cpu/user.slice/cpu.rt_runtime_us", "r");
	if (file) {
		ret = fscanf(file, "%d", &old_rt_runtime_us);
		fclose(file);

		if ((ret > 0) && (old_rt_runtime_us == 0)) {
			file = fopen("/sys/fs/cgroup/cpu/user.slice/cpu.rt_runtime_us", "w");
			if (file) {
				fprintf(file, "100\n");
				fclose(file);
			}
		}
	}

	p.sched_priority = param;
	if (sched_setscheduler(pid, SCHED_RR, &p)) {
		pr_perror("Can't set policy");
		kill(pid, SIGKILL);
		return -1;
	}

	test_daemon();
	test_waitsig();

	ret = sched_getscheduler(pid);
	if (ret != SCHED_RR) {
		fail("Broken/No policy");
		err++;
	}

	ret = sched_getparam(pid, &p);
	if (ret < 0 || p.sched_priority != param) {
		fail("Broken prio");
		err++;
	}

	if (!err)
		pass();

	kill(pid, SIGKILL);
	if (old_rt_runtime_us != -1) {
		file = fopen("/sys/fs/cgroup/cpu/user.slice/cpu.rt_runtime_us", "w");
		if (file) {
			fprintf(file, "%d\n", old_rt_runtime_us);
			fclose(file);
		}
	}
	return err;
}
