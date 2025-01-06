/*
 * Check that we can dump a process with threads having mismatching UID/GID
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <syscall.h>

#include <sys/capability.h>
#include <sys/prctl.h>
#include <pthread.h>

#include "zdtmtst.h"

#define exit_group(code) syscall(__NR_exit_group, code)

const char *test_doc = "Acquire UID/GID setting caps, create thread and drop thread to non-root by changing UID/GID\n";
const char *test_author = "Vitaly Ostrosablin <vostrosablin@virtuozzo.com>";

unsigned int gid;
unsigned int uid;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
task_waiter_t t;

int done = 0;

void *chg_uid_gid(void *arg)
{
	cap_t newcaps;
	cap_t mycaps;
	int ret;

	test_msg("Aux thread runs as UID: %d; GID: %d\n", getuid(), getgid());

	newcaps = cap_from_text("cap_setgid,cap_setuid=+eip");
	if (!newcaps) {
		pr_perror("Failed to get capability struct");
		exit(1);
	}

	ret = cap_set_proc(newcaps);
	if (ret) {
		pr_perror("Failed to set capabilities for the process");
		exit(1);
	}

	mycaps = cap_get_proc();
	if (!mycaps) {
		pr_perror("Failed to get child thread capabilities");
		exit_group(2);
	}

	test_msg("Child capabilities: %s\n", cap_to_text(mycaps, NULL));
	test_msg("Changing UID/GID in child thread to %d:%d\n", uid, gid);

	ret = syscall(SYS_setresgid, gid, gid, gid);
	if (ret >= 0) {
		syscall(SYS_setresuid, uid, uid, uid);
	} else if (ret < 0) {
		pr_perror("Failed to change UID/GID");
		exit_group(2);
	}

	gid = getgid();
	uid = getuid();
	test_msg("Now aux thread runs as UID: %d; GID: %d\n", uid, gid);

	test_msg("Child thread is waiting for main thread's signal\n");
	task_waiter_complete(&t, 1);

	pthread_mutex_lock(&mutex);
	while (!done) {
		pthread_cond_wait(&cond, &mutex);
	}
	pthread_mutex_unlock(&mutex);

	test_msg("Child thread returns\n");
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t diff_cred_thread;
	cap_t newcaps;
	int maingroup;
	int mainuser;
	int ret;

	test_init(argc, argv);
	task_waiter_init(&t);

	if (getuid() != 0) {
		fail("Test is expected to be run with root privileges");
		exit(1);
	}

	test_msg("Acquiring CAP_SETGID and CAP_SETUID...\n");

	newcaps = cap_from_text("cap_setgid,cap_setuid=+eip");
	if (!newcaps) {
		pr_perror("Failed to get capability struct");
		exit(1);
	}
	ret = cap_set_proc(newcaps);
	if (ret) {
		pr_perror("Failed to set capabilities for the process");
		exit(1);
	}
	ret = prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	if (ret) {
		pr_perror("Unable to set KEEPCAPS");
		exit(1);
	}

	test_msg("Main thread runs as UID: %d; GID: %d\n", getuid(), getgid());
	gid = 99;
	uid = 99;
	maingroup = 8;
	mainuser = 12;

	test_msg("Creating thread with different UID/GID\n");
	ret = pthread_create(&diff_cred_thread, NULL, &chg_uid_gid, NULL);
	task_waiter_wait4(&t, 1);

	test_msg("Relinquishing root privileges\n");
	ret = syscall(SYS_setresgid, maingroup, maingroup, maingroup);
	if (ret >= 0) {
		ret = syscall(SYS_setresuid, mainuser, mainuser, mainuser);
	} else {
		pr_perror("Failed to drop privileges");
		exit(1);
	}
	test_msg("Now main thread runs as UID: %d; GID: %d\n", getuid(), getgid());
	if (gid == getgid() || uid == getuid()) {
		pr_perror("Thread credentials match");
		exit(1);
	}
	test_msg("Main thread is waiting for signal\n");

	test_daemon();
	test_waitsig();

	if (gid == getgid() || uid == getuid()) {
		pr_perror("Thread credentials match after restore");
		exit(1);
	}

	pthread_mutex_lock(&mutex);
	done = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
	pthread_join(diff_cred_thread, NULL);
	test_msg("Threads joined\n");

	pass();

	return 0;
}
