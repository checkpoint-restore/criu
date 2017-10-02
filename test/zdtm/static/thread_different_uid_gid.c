/*
 * Check that we can dump a process with threads having mismatching UID/GID
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <syscall.h>

#include <sys/capability.h>
#include <sys/prctl.h>
#include <pthread.h>

#include "zdtmtst.h"

#define exit_group(code)	\
	syscall(__NR_exit_group, code)

const char *test_doc	= "Acquire UID/GID setting caps, create thread and drop thread to non-root by changing UID/GID\n";
const char *test_author	= "Vitaly Ostrosablin <vostrosablin@virtuozzo.com>";

unsigned int gid;
unsigned int uid;
pthread_mutex_t mutex  = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cond   = PTHREAD_COND_INITIALIZER;

int done = 0;

void *chg_uid_gid(void *arg)
{
	int ret;
	cap_t mycaps;
	cap_t newcaps;
	test_msg("Aux thread runs as UID: %d; GID: %d\n", getuid(), getgid());
	newcaps = cap_from_text("cap_setgid,cap_setuid=+eip");
	if (!newcaps)
	{
		pr_perror("Failed to get capability struct\n");
		exit(1);
	}
	ret = cap_set_proc(newcaps);
	if (ret) {
		pr_perror("Failed to set capabilities for the process\n");
		exit(1);
	}
	mycaps = cap_get_proc();
	if (!mycaps) {
		pr_perror("Failed to get child thread capabilities\n");
		exit_group(2);
	}
	test_msg("Child capabilities: %s\n", cap_to_text(mycaps, NULL));
	test_msg("Changing UID/GID in child thread to %d:%d\n", uid, gid);
	ret = syscall(SYS_setresgid, gid, gid, gid);
	if (ret >= 0) {
		syscall(SYS_setresuid, uid, uid, uid);
	}
	if (ret < 0) {
		pr_perror("Failed to change UID/GID\n");
		exit_group(2);
	}
	gid = getgid();
	uid = getuid();
	test_msg("Now aux thread runs as UID: %d; GID: %d\n", uid, gid);
	test_msg("Child thread is waiting for main thread's signal\n");
	pthread_mutex_lock(&mutex);
	while (!done)
	{
		pthread_cond_wait(&cond, &mutex);
	}
	pthread_mutex_unlock(&mutex);

	test_msg("Child thread returns\n");
	return NULL;
}

int main(int argc, char **argv)
{

	int ret;
	cap_t newcaps;
	struct group *group;
	struct passwd *user;
	pthread_t diff_cred_thread;
	test_init(argc, argv);
	int maingroup;
	int mainuser;

	if (getuid() != 0) {
		fail("Test is expected to be run with root privileges\n");
		exit(1);
	}

	test_daemon();
	test_msg("Test daemonized\n");

	test_msg("Acquiring CAP_SETGID and CAP_SETUID...\n");
	newcaps = cap_from_text("cap_setgid,cap_setuid=+eip");
	if (!newcaps)
	{
		pr_perror("Failed to get capability struct\n");
		exit(1);
	}
	ret = cap_set_proc(newcaps);
	if (ret) {
		pr_perror("Failed to set capabilities for the process\n");
		exit(1);
	}
	ret = prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
	if (ret) {
		pr_perror("Unable to set KEEPCAPS\n");
		exit(1);
	}

	test_msg("Main thread runs as UID: %d; GID: %d\n", getuid(), getgid());
	group = getgrnam("nogroup");
	group = (group) ? group : getgrnam("nobody");
	if (!group) {
		pr_perror("Failed to get nogroup/nobody GID\n");
		exit(1);
	}
	user = getpwnam("nobody");
	if (!user) {
		pr_perror("Failed to get nobody UID\n");
		exit(1);
	}
	gid = group->gr_gid;
	uid = user->pw_uid;
	group = getgrnam("mail");
	if (!group) {
		pr_perror("Failed to get mail GID\n");
		exit(1);
	}
	user = getpwnam("mail");
	if (!user) {
		pr_perror("Failed to get mail UID\n");
		exit(1);
	}
	maingroup = group->gr_gid;
	mainuser = user->pw_uid;

	test_msg("Creating thread with different UID/GID\n");
	ret = pthread_create(&diff_cred_thread, NULL, &chg_uid_gid, NULL);
	sleep(5);
	test_msg("Relinquishing root privileges\n");
	ret = syscall(SYS_setresgid, maingroup, maingroup, maingroup);
	if (ret >= 0) {
		ret = syscall(SYS_setresuid, mainuser, mainuser, mainuser);
	}
	if (ret < 0) {
		pr_perror("Failed to drop privileges\n");
		exit(1);
	}
	test_msg("Now main thread runs as UID: %d; GID: %d\n", getuid(), getgid());
	if (gid == getgid() || uid == getuid()) {
		pr_perror("Thread credentials match\n");
		exit(1);
	}
	test_msg("Main thread is waiting for signal\n");

	test_waitsig();

	if (gid == getgid() || uid == getuid()) {
		pr_perror("Thread credentials match after restore\n");
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
