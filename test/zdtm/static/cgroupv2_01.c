#include <sys/mount.h>
#include <sys/stat.h>
#include <pthread.h>
#include <syscall.h>

#include "zdtmtst.h"

const char *test_doc = "Check that cgroup-v2 threaded controllers";
const char *test_author = "Bui Quang Minh <minhquangbui99@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup-v2 directory name", 1);
const char *cgname = "subcg01";

task_waiter_t t;

#define gettid(code) syscall(__NR_gettid)

void cleanup(void)
{
	char path[1024];

	sprintf(path, "%s/%s/%s", dirname, cgname, "thread2");
	rmdir(path);
	sprintf(path, "%s/%s/%s", dirname, cgname, "thread1");
	rmdir(path);
	sprintf(path, "%s/%s", dirname, cgname);
	rmdir(path);
	sprintf(path, "%s", dirname);
	umount(path);
}

int is_in_cgroup(char *cgname)
{
	FILE *cgf;
	char buffer[1024];

	sprintf(buffer, "/proc/self/task/%ld/cgroup", gettid());
	cgf = fopen(buffer, "r");
	if (cgf == NULL) {
		pr_err("Fail to open thread's cgroup procfs\n");
		return 0;
	}

	while (fgets(buffer, sizeof(buffer), cgf)) {
		if (strstr(buffer, cgname)) {
			fclose(cgf);
			return 1;
		}
	}

	fclose(cgf);
	return 0;
}

void *thread_func(void *arg)
{
	char path[1024], aux[1024];

	sprintf(path, "%s/%s/%s/%s", dirname, cgname, "thread2", "cgroup.threads");
	sprintf(aux, "%ld", gettid());
	if (write_value(path, aux)) {
		cleanup();
		exit(1);
	}

	read_value(path, aux, sizeof(aux));

	task_waiter_complete(&t, 1);

	/* Wait for restore */
	task_waiter_wait4(&t, 2);

	sprintf(path, "/%s/%s", cgname, "thread2");
	if (!is_in_cgroup(path)) {
		fail("Thread2's cgroup is not restored");
		cleanup();
		exit(1);
	}

	return NULL;
}

int main(int argc, char **argv)
{
	char path[1024], aux[1024];
	pthread_t thread2;
	int ret = 1;

	test_init(argc, argv);
	task_waiter_init(&t);

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}

	if (mount("cgroup2", dirname, "cgroup2", 0, NULL)) {
		pr_perror("Can't mount cgroup-v2");
		return -1;
	}

	sprintf(path, "%s/%s", dirname, cgname);
	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		goto out;
	}

	/* Make cpuset controllers available in children directory */
	sprintf(path, "%s/%s", dirname, "cgroup.subtree_control");
	sprintf(aux, "%s", "+cpuset");
	if (write_value(path, aux))
		goto out;

	sprintf(path, "%s/%s/%s", dirname, cgname, "cgroup.subtree_control");
	sprintf(aux, "%s", "+cpuset");
	if (write_value(path, aux))
		goto out;

	sprintf(path, "%s/%s/%s", dirname, cgname, "cgroup.procs");
	sprintf(aux, "%d", getpid());
	if (write_value(path, aux))
		goto out;

	sprintf(path, "%s/%s/%s", dirname, cgname, "thread1");
	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		goto out;
	}

	sprintf(path, "%s/%s/%s/%s", dirname, cgname, "thread1", "cgroup.type");
	sprintf(aux, "%s", "threaded");
	if (write_value(path, aux))
		goto out;

	sprintf(path, "%s/%s/%s", dirname, cgname, "thread2");
	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		goto out;
	}

	sprintf(path, "%s/%s/%s/%s", dirname, cgname, "thread2", "cgroup.type");
	sprintf(aux, "%s", "threaded");
	if (write_value(path, aux))
		goto out;

	ret = pthread_create(&thread2, NULL, thread_func, NULL);
	if (ret < 0) {
		pr_err("pthread_create %s\n", strerror(ret));
		ret = 1;
		goto out;
	}

	sprintf(path, "%s/%s/%s/%s", dirname, cgname, "thread1", "cgroup.threads");
	sprintf(aux, "%ld", gettid());
	if (write_value(path, aux))
		goto out;

	task_waiter_wait4(&t, 1);

	test_daemon();
	test_waitsig();

	task_waiter_complete(&t, 2);

	sprintf(path, "/%s/%s", cgname, "thread1");
	if (!is_in_cgroup(path)) {
		fail("Main thread's cgroup is not restored");
		cleanup();
		exit(1);
	}
	pthread_join(thread2, NULL);
	pass();

	ret = 0;

out:
	cleanup();
	return ret;
}
