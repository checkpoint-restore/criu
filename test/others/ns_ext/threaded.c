#include <errno.h>
#include <pthread.h>

#include "criu-plugin.h"
#include "criu-log.h"

static void *thread_main(void *arg)
{
	return arg;
}

static int resume_devices_late(int pid)
{
	pthread_t thread;
	void *result;
	int ret;

	ret = pthread_create(&thread, NULL, thread_main, &pid);
	if (ret) {
		errno = ret;
		pr_perror("pidns-thread-test: cannot create plugin thread");
		return -ret;
	}
	ret = pthread_join(thread, &result);
	if (ret) {
		errno = ret;
		pr_perror("pidns-thread-test: cannot join plugin thread");
		return -ret;
	}
	if (result != &pid)
		return -EINVAL;
	pr_info("pidns-thread-test: plugin thread completed for %d\n", pid);
	return 0;
}

CR_PLUGIN_REGISTER_DUMMY("pidns-thread-test")
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, resume_devices_late)
