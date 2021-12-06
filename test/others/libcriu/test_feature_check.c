#include "criu.h"
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib.h"

int main(int argc, char **argv)
{
	int ret;
	char *env;
	bool mem_track = 0;
	bool lazy_pages = 0;
	bool pidfd_store = 0;
	struct criu_feature_check features = {
		.mem_track = true,
		.lazy_pages = true,
		.pidfd_store = true,
	};

	printf("--- Start feature check ---\n");
	criu_init_opts();
	criu_set_service_binary(argv[1]);

	env = getenv("CRIU_FEATURE_MEM_TRACK");
	if (env) {
		mem_track = true;
	}
	env = getenv("CRIU_FEATURE_LAZY_PAGES");
	if (env) {
		lazy_pages = true;
	}
	env = getenv("CRIU_FEATURE_PIDFD_STORE");
	if (env) {
		pidfd_store = true;
	}

	ret = criu_feature_check(&features, sizeof(features) + 1);
	printf("   `- passing too large structure to libcriu should return -1: %d\n", ret);
	if (ret != -1)
		return -1;

	ret = criu_feature_check(&features, sizeof(features));
	if (ret < 0) {
		what_err_ret_mean(ret);
		return ret;
	}

	printf("   `- mem_track  : %d - expected : %d\n", features.mem_track, mem_track);
	if (features.mem_track != mem_track)
		return -1;
	printf("   `- lazy_pages : %d - expected : %d\n", features.lazy_pages, lazy_pages);
	if (features.lazy_pages != lazy_pages)
		return -1;
	printf("   `- pidfd_store: %d - expected : %d\n", features.pidfd_store, pidfd_store);
	if (features.pidfd_store != pidfd_store)
		return -1;

	return 0;
}
