define TCP_REPAIR_TEST

#include <netinet/tcp.h>

int main(void)
{
	struct tcp_repair_opt opts;
	opts.opt_code = TCP_NO_QUEUE;
	opts.opt_val = 0;

	return opts.opt_val;
}
endef

define PRLIMIT_TEST

#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

int main(void)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	return prlimit(getpid(), RLIMIT_CPU, &limit, NULL);
}
endef

define STRLCPY_TEST

#include <string.h>

int main(void)
{
	char src[32] = "strlcpy";
	char dst[32];

	return strlcpy(dst, src, sizeof(dst));
}
endef
