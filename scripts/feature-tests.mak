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

define LIBBSD_DEV_TEST
#include <bsd/string.h>

int main(void)
{
	return 0;
}
endef

define STRLCPY_TEST

#include <string.h>

#ifdef CONFIG_HAS_LIBBSD
# include <bsd/string.h>
#endif

int main(void)
{
	return strlcpy(NULL, NULL, 0);
}
endef

define STRLCAT_TEST

#include <string.h>

#ifdef CONFIG_HAS_LIBBSD
# include <bsd/string.h>
#endif

int main(void)
{
	return strlcat(NULL, NULL, 0);
}
endef

define PTRACE_PEEKSIGINFO_TEST

#include <sys/ptrace.h>

int main(void)
{
	struct ptrace_peeksiginfo_args args = {};

	return 0;
}

endef
