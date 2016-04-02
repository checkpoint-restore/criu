define FEATURE_TEST_TCP_REPAIR

#include <netinet/tcp.h>

int main(void)
{
	struct tcp_repair_opt opts;
	opts.opt_code = TCP_NO_QUEUE;
	opts.opt_val = 0;

	return opts.opt_val;
}
endef

define FEATURE_TEST_LIBBSD_DEV
#include <bsd/string.h>

int main(void)
{
	return 0;
}
endef

define FEATURE_TEST_STRLCPY

#include <string.h>

#ifdef CONFIG_HAS_LIBBSD
# include <bsd/string.h>
#endif

int main(void)
{
	return strlcpy(NULL, NULL, 0);
}
endef

define FEATURE_TEST_STRLCAT

#include <string.h>

#ifdef CONFIG_HAS_LIBBSD
# include <bsd/string.h>
#endif

int main(void)
{
	return strlcat(NULL, NULL, 0);
}
endef

define FEATURE_TEST_PTRACE_PEEKSIGINFO

#include <sys/ptrace.h>

int main(void)
{
	struct ptrace_peeksiginfo_args args = {};

	return 0;
}

endef

define FEATURE_TEST_SETPROCTITLE_INIT

#include <bsd/unistd.h>

int main(int argc, char *argv[], char *envp[])
{
	setproctitle_init(argc, argv, envp);

	return 0;
}

endef

define FEATURE_TEST_MEMFD

#include <unistd.h>
#include <sys/syscall.h>

int main(void)
{
#ifdef __NR_memfd_create
	return 0;
#else
# error No memfd support
#endif
}

endef
