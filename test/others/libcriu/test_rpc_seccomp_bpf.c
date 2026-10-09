#include "criu.h"

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdlib.h>
#include <stdio.h>

static int expect_ret(const char *what, int got, int want)
{
	if (got != want) {
		fprintf(stderr, "%s: expected %d, got %d\n", what, want, got);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct sock_filter allow[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	char bad_len[sizeof(struct sock_filter) + 1];
	int ret = 0;

	(void)argc;
	(void)argv;

	criu_init_opts();

	ret |= expect_ret("NULL BPF", criu_set_seccomp_bpf(NULL, sizeof(allow)), -EINVAL);
	ret |= expect_ret("zero-length BPF", criu_set_seccomp_bpf(allow, 0), -EINVAL);
	ret |= expect_ret("misaligned BPF", criu_set_seccomp_bpf(bad_len, sizeof(bad_len)), -EINVAL);
	ret |= expect_ret("flags before BPF", criu_set_seccomp_bpf_flags(0), -EINVAL);
	ret |= expect_ret("valid BPF", criu_set_seccomp_bpf(allow, sizeof(allow)), 0);
	ret |= expect_ret("valid flags", criu_set_seccomp_bpf_flags(SECCOMP_FILTER_FLAG_TSYNC), 0);
	ret |= expect_ret("listener flag", criu_set_seccomp_bpf_flags(SECCOMP_FILTER_FLAG_NEW_LISTENER), -EINVAL);
	ret |= expect_ret("unsupported flags", criu_set_seccomp_bpf_flags(0xffffffff), -EINVAL);

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
