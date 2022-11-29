#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <linux/in.h>
#include <linux/in6.h>

#include "zdtmtst.h"

const char *test_doc = "Check that different ip socket options are restored";
const char *test_author = "Pavel Tikhomirov <ptikhomirov@virtuozzo.com>";

#ifdef ZDTM_VAL_ZERO
#define IP_OPT_VAL 0
#else
#define IP_OPT_VAL 1
#endif

struct sk_opt {
	int level;
	int opt;
};

struct sk_opt sk_opts_v4[] = {
	{ SOL_IP, IP_FREEBIND },
	{ SOL_IP, IP_PKTINFO },
};

#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif

struct sk_opt sk_opts_v6[] = {
	{ SOL_IPV6, IPV6_FREEBIND },
	{ SOL_IPV6, IPV6_RECVPKTINFO },
};

struct sk_conf {
	int domain;
	int type;
	int protocol;
	int sk;
} sk_confs[] = {
	{ AF_INET, SOCK_DGRAM, IPPROTO_UDP },
	{ AF_INET, SOCK_RAW, IPPROTO_UDP },
	{ AF_INET6, SOCK_DGRAM, IPPROTO_UDP },
	{ AF_INET6, SOCK_RAW, IPPROTO_UDP },
};

int main(int argc, char **argv)
{
	struct sk_opt *opts;
	int exit_code = 1;
	int i, j, val;
	socklen_t len;
	int n_opts;

	test_init(argc, argv);

	for (i = 0; i < ARRAY_SIZE(sk_confs); i++) {
		sk_confs[i].sk = socket(sk_confs[i].domain, sk_confs[i].type, sk_confs[i].protocol);
		if (sk_confs[i].sk == -1) {
			pr_perror("socket(%d,%d,%d) failed", sk_confs[i].domain, sk_confs[i].type,
				  sk_confs[i].protocol);
			goto close;
		}
	}

	for (i = 0; i < ARRAY_SIZE(sk_confs); i++) {
		opts = sk_confs[i].domain == AF_INET ? sk_opts_v4 : sk_opts_v6;
		n_opts = sk_confs[i].domain == AF_INET ? ARRAY_SIZE(sk_opts_v4) : ARRAY_SIZE(sk_opts_v6);

		for (j = 0; j < n_opts; j++) {
			val = IP_OPT_VAL;
			if (setsockopt(sk_confs[i].sk, opts[j].level, opts[j].opt, &val, sizeof(int)) == -1) {
				pr_perror("setsockopt(%d, %d) failed", opts[j].level, opts[j].opt);
				goto close;
			}
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < ARRAY_SIZE(sk_confs); i++) {
		opts = sk_confs[i].domain == AF_INET ? sk_opts_v4 : sk_opts_v6;
		n_opts = sk_confs[i].domain == AF_INET ? ARRAY_SIZE(sk_opts_v4) : ARRAY_SIZE(sk_opts_v6);

		for (j = 0; j < n_opts; j++) {
			len = sizeof(int);
			if (getsockopt(sk_confs[i].sk, opts[j].level, opts[j].opt, &val, &len) == -1) {
				pr_perror("getsockopt(%d, %d) failed", opts[j].level, opts[j].opt);
				goto close;
			}

			if (val != IP_OPT_VAL) {
				fail("Unexpected value socket(%d,%d,%d) opts(%d,%d)", sk_confs[i].domain,
				     sk_confs[i].type, sk_confs[i].protocol, opts[j].level, opts[j].opt);
				goto close;
			}
		}
	}

	pass();
	exit_code = 0;
close:
	for (i = 0; i < ARRAY_SIZE(sk_confs); i++)
		close(sk_confs[i].sk);
	return exit_code;
}
