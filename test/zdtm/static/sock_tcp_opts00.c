#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "zdtmtst.h"

const char *test_doc = "Check that different tcp socket options are restored";
const char *test_author = "Juntong Deng <juntong.deng@outlook.com>";

#ifdef ZDTM_VAL_ZERO
#define TCP_OPT_VAL 0
#else
#define TCP_OPT_VAL 1
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

struct sk_opt {
	int level;
	int opt;
	int val;
};

struct sk_opt tcp_sk_opts[] = {
	{ SOL_TCP, TCP_CORK, TCP_OPT_VAL },
	{ SOL_TCP, TCP_NODELAY, TCP_OPT_VAL },
};

struct sk_conf {
	int domain;
	int type;
	int protocol;
	int sk;
} sk_confs[] = {
	{ AF_INET, SOCK_STREAM, IPPROTO_TCP },
	{ AF_INET6, SOCK_STREAM, IPPROTO_TCP },
};

int main(int argc, char **argv)
{
	struct sk_opt *opts = tcp_sk_opts;
	int n_opts = ARRAY_SIZE(tcp_sk_opts);
	int exit_code = 1;
	int i, j, val;
	socklen_t len;

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
		for (j = 0; j < n_opts; j++) {
			val = opts[j].val;
			if (setsockopt(sk_confs[i].sk, opts[j].level, opts[j].opt, &val, sizeof(int)) == -1) {
				pr_perror("setsockopt(%d, %d) failed", opts[j].level, opts[j].opt);
				goto close;
			}
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < ARRAY_SIZE(sk_confs); i++) {
		for (j = 0; j < n_opts; j++) {
			len = sizeof(int);
			if (getsockopt(sk_confs[i].sk, opts[j].level, opts[j].opt, &val, &len) == -1) {
				pr_perror("getsockopt(%d, %d) failed", opts[j].level, opts[j].opt);
				goto close;
			}

			if (val != opts[j].val) {
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
