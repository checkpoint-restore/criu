#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "zdtmtst.h"

const char *test_doc = "Check inet socket uid is preserved after C/R";
const char *test_author = "Cyrill Troxler <cyrilltroxler@gmail.com>";

#define TEST_UID 12345

static const struct sk_test {
	const char *name;
	int family;
	int type;
	int proto;
	bool bind;
} sockets[] = {
	{ "tcp", AF_INET, SOCK_STREAM, IPPROTO_TCP, true },
	{ "udp", AF_INET, SOCK_DGRAM, IPPROTO_UDP, true },
	{ "tcp6", AF_INET6, SOCK_STREAM, IPPROTO_TCP, true },
	{ "udp6", AF_INET6, SOCK_DGRAM, IPPROTO_UDP, true },
	{ "tcp-unbound", AF_INET, SOCK_STREAM, IPPROTO_TCP, false },
	{ "udp-unbound", AF_INET, SOCK_DGRAM, IPPROTO_UDP, false },
	{ "tcp6-unbound", AF_INET6, SOCK_STREAM, IPPROTO_TCP, false },
	{ "udp6-unbound", AF_INET6, SOCK_DGRAM, IPPROTO_UDP, false },
};

#define NSOCKS (sizeof(sockets) / sizeof(*sockets))

int main(int argc, char **argv)
{
	int fds[NSOCKS];
	struct stat st;
	uid_t expected_uid;
	unsigned int i;

	test_init(argc, argv);

	expected_uid = getuid() == 0 ? TEST_UID : getuid();

	for (i = 0; i < NSOCKS; i++) {
		const struct sk_test *s = &sockets[i];
		union {
			struct sockaddr_in v4;
			struct sockaddr_in6 v6;
		} addr = {};
		socklen_t alen;

		fds[i] = socket(s->family, s->type, s->proto);
		if (fds[i] < 0) {
			pr_perror("can't create %s socket", s->name);
			return 1;
		}

		if (s->family == AF_INET) {
			addr.v4.sin_family = AF_INET;
			addr.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			alen = sizeof(addr.v4);
		} else {
			addr.v6.sin6_family = AF_INET6;
			addr.v6.sin6_addr = (struct in6_addr)IN6ADDR_LOOPBACK_INIT;
			alen = sizeof(addr.v6);
		}

		if (s->bind && bind(fds[i], (struct sockaddr *)&addr, alen)) {
			pr_perror("can't bind %s socket", s->name);
			return 1;
		}

		if (s->bind && s->type == SOCK_STREAM && listen(fds[i], 1)) {
			pr_perror("can't listen on %s socket", s->name);
			return 1;
		}

		if (expected_uid != getuid() && fchown(fds[i], expected_uid, -1)) {
			pr_perror("can't chown %s socket to %d", s->name, (int)expected_uid);
			return 1;
		}

		if (fstat(fds[i], &st)) {
			pr_perror("can't fstat %s socket", s->name);
			return 1;
		}

		if (st.st_uid != expected_uid) {
			pr_err("%s socket uid is %d, expected %d\n", s->name, (int)st.st_uid, (int)expected_uid);
			return 1;
		}
	}

	test_daemon();
	test_waitsig();

	for (i = 0; i < NSOCKS; i++) {
		if (fstat(fds[i], &st)) {
			pr_perror("can't fstat %s socket after C/R", sockets[i].name);
			return 1;
		}

		if (st.st_uid != expected_uid) {
			fail("%s socket uid changed: %d -> %d", sockets[i].name, (int)expected_uid, (int)st.st_uid);
			return 1;
		}
	}

	for (i = 0; i < NSOCKS; i++)
		close(fds[i]);

	pass();
	return 0;
}
