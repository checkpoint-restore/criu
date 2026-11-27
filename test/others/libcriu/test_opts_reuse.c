#include "criu.h"
#include "rpc.pb-c.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_ALLOCS 256

static void *allocs[MAX_ALLOCS];
static int nr_allocs;
static int fail_at = -1;
static void *protected_allocs[MAX_ALLOCS];
static int nr_protected;

void *__real_malloc(size_t size);
char *__real_strdup(const char *s);
void __real_free(void *p);

static int allocation_fails(void)
{
	if (fail_at < 0)
		return 0;
	if (fail_at--)
		return 0;
	errno = ENOMEM;
	return 1;
}

static void *record_alloc(void *p)
{
	if (p) {
		if (nr_allocs == MAX_ALLOCS) {
			fprintf(stderr, "allocation table full\n");
			exit(1);
		}
		allocs[nr_allocs++] = p;
	}
	return p;
}

void *__wrap_malloc(size_t size)
{
	return allocation_fails() ? NULL : record_alloc(__real_malloc(size));
}

char *__wrap_strdup(const char *s)
{
	return allocation_fails() ? NULL : record_alloc(__real_strdup(s));
}

void __wrap_free(void *p)
{
	int i;

	for (i = 0; i < nr_protected; i++) {
		if (protected_allocs[i] == p) {
			fprintf(stderr, "failed set freed an existing allocation\n");
			exit(1);
		}
	}
	for (i = 0; i < nr_allocs; i++) {
		if (allocs[i] == p) {
			allocs[i] = allocs[--nr_allocs];
			break;
		}
	}
	__real_free(p);
}

static int check_options(criu_opts *opts, int argc, char **argv,
			 const char *address, int port)
{
	unsigned char buf[4096];
	CriuResp resp = CRIU_RESP__INIT;
	CriuReq *req;
	struct timeval timeout = { .tv_sec = 1 };
	int sk[2], len, i, ret = 1;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sk)) {
		perror("socketpair");
		return 1;
	}
	if (setsockopt(sk[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    setsockopt(sk[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		perror("setsockopt");
		close(sk[0]);
		goto out;
	}
	resp.type = CRIU_REQ_TYPE__DUMP;
	resp.success = false;
	len = criu_resp__pack(&resp, buf);
	if (send(sk[1], buf, len, 0) != len) {
		perror("send");
		close(sk[0]);
		goto out;
	}
	criu_local_set_service_fd(opts, sk[0]);
	criu_local_set_pid(opts, getpid());
	if (criu_local_dump(opts) != -EBADE) {
		fprintf(stderr, "unexpected dump result\n");
		goto out;
	}
	len = recv(sk[1], buf, sizeof(buf), MSG_TRUNC);
	if (len <= 0 || (size_t)len > sizeof(buf)) {
		fprintf(stderr, "invalid request size: %d\n", len);
		goto out;
	}
	req = criu_req__unpack(NULL, len, buf);
	if (!req || req->type != CRIU_REQ_TYPE__DUMP || !req->opts) {
		fprintf(stderr, "invalid dump request\n");
		if (req)
			criu_req__free_unpacked(req, NULL);
		goto out;
	}
	if (req->opts->n_exec_cmd != (size_t)argc)
		goto free_req;
	for (i = 0; i < argc; i++)
		if (strcmp(req->opts->exec_cmd[i], argv[i]))
			goto free_req;
	if (address) {
		if (!req->opts->ps || !req->opts->ps->address ||
		    strcmp(req->opts->ps->address, address) ||
		    !req->opts->ps->has_port || req->opts->ps->port != port)
			goto free_req;
	} else if (req->opts->ps) {
		goto free_req;
	}
	ret = 0;
free_req:
	criu_req__free_unpacked(req, NULL);
	if (ret)
		fprintf(stderr, "serialized options differ\n");
out:
	close(sk[1]);
	return ret;
}

static char *first[] = { "first", "command" };
static char *second[] = { "second", "same", "same" };

static int test_exec_cmd(int existing, int failure)
{
	criu_opts *opts = NULL;
	int ret = 1;

	if (criu_local_init_opts(&opts))
		return 1;
	if (criu_local_set_page_server_address_port(opts, "127.0.0.1", 1234))
		goto out;
	if (existing && criu_local_set_exec_cmd(opts, 2, first))
		goto out;
	if (failure >= 0) {
		memcpy(protected_allocs, allocs, nr_allocs * sizeof(allocs[0]));
		nr_protected = nr_allocs;
	}
	fail_at = failure;
	ret = criu_local_set_exec_cmd(opts, 3, second);
	fail_at = -1;
	nr_protected = 0;
	if (ret != (failure < 0 ? 0 : -ENOMEM)) {
		fprintf(stderr, "exec_cmd result: %d (failure %d)\n", ret, failure);
		ret = 1;
		goto out;
	}
	ret = check_options(opts, failure < 0 ? 3 : (existing ? 2 : 0),
			    failure < 0 ? second : first, "127.0.0.1", 1234);
	if (!ret && failure >= 0) {
		ret = criu_local_set_exec_cmd(opts, 3, second);
		if (!ret)
			ret = check_options(opts, 3, second, "127.0.0.1", 1234);
	}
out:
	criu_local_free_opts(opts);
	return ret || nr_allocs;
}

static int test_page_server(int existing, int failure)
{
	const char *address = existing ? "127.0.0.1" : NULL;
	criu_opts *opts = NULL;
	int ret = 1;

	if (criu_local_init_opts(&opts))
		return 1;
	if (criu_local_set_exec_cmd(opts, 2, first))
		goto out;
	if (existing && criu_local_set_page_server_address_port(opts, "127.0.0.1", 1234))
		goto out;
	if (failure >= 0) {
		memcpy(protected_allocs, allocs, nr_allocs * sizeof(allocs[0]));
		nr_protected = nr_allocs;
	}
	fail_at = failure;
	ret = criu_local_set_page_server_address_port(opts, "127.0.0.2", 4321);
	fail_at = -1;
	nr_protected = 0;
	if (ret != (failure < 0 ? 0 : -ENOMEM)) {
		fprintf(stderr, "page-server result: %d (failure %d)\n", ret, failure);
		ret = 1;
		goto out;
	}
	if (failure < 0)
		address = "127.0.0.2";
	ret = check_options(opts, 2, first, address, failure < 0 ? 4321 : 1234);
	if (!ret && failure >= 0) {
		ret = criu_local_set_page_server_address_port(opts, "127.0.0.2", 4321);
		if (!ret)
			ret = check_options(opts, 2, first, "127.0.0.2", 4321);
	}
out:
	criu_local_free_opts(opts);
	return ret || nr_allocs;
}

static int test_boundaries(void)
{
	criu_opts *opts = NULL;
	char value[] = "copied";
	char *one[] = { value };
	char *expected[] = { "copied" };
	char *many[64];
	int i, ret = 1;

	for (i = 0; i < 64; i++)
		many[i] = "same";
	if (criu_local_init_opts(&opts))
		return 1;
	if (criu_local_set_exec_cmd(opts, 1, one))
		goto out;
	value[0] = 'X';
	if (check_options(opts, 1, expected, NULL, 0) ||
	    criu_local_set_exec_cmd(opts, 64, many) ||
	    check_options(opts, 64, many, NULL, 0) ||
	    criu_local_set_exec_cmd(opts, 0, NULL) ||
	    check_options(opts, 0, NULL, NULL, 0))
		goto out;
	ret = 0;
out:
	criu_local_free_opts(opts);
	return ret || nr_allocs;
}

int main(void)
{
	int existing, failure;

	for (existing = 1; existing >= 0; existing--) {
		for (failure = -1; failure < 4; failure++) {
			if (test_exec_cmd(existing, failure)) {
				fprintf(stderr, "exec_cmd: existing %d, failure %d, allocations %d\n",
					existing, failure, nr_allocs);
				return 1;
			}
		}
		for (failure = -1; failure < (existing ? 1 : 2); failure++) {
			if (test_page_server(existing, failure)) {
				fprintf(stderr, "page-server: existing %d, failure %d, allocations %d\n",
					existing, failure, nr_allocs);
				return 1;
			}
		}
	}
	if (test_boundaries()) {
		fprintf(stderr, "exec_cmd boundaries failed\n");
		return 1;
	}
	puts("option setter reuse: PASS");
	return 0;
}
