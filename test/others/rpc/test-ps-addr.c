/*
 * Test that the page server binds to the address from an RPC request.
 *
 * When lazy_pages is enabled, setup_opts_from_req() must copy the
 * address string from req->ps->address into opts.addr. Previously,
 * the copy was inside the !opts.lazy_pages branch and was skipped,
 * so the page server would bind to 0.0.0.0 instead of the requested
 * address.
 *
 * This test sends a PAGE_SERVER request with lazy_pages enabled and
 * ps.address set to 127.0.0.1, then checks /proc/net/tcp to confirm
 * the page server actually bound to that address.
 *
 * The images directory must contain pstree.img and inventory.img
 * because the page server reads them on startup.
 */
#include "rpc.pb-c.h"
#include <arpa/inet.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_MSG_SIZE 1024

static CriuResp *recv_resp(int socket_fd)
{
	unsigned char buf[MAX_MSG_SIZE];
	int len;
	CriuResp *msg = 0;

	len = read(socket_fd, buf, MAX_MSG_SIZE);
	if (len == -1) {
		perror("Can't read response");
		return NULL;
	}

	msg = criu_resp__unpack(NULL, len, buf);
	if (!msg) {
		perror("Failed unpacking response");
		return NULL;
	}

	return msg;
}

static int send_req(int socket_fd, CriuReq *req)
{
	unsigned char buf[MAX_MSG_SIZE];
	int len;

	len = criu_req__get_packed_size(req);

	if (len > MAX_MSG_SIZE) {
		fprintf(stderr, "Request too large: %d > %d\n",
			len, MAX_MSG_SIZE);
		return -1;
	}

	if (criu_req__pack(req, buf) != len) {
		perror("Failed packing request");
		return -1;
	}

	if (write(socket_fd, buf, len) == -1) {
		perror("Can't send request");
		return -1;
	}

	return 0;
}

static int connect_to_service(const char *path)
{
	struct sockaddr_un addr;
	socklen_t addr_len;
	int fd;

	fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (fd == -1) {
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;

	if (strlen(path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "Socket path too long: %s\n", path);
		close(fd);
		return -1;
	}

	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1;

	if (connect(fd, (struct sockaddr *)&addr, addr_len) == -1) {
		perror("Can't connect to socket");
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Check that a listening socket on @port is bound to @expect_addr
 * by parsing /proc/net/tcp.
 *
 * Each line looks like:
 *   sl  local_address rem_address   st ...
 *    0: 0100007F:001B 00000000:0000 0A ...
 *
 * The local address is hex in network byte order. State 0A = LISTEN.
 */
static int check_listen_addr(int port, const char *expect_addr)
{
	FILE *f;
	char line[512];
	unsigned int local_addr, local_port, state;
	struct in_addr expected, found;

	if (inet_pton(AF_INET, expect_addr, &expected) != 1) {
		fprintf(stderr, "Bad expected address: %s\n", expect_addr);
		return -1;
	}

	f = fopen("/proc/net/tcp", "r");
	if (!f) {
		perror("Can't open /proc/net/tcp");
		return -1;
	}

	/* Skip header */
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, " %*d: %X:%X %*X:%*X %X",
			   &local_addr, &local_port, &state) != 3)
			continue;

		if (local_port != (unsigned int)port || state != 0x0A)
			continue;

		found.s_addr = local_addr;
		if (found.s_addr == expected.s_addr) {
			fclose(f);
			return 0;
		}

		fprintf(stderr, "Page server bound to %s:%d, expected %s:%d\n",
			inet_ntoa(found), port, expect_addr, port);
		fclose(f);
		return -1;
	}

	fprintf(stderr, "No listening socket found on port %d\n", port);
	fclose(f);
	return -1;
}

int main(int argc, char *argv[])
{
	CriuReq req = CRIU_REQ__INIT;
	CriuPageServerInfo ps = CRIU_PAGE_SERVER_INFO__INIT;
	CriuResp *resp = NULL;
	int fd = -1, dir_fd = -1, ret = 0;
	int ps_pid = 0;

	if (argc != 3) {
		fprintf(stderr, "Usage: test-ps-addr socket imgs_dir\n");
		return -1;
	}

	dir_fd = open(argv[2], O_DIRECTORY);
	if (dir_fd == -1) {
		perror("Can't open imgs dir");
		return -1;
	}

	req.type = CRIU_REQ_TYPE__PAGE_SERVER_CHLD;
	req.opts = malloc(sizeof(CriuOpts));
	if (!req.opts) {
		perror("Can't allocate memory");
		ret = -1;
		goto out;
	}

	criu_opts__init(req.opts);
	req.opts->images_dir_fd = dir_fd;
	req.opts->has_log_level = true;
	req.opts->log_level = 4;
	req.opts->log_file = "page-server-addr-test.log";
	req.opts->has_lazy_pages = true;
	req.opts->lazy_pages = true;

	ps.address = "127.0.0.1";
	ps.has_port = true;
	ps.port = 0;
	req.opts->ps = &ps;

	fd = connect_to_service(argv[1]);
	if (fd == -1) {
		ret = -1;
		goto out;
	}

	ret = send_req(fd, &req);
	if (ret == -1) {
		perror("Can't send request");
		goto out;
	}

	resp = recv_resp(fd);
	if (!resp) {
		perror("Can't recv response");
		ret = -1;
		goto out;
	}

	if (resp->type != CRIU_REQ_TYPE__PAGE_SERVER) {
		fprintf(stderr, "Unexpected response type %d\n", resp->type);
		ret = -1;
		goto out;
	}

	if (!resp->success) {
		fprintf(stderr, "Page server request failed\n");
		ret = -1;
		goto out;
	}

	ps_pid = resp->ps->pid;
	printf("Page server started on port %d (pid %d)\n",
	       resp->ps->port, ps_pid);

	if (check_listen_addr(resp->ps->port, "127.0.0.1")) {
		fprintf(stderr, "FAIL: page server did not bind to 127.0.0.1\n");
		ret = -1;
	} else {
		puts("PASS: page server bound to 127.0.0.1");
	}

out:
	if (ps_pid > 0) {
		kill(ps_pid, SIGKILL);
		waitpid(ps_pid, NULL, 0);
	}
	if (fd >= 0)
		close(fd);
	if (dir_fd >= 0)
		close(dir_fd);
	if (resp)
		criu_resp__free_unpacked(resp, NULL);
	return ret;
}
