#include "rpc.pb-c.h"
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <dirent.h>

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

	if (criu_req__pack(req, buf) != len) {
		perror("Failed packing request");
		return -1;
	}

	if (write(socket_fd, buf, len)  == -1) {
		perror("Can't send request");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	CriuReq req		= CRIU_REQ__INIT;
	CriuResp *resp		= NULL;
	int fd, dir_fd;
	int ret = 0;
	struct sockaddr_un addr;
	socklen_t addr_len;
	struct stat st = {0};

	if (argc != 3) {
		fprintf(stderr, "Usage: test-c criu-service.socket imgs_dir");
		return -1;
	}

	/*
	 * Open a directory, in which criu will
	 * put images
	 */

	puts(argv[2]);
	dir_fd = open(argv[2], O_DIRECTORY);
	if (dir_fd == -1) {
		perror("Can't open imgs dir");
		return -1;
	}

	/*
	 * Set "DUMP" type of request.
	 * Allocate CriuDumpReq.
	 */
	req.type			= CRIU_REQ_TYPE__DUMP;
	req.opts			= malloc(sizeof(CriuOpts));
	if (!req.opts) {
			perror("Can't allocate memory for dump request");
			return -1;
	}

	criu_opts__init(req.opts);

	/*
	 * Set dump options.
	 * Checkout more in protobuf/rpc.proto.
	 */
	req.opts->has_leave_running	= true;
	req.opts->leave_running		= true;
	req.opts->images_dir_fd		= dir_fd;
	req.opts->has_shell_job		= true;
	req.opts->shell_job		= true;
	req.opts->has_log_level		= true;
	req.opts->log_level		= 4;

	/*
	 * Connect to service socket
	 */
	fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (fd == -1) {
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;

	strcpy(addr.sun_path, argv[1]);

	addr_len = strlen(addr.sun_path) + sizeof(addr.sun_family);

	ret = connect(fd, (struct sockaddr *) &addr, addr_len);
	if (ret == -1) {
		perror("Cant connect to socket");
		goto exit;
	}

	/*
	 * Send request
	 */
	ret = send_req(fd, &req);
	if (ret == -1) {
		perror("Can't send request");
		goto exit;
	}

	/*
	 * Recv response
	 */
	resp = recv_resp(fd);
	if (!resp) {
		perror("Can't recv response");
		ret = -1;
		goto exit;
	}

	if (resp->type != CRIU_REQ_TYPE__DUMP) {
		perror("Unexpected response type");
		ret = -1;
		goto exit;
	}

	/*
	 * Check response.
	 */
	if (resp->success)
		puts("Success");
	else {
		puts("Fail");
		ret = -1;
		goto exit;
	}

	if (resp->dump->has_restored && resp->dump->restored)
		puts("Restored");

exit:
	close(fd);
	close(dir_fd);
	criu_resp__free_unpacked(resp, NULL);
	return ret;
}
