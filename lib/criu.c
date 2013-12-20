#include "version.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "criu.h"
#include "rpc.pb-c.h"
#include "cr-service-const.h"

const char *criu_lib_version = CRIU_VERSION;

static char *service_address = CR_DEFAULT_SERVICE_ADDRESS;
static CriuOpts *opts;
static int saved_errno;

void criu_set_service_address(char *path)
{
	if (path)
		service_address = path;
	else
		service_address = CR_DEFAULT_SERVICE_ADDRESS;
}

int criu_init_opts(void)
{
	if (opts)
		criu_opts__free_unpacked(opts, NULL);

	opts = malloc(sizeof(CriuOpts));
	if (opts == NULL) {
		perror("Can't allocate memory for criu opts");
		return -1;
	}

	criu_opts__init(opts);
	return 0;
}

void criu_set_pid(int pid)
{
	opts->has_pid	= true;
	opts->pid	= pid;
}

void criu_set_images_dir_fd(int fd)
{
	opts->images_dir_fd = fd;
}

void criu_set_leave_running(bool leave_running)
{
	opts->has_leave_running	= true;
	opts->leave_running	= leave_running;
}

void criu_set_ext_unix_sk(bool ext_unix_sk)
{
	opts->has_ext_unix_sk	= true;
	opts->ext_unix_sk	= ext_unix_sk;
}

void criu_set_tcp_established(bool tcp_established)
{
	opts->has_tcp_established	= true;
	opts->tcp_established		= tcp_established;
}

void criu_set_evasive_devices(bool evasive_devices)
{
	opts->has_evasive_devices	= true;
	opts->evasive_devices		= evasive_devices;
}

void criu_set_shell_job(bool shell_job)
{
	opts->has_shell_job	= true;
	opts->shell_job		= shell_job;
}

void criu_set_file_locks(bool file_locks)
{
	opts->has_file_locks	= true;
	opts->file_locks	= file_locks;
}

void criu_set_log_level(int log_level)
{
	opts->has_log_level	= true;
	opts->log_level		= log_level;
}

void criu_set_log_file(char *log_file)
{
	opts->log_file = strdup(log_file);
}

static CriuResp *recv_resp(int socket_fd)
{
	unsigned char buf[CR_MAX_MSG_SIZE];
	int len;
	CriuResp *msg = 0;

	len = read(socket_fd, buf, CR_MAX_MSG_SIZE);
	if (len == -1) {
		perror("Can't read response");
		goto err;
	}

	msg = criu_resp__unpack(NULL, len, buf);
	if (!msg) {
		perror("Failed unpacking response");
		goto err;
	}

	return msg;
err:
	saved_errno = errno;
	return NULL;
}

static int send_req(int socket_fd, CriuReq *req)
{
	unsigned char buf[CR_MAX_MSG_SIZE];
	int len;

	len = criu_req__get_packed_size(req);

	if (criu_req__pack(req, buf) != len) {
		perror("Failed packing request");
		goto err;
	}

	if (write(socket_fd, buf, len)  == -1) {
		perror("Can't send request");
		goto err;
	}

	return 0;
err:
	saved_errno = errno;
	return -1;
}

static int criu_connect(void)
{
	int fd, ret;
	struct sockaddr_un addr;
	socklen_t addr_len;

	fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		saved_errno = errno;
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;

	strncpy(addr.sun_path, service_address, sizeof(addr.sun_path));

	addr_len = strlen(addr.sun_path) + sizeof(addr.sun_family);

	ret = connect(fd, (struct sockaddr *) &addr, addr_len);
	if (ret < 0) {
		saved_errno = errno;
		perror("Can't connect to socket");
		close(fd);
		return -1;
	}

	return fd;
}

static int send_req_and_recv_resp(CriuReq *req, CriuResp **resp)
{
	int fd;
	int ret	= 0;

	fd = criu_connect();
	if (fd < 0) {
		perror("Can't connect to criu");
		ret = ECONNREFUSED;
		goto exit;
	}

	if (send_req(fd, req) < 0) {
		ret = ECOMM;
		goto exit;
	}

	*resp = recv_resp(fd);
	if (!*resp) {
		perror("Can't receive response");
		ret = ECOMM;
		goto exit;
	}

	if ((*resp)->type != req->type) {
		if ((*resp)->type == CRIU_REQ_TYPE__EMPTY &&
		    (*resp)->success == false)
			ret = EINVAL;
		else {
			perror("Unexpected response type");
			ret = EBADMSG;
		}
	}

exit:
	if (fd >= 0)
		close(fd);

	return -ret;
}

int criu_check(void)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__CHECK;

	ret = send_req_and_recv_resp(&req, &resp);
	if (ret)
		goto exit;

	ret = resp->success ? 0 : -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}

int criu_dump(void)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__DUMP;
	req.opts	= opts;

	ret = send_req_and_recv_resp(&req, &resp);
	if (ret)
		goto exit;

	if (resp->success) {
		if (resp->dump->has_restored && resp->dump->restored)
			ret = 1;
		else
			ret = 0;
	} else
		ret = -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}

int criu_restore(void)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__RESTORE;
	req.opts	= opts;

	ret = send_req_and_recv_resp(&req, &resp);
	if (ret)
		goto exit;

	if (resp->success)
		ret = resp->restore->pid;
	else
		ret = -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}
