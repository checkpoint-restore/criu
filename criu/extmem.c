#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/lock.h"
#include "criu-log.h"
#include "extmem.h"
#include "files.h"
#include "int.h"
#include "images/extmem.pb-c.h"
#include "rst-malloc.h"

#define EXTMEM_MAX_PACKET   (8U << 10)
#define EXTMEM_PROVIDER_KEY "extmem-provider"

enum extmem_session_state {
	EXTMEM_SESSION_NEW,
	EXTMEM_SESSION_ACTIVE,
	EXTMEM_SESSION_UNSUPPORTED,
	EXTMEM_SESSION_CLOSED,
};

static enum extmem_session_state session_state;
static __thread int provider_thread_fd = -1;
static mutex_t *provider_lock;

bool extmem_is_active(void)
{
	return session_state == EXTMEM_SESSION_ACTIVE;
}

static int provider_socket(void)
{
	if (provider_thread_fd >= 0)
		return provider_thread_fd;
	return inherit_fd_lookup_id(EXTMEM_PROVIDER_KEY);
}

int extmem_acquire_provider_fd(void)
{
	if (provider_thread_fd >= 0)
		return 0;
	provider_thread_fd = inherit_fd_lookup_id(EXTMEM_PROVIDER_KEY);
	return provider_thread_fd < 0 ? -ENOTSUP : 0;
}

void extmem_release_provider_fd(void)
{
	if (provider_thread_fd >= 0) {
		close(provider_thread_fd);
		provider_thread_fd = -1;
	}
}

static void close_received_fds(struct msghdr *msg)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		int *fds;
		size_t nr_fds;

		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len < CMSG_LEN(0))
			continue;
		fds = (int *)CMSG_DATA(cmsg);
		nr_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(*fds);
		while (nr_fds)
			close(fds[--nr_fds]);
	}
}

static int get_received_fd(struct msghdr *msg, int *fd)
{
	struct cmsghdr *cmsg;

	cmsg = CMSG_FIRSTHDR(msg);
	if (!cmsg)
		return 0;
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len != CMSG_LEN(sizeof(*fd)) ||
	    msg->msg_controllen != CMSG_SPACE(sizeof(*fd))) {
		close_received_fds(msg);
		errno = EBADMSG;
		return -1;
	}
	memcpy(fd, CMSG_DATA(cmsg), sizeof(*fd));
	return 1;
}

struct provider_response {
	uint8_t packet[EXTMEM_MAX_PACKET];
	char control[CMSG_SPACE(sizeof(int))];
	struct msghdr msg;
	struct iovec iov;
	ssize_t len;
};

static int decode_provider_response(ExtmemOp op, struct provider_response *response, int *fd)
{
	ExtmemResp *resp;
	int received_fd = -1;
	int has_fd;
	int ret = -1;

	has_fd = get_received_fd(&response->msg, &received_fd);
	if (has_fd < 0)
		goto out;
	if ((response->msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
	    response->len > (ssize_t)sizeof(response->packet)) {
		pr_err("extmem invalid response for op %d\n", op);
		errno = EBADMSG;
		goto out;
	}

	resp = extmem_resp__unpack(NULL, response->len, response->packet);
	if (!resp) {
		pr_err("extmem invalid response for op %d\n", op);
		errno = EBADMSG;
		goto out;
	}
	if (has_fd != (resp->status ? 0 : !!fd)) {
		pr_err("extmem unexpected file descriptor for op %d\n", op);
		errno = EBADMSG;
		goto free_response;
	}
	if (resp->status) {
		pr_info("extmem provider op %d status %d\n", op, resp->status);
		errno = resp->status < 0 && resp->status != INT32_MIN ? -resp->status : EIO;
		ret = resp->status == -ENOTSUP ? -ENOTSUP : -1;
		goto free_response;
	}
	if (fd) {
		*fd = received_fd;
		received_fd = -1;
	}
	ret = 0;

free_response:
	extmem_resp__free_unpacked(resp, NULL);
out:
	if (received_fd >= 0)
		close(received_fd);
	return ret;
}

static int provider_send_recv(ExtmemOp op, int socket_fd, struct msghdr *request, size_t request_len,
			      struct provider_response *response)
{
	ssize_t sent;

	mutex_lock(provider_lock);
	sent = sendmsg(socket_fd, request, MSG_NOSIGNAL);
	if (sent == (ssize_t)request_len) {
		response->msg.msg_controllen = sizeof(response->control);
		response->msg.msg_flags = 0;
		response->len = recvmsg(socket_fd, &response->msg, 0);
	}
	mutex_unlock(provider_lock);
	if (sent != (ssize_t)request_len) {
		if (sent >= 0)
			errno = EIO;
		pr_err("extmem send failed for op %d: %s\n", op, strerror(errno));
		return -1;
	}
	if (response->len == 0)
		errno = ECONNRESET;
	if (response->len <= 0) {
		pr_err("extmem receive failed for op %d: %s\n", op, strerror(errno));
		return -1;
	}
	return 0;
}

static int provider_request(ExtmemReq *req, int *fd)
{
	uint8_t packet[EXTMEM_MAX_PACKET];
	struct provider_response response;
	struct msghdr request = {};
	struct iovec request_iov = { .iov_base = packet };
	int socket_fd;
	size_t packed;
	int ret = -1;

	packed = extmem_req__get_packed_size(req);
	if (packed > sizeof(packet)) {
		errno = EMSGSIZE;
		return -1;
	}
	if (extmem_req__pack(req, packet) != packed) {
		errno = EIO;
		return -1;
	}
	request_iov.iov_len = packed;
	request.msg_iov = &request_iov;
	request.msg_iovlen = 1;
	memset(&response, 0, sizeof(response));
	response.iov.iov_base = response.packet;
	response.iov.iov_len = sizeof(response.packet);
	response.msg.msg_iov = &response.iov;
	response.msg.msg_iovlen = 1;
	response.msg.msg_control = response.control;
	response.msg.msg_controllen = sizeof(response.control);
	socket_fd = provider_socket();
	if (socket_fd < 0)
		return -1;

	if (provider_send_recv(req->op, socket_fd, &request, packed, &response))
		goto out;
	ret = decode_provider_response(req->op, &response, fd);
out:
	if (provider_thread_fd < 0)
		close(socket_fd);
	return ret;
}

int extmem_init(void)
{
	ExtmemReq req = EXTMEM_REQ__INIT;
	bool release_fd = false;
	int ret = -1;
	if (session_state == EXTMEM_SESSION_ACTIVE)
		return 0;
	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state == EXTMEM_SESSION_UNSUPPORTED)
		return -ENOTSUP;
	if (provider_thread_fd < 0) {
		ret = extmem_acquire_provider_fd();
		if (ret)
			goto out;
		release_fd = true;
	}
	if (!provider_lock) {
		provider_lock = shmalloc(sizeof(*provider_lock));
		if (!provider_lock) {
			ret = -ENOMEM;
			goto out;
		}
		mutex_init(provider_lock);
	}
	pr_info("External memory provider init\n");
	ret = provider_request(&req, NULL);
out:
	if (release_fd)
		extmem_release_provider_fd();
	if (ret == -ENOTSUP)
		session_state = EXTMEM_SESSION_UNSUPPORTED;
	if (ret)
		return ret;
	session_state = EXTMEM_SESSION_ACTIVE;
	return 0;
}

int extmem_open_image(const char *name, int flags, int *fd)
{
	ExtmemOpenImage image = EXTMEM_OPEN_IMAGE__INIT;
	ExtmemReq req = EXTMEM_REQ__INIT;
	int ret;

	ret = extmem_init();
	if (ret)
		return ret;
	image.name = (char *)name;
	image.flags = flags;
	req.op = EXTMEM_OP__EXTMEM_OPEN_IMAGE;
	req.open_image = &image;
	return provider_request(&req, fd);
}

int extmem_get_vma(pid_t pid, unsigned int vma_id, unsigned long vaddr, unsigned long length, int *fd)
{
	ExtmemGetVma vma = EXTMEM_GET_VMA__INIT;
	ExtmemReq req = EXTMEM_REQ__INIT;
	int ret;

	ret = extmem_init();
	if (ret)
		return ret;
	vma.pid = pid;
	vma.vma_id = vma_id;
	vma.vaddr = vaddr;
	vma.length = length;
	req.op = EXTMEM_OP__EXTMEM_GET_VMA;
	req.get_vma = &vma;
	return provider_request(&req, fd);
}

int extmem_get_shared(unsigned long shmid, unsigned long length, int *fd)
{
	ExtmemGetShared shared = EXTMEM_GET_SHARED__INIT;
	ExtmemReq req = EXTMEM_REQ__INIT;
	int ret;

	ret = extmem_init();
	if (ret)
		return ret;
	shared.shmid = shmid;
	shared.length = length;
	req.op = EXTMEM_OP__EXTMEM_GET_SHARED;
	req.get_shared = &shared;
	return provider_request(&req, fd);
}

int extmem_wait_ready(void)
{
	ExtmemReq req = EXTMEM_REQ__INIT;
	int ret;

	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state != EXTMEM_SESSION_ACTIVE)
		return -ENOTSUP;
	req.op = EXTMEM_OP__EXTMEM_WAIT_READY;
	ret = provider_request(&req, NULL);
	/*
	 * A provider that completed INIT must support WAIT_READY. Treat an
	 * unsupported WAIT_READY as a protocol error.
	 */
	if (ret == -ENOTSUP)
		return -EPROTO;
	return ret;
}

static int end_session(ExtmemOp op)
{
	ExtmemReq req = EXTMEM_REQ__INIT;
	int ret;
	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state != EXTMEM_SESSION_ACTIVE)
		return 0;
	req.op = op;
	ret = provider_request(&req, NULL);
	session_state = EXTMEM_SESSION_CLOSED;
	return ret;
}

int extmem_commit(void)
{
	return end_session(EXTMEM_OP__EXTMEM_COMMIT);
}
int extmem_abort(void)
{
	return end_session(EXTMEM_OP__EXTMEM_ABORT);
}
