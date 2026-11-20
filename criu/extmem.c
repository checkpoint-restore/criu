#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/lock.h"
#include "cr_options.h"
#include "criu-log.h"
#include "extmem.h"
#include "files.h"
#include "int.h"
#include "images/extmem.pb-c.h"
#include "rst-malloc.h"
#include "servicefd.h"

/* Fits a PATH_MAX-length image name (4 KiB on Linux) plus protobuf overhead. */
#define EXTMEM_MAX_PACKET	(8U << 10)
#define EXTMEM_PROVIDER_KEY	"extmem-provider"
#define EXTMEM_PROTOCOL_VERSION 1

enum extmem_session_state {
	EXTMEM_SESSION_NEW,
	EXTMEM_SESSION_ACTIVE,
	EXTMEM_SESSION_UNSUPPORTED,
	EXTMEM_SESSION_CLOSED,
};

static enum extmem_session_state session_state;

/*
 * Shared between CRIU and the restored tasks, which all use the same socket.
 *
 * @lock serializes request/reply pairs. @in_flight is set while a task owns
 * the socket for a request; it stays set if a reply may still be pending, so
 * the socket can't be used any more. @closing is set by the main process
 * before COMMIT or ABORT; no new request starts after that.
 */
struct extmem_session {
	mutex_t lock;
	atomic_t in_flight;
	atomic_t closing;
};
static struct extmem_session *session;

bool extmem_is_active(void)
{
	return session_state == EXTMEM_SESSION_ACTIVE;
}

static void close_received_fds(struct msghdr *msg)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		size_t nr_fds;
		int *fds;

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
	int received_fd = -1;
	ExtmemResp *resp;
	bool expect_fd;
	int ret = -1;
	int has_fd;

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

	/* Only a successful reply to a request that asks for an FD carries one. */
	expect_fd = fd != NULL && resp->status == 0;
	if (has_fd != expect_fd) {
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
	/* See end_session(): terminal requests are sent without the lock. */
	bool terminal = op == EXTMEM_OP__EXTMEM_COMMIT || op == EXTMEM_OP__EXTMEM_ABORT;
	ssize_t sent;

	response->len = -1;
	if (!terminal) {
		mutex_lock(&session->lock);
		/* Pairs with the closing/in_flight check in end_session(). */
		atomic_inc_return(&session->in_flight);
		if (atomic_read(&session->closing)) {
			atomic_dec(&session->in_flight);
			mutex_unlock(&session->lock);
			pr_err("extmem session is closing, op %d not sent\n", op);
			errno = EPIPE;
			return -1;
		}
	}

	sent = sendmsg(socket_fd, request, MSG_NOSIGNAL);
	if (sent == (ssize_t)request_len) {
		response->msg.msg_controllen = sizeof(response->control);
		response->msg.msg_flags = 0;
		/* Don't leak received FDs into action scripts. */
		response->len = recvmsg(socket_fd, &response->msg, MSG_CMSG_CLOEXEC);
	}

	if (!terminal) {
		/*
		 * If the request went out but no reply came back, a late reply
		 * would be read by the next request. Leave in_flight set, so
		 * that the session is not used any more.
		 */
		if (sent != (ssize_t)request_len || response->len >= 0)
			atomic_dec(&session->in_flight);
		mutex_unlock(&session->lock);
	}

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
	struct provider_response response;
	uint8_t packet[EXTMEM_MAX_PACKET];
	struct iovec request_iov = { .iov_base = packet };
	struct msghdr request = {};
	int socket_fd;
	size_t packed;

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

	socket_fd = get_service_fd(EXTMEM_PROVIDER_FD_OFF);
	if (socket_fd < 0)
		return -1;

	if (provider_send_recv(req->op, socket_fd, &request, packed, &response))
		return -1;
	return decode_provider_response(req->op, &response, fd);
}

/* Resolve the images directory as CRIU sees it. Best effort. */
static char *get_images_dir(char *buf, size_t size)
{
	char path[64];
	ssize_t len;
	int fd;

	fd = get_service_fd(IMG_FD_OFF);
	if (fd < 0)
		return NULL;

	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	len = readlink(path, buf, size - 1);
	if (len < 0)
		return NULL;
	buf[len] = '\0';
	return buf;
}

/*
 * The provider replaces image and memory transport. Do not combine it with
 * other transports: they would bypass the provider or fill provider-backed
 * mappings behind its back.
 */
static int check_conflicting_opts(void)
{
	const char *opt = NULL;

	if (opts.stream)
		opt = "--stream";
	else if (opts.lazy_pages)
		opt = "--lazy-pages";
	else if (opts.use_page_server)
		opt = "--page-server";
	else if (opts.auto_dedup && opts.mode == CR_RESTORE)
		opt = "--auto-dedup";

	if (opt) {
		pr_err("External memory provider can't be used with %s\n", opt);
		return -1;
	}
	return 0;
}

int extmem_init(void)
{
	ExtmemInit init = EXTMEM_INIT__INIT;
	ExtmemReq req = EXTMEM_REQ__INIT;
	char images_dir[PATH_MAX];
	int socket_fd = -1;
	int ret = -1;

	if (session_state == EXTMEM_SESSION_ACTIVE)
		return 0;
	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state == EXTMEM_SESSION_UNSUPPORTED)
		return -ENOTSUP;

	socket_fd = inherit_fd_take(EXTMEM_PROVIDER_KEY);
	if (socket_fd < 0) {
		ret = -ENOTSUP;
		goto out;
	}
	if (check_conflicting_opts()) {
		close(socket_fd);
		ret = -EINVAL;
		goto out;
	}
	if (install_service_fd(EXTMEM_PROVIDER_FD_OFF, socket_fd) < 0)
		goto out;

	if (!session) {
		session = shmalloc(sizeof(*session));
		if (!session) {
			ret = -ENOMEM;
			goto out;
		}
		mutex_init(&session->lock);
		atomic_set(&session->in_flight, 0);
		atomic_set(&session->closing, 0);
	}

	pr_info("External memory provider init\n");
	init.version = EXTMEM_PROTOCOL_VERSION;
	init.mode = opts.mode == CR_DUMP ? EXTMEM_MODE__EXTMEM_MODE_DUMP : EXTMEM_MODE__EXTMEM_MODE_RESTORE;
	init.images_dir = get_images_dir(images_dir, sizeof(images_dir));
	req.op = EXTMEM_OP__EXTMEM_INIT;
	req.init = &init;
	ret = provider_request(&req, NULL);
out:
	if (ret)
		close_service_fd(EXTMEM_PROVIDER_FD_OFF);
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

	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state != EXTMEM_SESSION_ACTIVE)
		return -ENOTSUP;

	image.name = (char *)name;
	image.flags = flags;
	req.op = EXTMEM_OP__EXTMEM_OPEN_IMAGE;
	req.open_image = &image;
	return provider_request(&req, fd);
}

int extmem_get_vma(pid_t pid, unsigned int vma_id, unsigned long vaddr, unsigned long length,
		   unsigned long offset, int *fd)
{
	ExtmemGetVma vma = EXTMEM_GET_VMA__INIT;
	ExtmemReq req = EXTMEM_REQ__INIT;

	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state != EXTMEM_SESSION_ACTIVE)
		return -ENOTSUP;

	vma.pid = pid;
	vma.vma_id = vma_id;
	vma.vaddr = vaddr;
	vma.length = length;
	vma.offset = offset;
	req.op = EXTMEM_OP__EXTMEM_GET_VMA;
	req.get_vma = &vma;
	return provider_request(&req, fd);
}

int extmem_get_shared(unsigned long shmid, unsigned long length, int *fd)
{
	ExtmemGetShared shared = EXTMEM_GET_SHARED__INIT;
	ExtmemReq req = EXTMEM_REQ__INIT;

	if (session_state == EXTMEM_SESSION_CLOSED)
		return -EPIPE;
	if (session_state != EXTMEM_SESSION_ACTIVE)
		return -ENOTSUP;

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

	/*
	 * Only the main process ends the session, after the restored tasks
	 * have finished or have been killed. Don't take the lock: a task
	 * killed in the middle of a request holds it forever. Stop new
	 * requests first, then check that none is in flight; otherwise a
	 * late reply could be read as the reply to COMMIT or ABORT. In that
	 * case just close the socket: the provider treats EOF without
	 * COMMIT as ABORT.
	 */
	atomic_inc_return(&session->closing);
	if (atomic_read(&session->in_flight)) {
		pr_warn("A provider request may be in flight, closing the session without %s\n",
			op == EXTMEM_OP__EXTMEM_COMMIT ? "COMMIT" : "ABORT");
		ret = op == EXTMEM_OP__EXTMEM_COMMIT ? -1 : 0;
		errno = EPIPE;
	} else {
		req.op = op;
		ret = provider_request(&req, NULL);
	}
	session_state = EXTMEM_SESSION_CLOSED;
	close_service_fd(EXTMEM_PROVIDER_FD_OFF);
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
