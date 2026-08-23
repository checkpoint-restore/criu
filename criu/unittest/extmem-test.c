#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "extmem.h"
#include "images/extmem.pb-c.h"
#include "memfd.h"

static int provider_fd = -1;
static int provider_lookup_count;

enum provider_mode {
	PROVIDER_NORMAL,
	PROVIDER_UNSUPPORTED_VMA,
	PROVIDER_FAILED_VMA,
	PROVIDER_UNSUPPORTED_INIT,
	PROVIDER_MULTIPLE_FDS,
	PROVIDER_MISSING_FD,
	PROVIDER_ERROR_FD,
	PROVIDER_INT_MIN_STATUS,
	PROVIDER_UNSUPPORTED_WAIT,
};

int inherit_fd_lookup_id(char *id)
{
	assert(strcmp(id, "extmem-provider") == 0);
	provider_lookup_count++;
	return dup(provider_fd);
}

static void send_response_fds(int socket, int status, const int *fds, unsigned int nr_fds)
{
	ExtmemResp response = EXTMEM_RESP__INIT;
	uint8_t buffer[128];
	struct iovec iov = { .iov_base = buffer };
	struct msghdr message = {};
	char control[CMSG_SPACE(sizeof(int) * 2)] = {};
	size_t length;

	assert(nr_fds <= 2);
	response.status = status;
	length = extmem_resp__pack(&response, buffer);
	iov.iov_len = length;
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	if (nr_fds) {
		struct cmsghdr *cmsg;

		message.msg_control = control;
		message.msg_controllen = sizeof(control);
		cmsg = CMSG_FIRSTHDR(&message);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(*fds) * nr_fds);
		memcpy(CMSG_DATA(cmsg), fds, sizeof(*fds) * nr_fds);
	}
	assert(sendmsg(socket, &message, 0) == (ssize_t)length);
}

static void send_response(int socket, int status, int fd)
{
	send_response_fds(socket, status, fd >= 0 ? &fd : NULL, fd >= 0);
}

static ExtmemReq *receive_request(int socket)
{
	uint8_t buffer[PATH_MAX + 32];
	ssize_t length;

	length = recv(socket, buffer, sizeof(buffer), 0);
	assert(length > 0);
	return extmem_req__unpack(NULL, length, buffer);
}

static void assert_init(int socket, int status)
{
	ExtmemReq *request = receive_request(socket);

	assert(request);
	assert(request->op == EXTMEM_OP__EXTMEM_INIT);
	send_response(socket, status, -1);
	extmem_req__free_unpacked(request, NULL);
}

static void run_normal_provider(int socket)
{
	ExtmemReq *request;
	int fd;

	assert_init(socket, 0);

	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_OPEN_IMAGE);
	assert(request->open_image);
	assert(strlen(request->open_image->name) == PATH_MAX - 1);
	assert(request->open_image->flags == O_RDONLY);
	fd = memfd_create("extmem-image", 0);
	assert(fd >= 0);
	send_response(socket, 0, fd);
	close(fd);
	extmem_req__free_unpacked(request, NULL);

	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_GET_VMA);
	assert(request->get_vma);
	assert(request->get_vma->pid == 123);
	assert(request->get_vma->vma_id == 0);
	assert(request->get_vma->vaddr == 0x1000);
	assert(request->get_vma->length == 0x2000);
	fd = memfd_create("extmem-vma", MFD_ALLOW_SEALING);
	assert(fd >= 0);
	assert(ftruncate(fd, 0x2000) == 0);
	send_response(socket, 0, fd);
	close(fd);
	extmem_req__free_unpacked(request, NULL);

	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_GET_SHARED);
	assert(request->get_shared);
	assert(request->get_shared->shmid == 55);
	assert(request->get_shared->length == 0x3000);
	fd = memfd_create("extmem-shared", MFD_ALLOW_SEALING);
	assert(fd >= 0);
	assert(ftruncate(fd, 0x3000) == 0);
	send_response(socket, 0, fd);
	extmem_req__free_unpacked(request, NULL);

	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_GET_SHARED);
	assert(request->get_shared);
	assert(request->get_shared->shmid == 55);
	assert(request->get_shared->length == 0x3000);
	send_response(socket, 0, fd);
	close(fd);
	extmem_req__free_unpacked(request, NULL);

	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_WAIT_READY);
	send_response(socket, 0, -1);
	extmem_req__free_unpacked(request, NULL);

	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_COMMIT);
	send_response(socket, 0, -1);
	extmem_req__free_unpacked(request, NULL);
}

static void run_vma_provider(int socket, int status)
{
	ExtmemReq *request;

	assert_init(socket, 0);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_GET_VMA);
	send_response(socket, status, -1);
	extmem_req__free_unpacked(request, NULL);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_ABORT);
	send_response(socket, 0, -1);
	extmem_req__free_unpacked(request, NULL);
}

static void run_unsupported_wait_provider(int socket)
{
	ExtmemReq *request;
	int fd;

	assert_init(socket, 0);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_OPEN_IMAGE);
	fd = memfd_create("extmem-image", 0);
	assert(fd >= 0);
	send_response(socket, 0, fd);
	close(fd);
	extmem_req__free_unpacked(request, NULL);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_WAIT_READY);
	send_response(socket, -ENOTSUP, -1);
	extmem_req__free_unpacked(request, NULL);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_ABORT);
	send_response(socket, 0, -1);
	extmem_req__free_unpacked(request, NULL);
}

static void run_multiple_fds_provider(int socket)
{
	ExtmemReq *request;
	int fds[2];

	assert_init(socket, 0);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_GET_VMA);
	fds[0] = memfd_create("extmem-first", 0);
	fds[1] = memfd_create("extmem-second", 0);
	assert(fds[0] >= 0 && fds[1] >= 0);
	send_response_fds(socket, 0, fds, 2);
	close(fds[0]);
	close(fds[1]);
	extmem_req__free_unpacked(request, NULL);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_ABORT);
	send_response(socket, 0, -1);
	extmem_req__free_unpacked(request, NULL);
}

static void run_error_fd_provider(int socket)
{
	ExtmemReq *request;
	int fd;

	assert_init(socket, 0);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_GET_VMA);
	fd = memfd_create("extmem-error", 0);
	assert(fd >= 0);
	send_response(socket, -EIO, fd);
	close(fd);
	extmem_req__free_unpacked(request, NULL);
	request = receive_request(socket);
	assert(request && request->op == EXTMEM_OP__EXTMEM_ABORT);
	send_response(socket, 0, -1);
	extmem_req__free_unpacked(request, NULL);
}

static void run_provider(int socket, enum provider_mode mode)
{
	switch (mode) {
	case PROVIDER_NORMAL:
		run_normal_provider(socket);
		break;
	case PROVIDER_UNSUPPORTED_VMA:
		run_vma_provider(socket, -ENOTSUP);
		break;
	case PROVIDER_FAILED_VMA:
		run_vma_provider(socket, -EIO);
		break;
	case PROVIDER_UNSUPPORTED_INIT:
		assert_init(socket, -ENOTSUP);
		break;
	case PROVIDER_MULTIPLE_FDS:
		run_multiple_fds_provider(socket);
		break;
	case PROVIDER_MISSING_FD:
		run_vma_provider(socket, 0);
		break;
	case PROVIDER_ERROR_FD:
		run_error_fd_provider(socket);
		break;
	case PROVIDER_INT_MIN_STATUS:
		run_vma_provider(socket, INT32_MIN);
		break;
	case PROVIDER_UNSUPPORTED_WAIT:
		run_unsupported_wait_provider(socket);
		break;
	}
	close(socket);
}

static pid_t start_provider(enum provider_mode mode)
{
	int sockets[2];
	pid_t pid;

	assert(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) == 0);
	pid = fork();
	assert(pid >= 0);
	if (pid == 0) {
		close(sockets[0]);
		run_provider(sockets[1], mode);
		_exit(0);
	}
	close(sockets[1]);
	provider_fd = sockets[0];
	provider_lookup_count = 0;
	return pid;
}

static void finish_provider(pid_t pid)
{
	int status;

	close(provider_fd);
	provider_fd = -1;
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_normal_provider(void)
{
	char image_name[PATH_MAX];
	int image_fd, shared_fd;
	struct stat first_shared, second_shared;
	pid_t pid = start_provider(PROVIDER_NORMAL);

	memset(image_name, 'x', sizeof(image_name) - 1);
	image_name[sizeof(image_name) - 1] = '\0';
	assert(extmem_init() == 0);
	assert(extmem_init() == 0);
	assert(extmem_acquire_provider_fd() == 0);
	assert(extmem_acquire_provider_fd() == 0);
	assert(extmem_open_image(image_name, O_RDONLY, &image_fd) == 0);
	assert(image_fd >= 0);
	close(image_fd);
	assert(extmem_get_vma(123, 0, 0x1000, 0x2000, &image_fd) == 0);
	close(image_fd);
	assert(extmem_get_shared(55, 0x3000, &shared_fd) == 0);
	assert(fstat(shared_fd, &first_shared) == 0);
	close(shared_fd);
	assert(extmem_get_shared(55, 0x3000, &shared_fd) == 0);
	assert(fstat(shared_fd, &second_shared) == 0);
	assert(first_shared.st_dev == second_shared.st_dev);
	assert(first_shared.st_ino == second_shared.st_ino);
	close(shared_fd);
	extmem_release_provider_fd();
	assert(extmem_wait_ready() == 0);
	assert(extmem_commit() == 0);
	assert(extmem_get_vma(123, 0, 0x1000, 0x2000, &image_fd) == -EPIPE);
	finish_provider(pid);
}

static void test_vma_response(enum provider_mode mode, int expected, int expected_errno)
{
	int fd;
	pid_t pid = start_provider(mode);

	assert(extmem_get_vma(1, 0, 0x1000, 0x1000, &fd) == expected);
	assert(errno == expected_errno);
	assert(extmem_abort() == 0);
	finish_provider(pid);
}

static void test_unsupported_init(void)
{
	int fd;
	pid_t pid = start_provider(PROVIDER_UNSUPPORTED_INIT);

	assert(extmem_open_image("pages-1", O_RDONLY, &fd) == -ENOTSUP);
	assert(errno == ENOTSUP);
	assert(provider_lookup_count == 1);
	finish_provider(pid);
}

static void test_missing_provider(void)
{
	provider_fd = -1;
	provider_lookup_count = 0;

	assert(extmem_init() == -ENOTSUP);
	assert(extmem_init() == -ENOTSUP);
	assert(provider_lookup_count == 1);
}

static void test_unsupported_wait(void)
{
	int fd;
	pid_t pid = start_provider(PROVIDER_UNSUPPORTED_WAIT);

	assert(extmem_open_image("pages-1", O_RDONLY, &fd) == 0);
	close(fd);
	assert(extmem_wait_ready() == -EPROTO);
	assert(extmem_abort() == 0);
	finish_provider(pid);
}

static void test_unsupported_object(void)
{
	test_vma_response(PROVIDER_UNSUPPORTED_VMA, -ENOTSUP, ENOTSUP);
}

static void test_failed_object(void)
{
	test_vma_response(PROVIDER_FAILED_VMA, -1, EIO);
}

static void test_multiple_fds(void)
{
	test_vma_response(PROVIDER_MULTIPLE_FDS, -1, EBADMSG);
}

static void test_missing_fd(void)
{
	test_vma_response(PROVIDER_MISSING_FD, -1, EBADMSG);
}

static void test_error_fd(void)
{
	test_vma_response(PROVIDER_ERROR_FD, -1, EBADMSG);
}

static void test_int_min_status(void)
{
	test_vma_response(PROVIDER_INT_MIN_STATUS, -1, EIO);
}

static void run_test(void (*test)(void))
{
	int status;
	pid_t pid = fork();

	assert(pid >= 0);
	if (pid == 0) {
		test();
		_exit(0);
	}
	assert(waitpid(pid, &status, 0) == pid);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void test_extmem(void)
{
	run_test(test_missing_provider);
	run_test(test_normal_provider);
	run_test(test_unsupported_object);
	run_test(test_failed_object);
	run_test(test_unsupported_init);
	run_test(test_unsupported_wait);
	run_test(test_multiple_fds);
	run_test(test_missing_fd);
	run_test(test_error_fd);
	run_test(test_int_min_status);
}
