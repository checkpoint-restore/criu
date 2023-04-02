#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>

#include "cr_options.h"
#include "img-streamer.h"
#include "image.h"
#include "images/img-streamer.pb-c.h"
#include "protobuf.h"
#include "servicefd.h"
#include "rst-malloc.h"
#include "common/scm.h"
#include "common/lock.h"
#include "action-scripts.h"

/*
 * We use different path names for the dump and restore sockets because:
 * 1) The user may want to perform both at the same time (akin to live
 *     migration). Specifying the same images-dir is convenient.
 * 2) It fails quickly when the user mix-up the streamer and CRIU operations.
 *    (e.g., streamer is in capture more, while CRIU is in restore mode).
 */
#define IMG_STREAMER_CAPTURE_SOCKET_NAME "streamer-capture.sock"
#define IMG_STREAMER_SERVE_SOCKET_NAME	 "streamer-serve.sock"

/* All requests go through the same socket connection. We must synchronize */
static mutex_t *img_streamer_fd_lock;

/* Either O_DUMP or O_RSTR */
static int img_streamer_mode;

static const char *socket_name_for_mode(int mode)
{
	switch (mode) {
	case O_DUMP:
		return IMG_STREAMER_CAPTURE_SOCKET_NAME;
	case O_RSTR:
		return IMG_STREAMER_SERVE_SOCKET_NAME;
	default:
		BUG();
		return NULL;
	}
}

/*
 * img_streamer_init() connects to the image streamer socket.
 * mode should be either O_DUMP or O_RSTR.
 */
int img_streamer_init(const char *image_dir, int mode)
{
	struct sockaddr_un addr;
	int pre_stream_ret;
	int sockfd;

	img_streamer_mode = mode;

	pre_stream_ret = run_scripts(ACT_PRE_STREAM);
	if (pre_stream_ret != 0) {
		pr_err("Pre-stream script failed with %d!\n", pre_stream_ret);
		return -1;
	}

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		pr_perror("Unable to instantiate UNIX socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s", image_dir, socket_name_for_mode(mode));

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pr_perror("Unable to connect to image streamer socket: %s", addr.sun_path);
		goto err;
	}

	img_streamer_fd_lock = shmalloc(sizeof(*img_streamer_fd_lock));
	if (!img_streamer_fd_lock) {
		pr_err("Failed to allocate memory\n");
		goto err;
	}
	mutex_init(img_streamer_fd_lock);

	if (install_service_fd(IMG_STREAMER_FD_OFF, sockfd) < 0)
		return -1;

	return 0;

err:
	close(sockfd);
	return -1;
}

/*
 * img_streamer_finish() indicates that no more files will be opened.
 * In other words, img_streamer_open() will no longer be called.
 */
void img_streamer_finish(void)
{
	if (get_service_fd(IMG_STREAMER_FD_OFF) >= 0) {
		pr_info("Dismissing the image streamer\n");
		close_service_fd(IMG_STREAMER_FD_OFF);
	}
}

/*
 * The regular protobuf APIs pb_write_one() and pb_read_one() operate over a
 * `struct cr_img` object. Sadly, we don't have such object. We just have a
 * file descriptor. The following pb_write_one_fd() and pb_read_one_fd()
 * provide a protobuf API over a file descriptor. The implementation is a bit
 * of a hack, but should be fine. At some point we can revisit to have a
 * proper protobuf API over fds.
 */
static int pb_write_one_fd(int fd, void *obj, int type)
{
	int ret;
	struct cr_img img;
	memset(&img, 0, sizeof(img));

	img._x.fd = fd;
	ret = pb_write_one(&img, obj, type);
	if (ret < 0)
		pr_perror("Failed to communicate with the image streamer");
	return ret;
}

static int pb_read_one_fd(int fd, void **pobj, int type)
{
	int ret;
	struct cr_img img;
	memset(&img, 0, sizeof(img));

	img._x.fd = fd;
	ret = pb_read_one(&img, pobj, type);
	if (ret < 0)
		pr_perror("Failed to communicate with the image streamer");
	return ret;
}

static int send_file_request(char *filename)
{
	ImgStreamerRequestEntry req = IMG_STREAMER_REQUEST_ENTRY__INIT;
	req.filename = filename;
	return pb_write_one_fd(get_service_fd(IMG_STREAMER_FD_OFF), &req, PB_IMG_STREAMER_REQUEST);
}

static int recv_file_reply(bool *exists)
{
	ImgStreamerReplyEntry *reply;
	int ret = pb_read_one_fd(get_service_fd(IMG_STREAMER_FD_OFF), (void **)&reply, PB_IMG_STREAMER_REPLY);
	if (ret < 0)
		return ret;

	*exists = reply->exists;
	free(reply);

	return 0;
}

/*
 * Using a pipe for image file transfers allows the data to be spliced by the
 * image streamer, greatly improving performance.
 * Transfer rates of up to 15GB/s can be seen with this technique.
 */
#define READ_PIPE  0 /* index of the read pipe returned by pipe() */
#define WRITE_PIPE 1
static int establish_streamer_file_pipe(void)
{
	/*
	 * If the other end of the pipe closes, the kernel will want to kill
	 * us with a SIGPIPE. These signal must be ignored, which we do in
	 * crtools.c:main() with signal(SIGPIPE, SIG_IGN).
	 */
	int ret = -1;
	int criu_pipe_direction = img_streamer_mode == O_DUMP ? WRITE_PIPE : READ_PIPE;
	int streamer_pipe_direction = 1 - criu_pipe_direction;
	int fds[2];

	if (pipe(fds) < 0) {
		pr_perror("Unable to create pipe");
		return -1;
	}

	if (send_fd(get_service_fd(IMG_STREAMER_FD_OFF), NULL, 0, fds[streamer_pipe_direction]) < 0)
		close(fds[criu_pipe_direction]);
	else
		ret = fds[criu_pipe_direction];

	close(fds[streamer_pipe_direction]);

	return ret;
}

static int _img_streamer_open(char *filename)
{
	if (send_file_request(filename) < 0)
		return -1;

	if (img_streamer_mode == O_RSTR) {
		/* The streamer replies whether the file exists */
		bool exists;
		if (recv_file_reply(&exists) < 0)
			return -1;

		if (!exists)
			return -ENOENT;
	}

	/*
	 * When the image streamer encounters a fatal error, it won't report
	 * errors via protobufs. Instead, CRIU will get a broken pipe error
	 * when trying to access a streaming pipe. This behavior is similar to
	 * what would happen if we were connecting criu and * criu-image-streamer
	 * via a shell pipe.
	 */

	return establish_streamer_file_pipe();
}

/*
 * Opens an image file via a UNIX pipe with the image streamer.
 *
 * Return:
 * 	A file descriptor on success
 * 	-ENOENT when the file was not found.
 * 	-1 on any other error.
 */
int img_streamer_open(char *filename, int flags)
{
	int ret;

	BUG_ON(flags != img_streamer_mode);

	mutex_lock(img_streamer_fd_lock);
	ret = _img_streamer_open(filename);
	mutex_unlock(img_streamer_fd_lock);
	return ret;
}
