#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/un.h>
#include <unistd.h>

#include "cr_options.h"
#include "img-remote.h"
#include "image.h"
#include "images/remote-image.pb-c.h"
#include "protobuf.h"
#include "servicefd.h"
#include "xmalloc.h"

#define EPOLL_MAX_EVENTS 50

#define strflags(f) ((f) == O_RDONLY ? "read" : \
		     (f) == O_APPEND ? "append" : "write")

// List of images already in memory.
static LIST_HEAD(rimg_head);

// List of local operations currently in-progress.
static LIST_HEAD(rop_inprogress);

// List of local operations pending (reads on the restore side for images that
// still haven't arrived).
static LIST_HEAD(rop_pending);

// List of images waiting to be forwarded. The head of the list is currently
// being forwarded.
static LIST_HEAD(rop_forwarding);

// List of snapshots (useful when doing incremental restores/dumps)
static LIST_HEAD(snapshot_head);

// Snapshot id (setup at launch time by dump or restore).
static char *snapshot_id;

// True if restoring (cache := true; proxy := false).
bool restoring = true;

// True if the proxy to cache socket is being used (receiving or sending).
static bool forwarding = false;

// True if the local dump or restore is finished.
static bool finished_local = false;

// True if the communication between the proxy and cache can be closed.
static bool finished_remote = false;

// Proxy to cache socket fd; Local dump or restore servicing fd.
int remote_sk;
int local_sk;

// Epoll fd and event array.
static int epoll_fd;
static struct epoll_event *events;

static int64_t recv_image_async(struct roperation *op);
static int64_t send_image_async(struct roperation *op);

/* A snapshot is a dump or pre-dump operation. Each snapshot is identified by an
 * ID which corresponds to the working directory specified by the user.
 */
struct snapshot {
	char snapshot_id[PATH_MAX];
	struct list_head l;
};

static struct snapshot *new_snapshot(char *snapshot_id)
{
	struct snapshot *s = xmalloc(sizeof(struct snapshot));

	if (!s)
		return NULL;

	strncpy(s->snapshot_id, snapshot_id, PATH_MAX - 1);
	s->snapshot_id[PATH_MAX - 1]= '\0';
	return s;
}

static inline void add_snapshot(struct snapshot *snapshot)
{
	list_add_tail(&(snapshot->l), &snapshot_head);
}

struct rimage *get_rimg_by_name(const char *snapshot_id, const char *path)
{
	struct rimage *rimg = NULL;

	list_for_each_entry(rimg, &rimg_head, l) {
		if (!strncmp(rimg->path, path, PATH_MAX) &&
			!strncmp(rimg->snapshot_id, snapshot_id, PATH_MAX)) {
			return rimg;
		}
	}
	return NULL;
}

static inline struct roperation *get_rop_by_name(struct list_head *head,
	const char *snapshot_id, const char *path)
{
	struct roperation *rop = NULL;

	list_for_each_entry(rop, head, l) {
		if (!strncmp(rop->path, path, PATH_MAX) &&
			!strncmp(rop->snapshot_id, snapshot_id, PATH_MAX)) {
			return rop;
		}
	}
	return NULL;
}

static int event_set(int epoll_fd, int op, int fd, uint32_t events, void *data)
{
	int ret;
	struct epoll_event event;
	event.events = events;
	event.data.ptr = data;

	ret = epoll_ctl(epoll_fd, op, fd, &event);
	if (ret)
		pr_perror("[fd=%d] Unable to set event", fd);
	return ret;
}

int setup_UNIX_server_socket(char *path)
{
	struct sockaddr_un addr;
	int sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);

	if (sockfd < 0) {
		pr_perror("Unable to open image socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

	unlink(path);

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		pr_perror("Unable to bind image socket");
		goto err;
	}

	if (listen(sockfd, 50) == -1) {
		pr_perror("Unable to listen image socket");
		goto err;
	}

	return sockfd;
err:
	close(sockfd);
	return -1;
}

static int setup_UNIX_client_socket(char *path)
{
	struct sockaddr_un addr;
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sockfd < 0) {
		pr_perror("Unable to open local image socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		pr_perror("Unable to connect to local socket: %s", path);
		close(sockfd);
		return -1;
	}

	return sockfd;
}

static inline int64_t pb_write_obj(int fd, void *obj, int type)
{
	struct cr_img img;

	img._x.fd = fd;
	bfd_setraw(&img._x);
	return pb_write_one(&img, obj, type);
}

static inline int64_t pb_read_obj(int fd, void **pobj, int type)
{
	struct cr_img img;

	img._x.fd = fd;
	bfd_setraw(&img._x);
	return do_pb_read_one(&img, pobj, type, true);
}

static inline int64_t write_header(int fd, char *snapshot_id, char *path,
	int flags)
{
	LocalImageEntry li = LOCAL_IMAGE_ENTRY__INIT;

	li.name = path;
	li.snapshot_id = snapshot_id;
	li.open_mode = flags;
	return pb_write_obj(fd, &li, PB_LOCAL_IMAGE);
}

static inline int64_t write_reply_header(int fd, int error)
{
	LocalImageReplyEntry lir = LOCAL_IMAGE_REPLY_ENTRY__INIT;

	lir.error = error;
	return pb_write_obj(fd, &lir, PB_LOCAL_IMAGE_REPLY);
}

static inline int64_t write_remote_header(int fd, char *snapshot_id,
	char *path, int flags, uint64_t size)
{
	RemoteImageEntry ri = REMOTE_IMAGE_ENTRY__INIT;

	ri.name = path;
	ri.snapshot_id = snapshot_id;
	ri.open_mode = flags;
	ri.size = size;
	return pb_write_obj(fd, &ri, PB_REMOTE_IMAGE);
}

static inline int64_t read_header(int fd, char *snapshot_id, char *path,
	int *flags)
{
	LocalImageEntry *li;
	int ret = pb_read_obj(fd, (void **)&li, PB_LOCAL_IMAGE);

	if (ret > 0) {
		strncpy(snapshot_id, li->snapshot_id, PATH_MAX - 1);
		snapshot_id[PATH_MAX - 1] = 0;
		strncpy(path, li->name, PATH_MAX - 1);
		path[PATH_MAX - 1] = 0;
		*flags = li->open_mode;
	}
	free(li);
	return ret;
}

static inline int64_t read_reply_header(int fd, int *error)
{
	LocalImageReplyEntry *lir;
	int ret = pb_read_obj(fd, (void **)&lir, PB_LOCAL_IMAGE_REPLY);

	if (ret > 0)
		*error = lir->error;
	free(lir);
	return ret;
}

static inline int64_t read_remote_header(int fd, char *snapshot_id, char *path,
	int *flags, uint64_t *size)
{
	RemoteImageEntry *ri;
	int ret = pb_read_obj(fd, (void **)&ri, PB_REMOTE_IMAGE);

	if (ret > 0) {
		strncpy(snapshot_id, ri->snapshot_id, PATH_MAX - 1);
		strncpy(path, ri->name, PATH_MAX - 1);
		*flags = ri->open_mode;
		*size = ri->size;
	}
	free(ri);
	return ret;
}

static struct rimage *new_remote_image(char *path, char *snapshot_id)
{
	struct rimage *rimg = xzalloc(sizeof(struct rimage));
	struct rbuf *buf = xzalloc(sizeof(struct rbuf));

	if (rimg == NULL || buf == NULL)
		goto err;

	strncpy(rimg->path, path, PATH_MAX -1 );
	strncpy(rimg->snapshot_id, snapshot_id, PATH_MAX - 1);
	rimg->path[PATH_MAX - 1] = '\0';
	rimg->snapshot_id[PATH_MAX - 1] = '\0';
	INIT_LIST_HEAD(&(rimg->buf_head));
	list_add_tail(&(buf->l), &(rimg->buf_head));
	rimg->curr_fwd_buf = buf;

	return rimg;
err:
	xfree(rimg);
	xfree(buf);
	return NULL;
}

static struct roperation *new_remote_operation(char *path,
	char *snapshot_id, int cli_fd, int flags, bool close_fd)
{
	struct roperation *rop = xzalloc(sizeof(struct roperation));

	if (rop == NULL)
		return NULL;

	strncpy(rop->path, path, PATH_MAX -1 );
	strncpy(rop->snapshot_id, snapshot_id, PATH_MAX - 1);
	rop->path[PATH_MAX - 1] = '\0';
	rop->snapshot_id[PATH_MAX - 1] = '\0';
	rop->fd = cli_fd;
	rop->flags = flags;
	rop->close_fd = close_fd;

	return rop;
}

static inline void rop_set_rimg(struct roperation *rop, struct rimage *rimg)
{
	rop->rimg = rimg;
	rop->size = rimg->size;
	if (rop->flags == O_APPEND) {
		// Image forward on append must start where the last fwd finished.
		if (rop->fd == remote_sk) {
			rop->curr_sent_buf = rimg->curr_fwd_buf;
			rop->curr_sent_bytes = rimg->curr_fwd_bytes;
		} else {
			// For local appends, just write at the end.
			rop->curr_sent_buf = list_entry(rimg->buf_head.prev, struct rbuf, l);
			rop->curr_sent_bytes = rop->curr_sent_buf->nbytes;
		}
		// On the receiver size, we just append
		rop->curr_recv_buf = list_entry(rimg->buf_head.prev, struct rbuf, l);
	} else {
		// Writes or reads are simple. Just do it from the beginning.
		rop->curr_recv_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
		rop->curr_sent_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
		rop->curr_sent_bytes = 0;
	}
}

/* Clears a remote image struct for reusing it. */
static inline struct rimage *clear_remote_image(struct rimage *rimg)
{
	while (!list_is_singular(&(rimg->buf_head))) {
		struct rbuf *buf = list_entry(rimg->buf_head.prev, struct rbuf, l);

		list_del(rimg->buf_head.prev);
		xfree(buf);
	}

	list_entry(rimg->buf_head.next, struct rbuf, l)->nbytes = 0;
	rimg->size = 0;

	return rimg;
}

static struct roperation *handle_accept_write(int cli_fd, char *snapshot_id,
	char *path, int flags, bool close_fd, uint64_t size)
{
	struct roperation *rop = NULL;
	struct rimage *rimg = get_rimg_by_name(snapshot_id, path);

	if (rimg == NULL) {
		rimg = new_remote_image(path, snapshot_id);
		if (rimg == NULL) {
			pr_perror("Error preparing remote image");
			goto err;
		}
	} else {
		list_del(&(rimg->l));
		if (flags == O_APPEND)
			clear_remote_image(rimg);
	}

	rop = new_remote_operation(path, snapshot_id, cli_fd, flags, close_fd);
	if (rop == NULL) {
		pr_perror("Error preparing remote operation");
		goto err;
	}

	rop_set_rimg(rop, rimg);
	rop->size = size;
	return rop;
err:
	xfree(rimg);
	xfree(rop);
	return NULL;
}

static inline struct roperation *handle_accept_proxy_write(int cli_fd,
	char *snapshot_id, char *path, int flags)
{
	return handle_accept_write(cli_fd, snapshot_id, path, flags, true, 0);
}

static struct roperation *handle_accept_proxy_read(int cli_fd,
	char *snapshot_id, char *path, int flags)
{
	struct roperation *rop = NULL;
	struct rimage *rimg    = NULL;

	rimg = get_rimg_by_name(snapshot_id, path);

	// Check if we already have the image.
	if (rimg == NULL) {
		pr_info("No image %s:%s.\n", path, snapshot_id);
		if (write_reply_header(cli_fd, ENOENT) < 0) {
			pr_perror("Error writing reply header for unexisting image");
			goto err;
		}
		close(cli_fd);
		return NULL;
	}

	if (write_reply_header(cli_fd, 0) < 0) {
		pr_perror("Error writing reply header for %s:%s",
			path, snapshot_id);
		goto err;
	}

	rop = new_remote_operation(path, snapshot_id, cli_fd, flags, true);
	if (rop == NULL) {
		pr_perror("Error preparing remote operation");
		goto err;
	}

	rop_set_rimg(rop, rimg);
	return rop;
err:
	close(cli_fd);
	return NULL;
}

static inline void finish_local()
{
	int ret;
	finished_local = true;
	ret = event_set(epoll_fd, EPOLL_CTL_DEL, local_sk, 0, 0);
	if (ret) {
		pr_perror("Failed to del local fd from epoll");
	}
}

static struct roperation *handle_accept_cache_read(int cli_fd,
	char *snapshot_id, char *path, int flags)
{
	struct rimage     *rimg = NULL;
	struct roperation *rop   = NULL;

	rop = new_remote_operation(path, snapshot_id, cli_fd, flags, true);
	if (rop == NULL) {
		pr_perror("Error preparing remote operation");
		close(cli_fd);
		return NULL;
	}

	// Check if we already have the image.
	rimg = get_rimg_by_name(snapshot_id, path);
	if (rimg != NULL && rimg->size > 0) {
		if (write_reply_header(cli_fd, 0) < 0) {
			pr_perror("Error writing reply header for %s:%s",
				path, snapshot_id);
			close(rop->fd);
			xfree(rop);
		}
		rop_set_rimg(rop, rimg);
		return rop;
	} else if (finished_remote) {
		// The file does not exist.
		pr_info("No image %s:%s.\n", path, snapshot_id);
		if (write_reply_header(cli_fd, ENOENT) < 0)
			pr_perror("Error writing reply header for unexisting image");
		close(cli_fd);
		xfree(rop);
	}
	return NULL;
}

static void forward_remote_image(struct roperation *rop)
{
	int64_t ret = 0;

	// Set blocking during the setup.
	fd_set_nonblocking(rop->fd, false);

	ret = write_remote_header(
		rop->fd, rop->snapshot_id, rop->path, rop->flags, rop->size);

	if (ret < 0) {
		pr_perror("Error writing header for %s:%s",
			rop->path, rop->snapshot_id);
		return;
	}

	pr_info("[fd=%d] Forwarding %s request for %s:%s (%" PRIu64 " bytes\n",
		rop->fd, strflags(rop->flags), rop->path, rop->snapshot_id,
		rop->size);

	// Go back to non-blocking
	fd_set_nonblocking(rop->fd, true);

	forwarding = true;
	event_set(epoll_fd, EPOLL_CTL_ADD, rop->fd, EPOLLOUT, rop);
}

static void handle_remote_accept(int fd)
{
	char path[PATH_MAX];
	char snapshot_id[PATH_MAX];
	int flags = 0;
	uint64_t size = 0;
	int64_t ret;
	struct roperation* rop = NULL;

	// Set blocking during the setup.
	fd_set_nonblocking(fd, false);

	ret = read_remote_header(fd, snapshot_id, path, &flags, &size);
	if (ret < 0) {
		pr_perror("Unable to receive remote header from image proxy");
		goto err;
	}
	/* This means that the no more images are coming. */
	else if (!ret) {
		finished_remote = true;
		pr_info("Image Proxy connection closed.\n");
		return;
	}

	// Go back to non-blocking
	fd_set_nonblocking(fd, true);

	pr_info("[fd=%d] Received %s request for %s:%s with %" PRIu64 " bytes\n",
		fd, strflags(flags), path, snapshot_id, size);


	forwarding = true;
	rop = handle_accept_write(fd, snapshot_id, path, flags, false, size);

	if (rop != NULL) {
		list_add_tail(&(rop->l), &rop_inprogress);
		event_set(epoll_fd, EPOLL_CTL_ADD, rop->fd, EPOLLIN, rop);
	}
	return;
err:
	close(fd);
}

static void handle_local_accept(int fd)
{
	int cli_fd;
	char path[PATH_MAX];
	char snapshot_id[PATH_MAX];
	int flags = 0;
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	struct roperation *rop = NULL;

	cli_fd = accept(fd, (struct sockaddr *) &cli_addr, &clilen);
	if (cli_fd < 0) {
		pr_perror("Unable to accept local image connection");
		return;
	}

	if (read_header(cli_fd, snapshot_id, path, &flags) < 0) {
		pr_err("Error reading local image header\n");
		goto err;
	}

	if (snapshot_id[0] == NULL_SNAPSHOT_ID && path[0] == FINISH) {
		close(cli_fd);
		finish_local();
		return;
	}

	pr_info("[fd=%d] Received %s request for %s:%s\n",
		cli_fd, strflags(flags), path, snapshot_id);

	// Write/Append case (only possible in img-proxy).
	if (flags != O_RDONLY) {
		rop = handle_accept_proxy_write(cli_fd, snapshot_id, path, flags);
	} else if (restoring) {
		// Read case while restoring (img-cache).
		rop = handle_accept_cache_read(cli_fd, snapshot_id, path, flags);
	} else {
		// Read case while dumping (img-proxy).
		rop = handle_accept_proxy_read(cli_fd, snapshot_id, path, flags);
	}

	// If we have an operation. Check if we are ready to start or not.
	if (rop != NULL) {
		if (rop->rimg != NULL) {
			list_add_tail(&(rop->l), &rop_inprogress);
			event_set(
				epoll_fd,
				EPOLL_CTL_ADD,
				rop->fd,
				rop->flags == O_RDONLY ? EPOLLOUT : EPOLLIN,
				rop);
		} else {
			list_add_tail(&(rop->l), &rop_pending);
		}
		fd_set_nonblocking(rop->fd, false);
	}

	return;
err:
	close(cli_fd);
}

static inline void finish_proxy_read(struct roperation *rop)
{
	// If finished forwarding image
	if (rop->fd == remote_sk) {
		// Update fwd buffer and byte count on rimg.
		rop->rimg->curr_fwd_buf = rop->curr_sent_buf;
		rop->rimg->curr_fwd_bytes = rop->curr_sent_bytes;

		forwarding = false;

		// If there are images waiting to be forwarded, forward the next.
		if (!list_empty(&rop_forwarding)) {
			forward_remote_image(list_entry(rop_forwarding.next, struct roperation, l));
		}
	}
}

static inline void finish_proxy_write(struct roperation *rop)
{
	// Normal image received, forward it.
	struct roperation *rop_to_forward = new_remote_operation(
		rop->path, rop->snapshot_id, remote_sk, rop->flags, false);

	// Add image to list of images.
	list_add_tail(&(rop->rimg->l), &rimg_head);

	rop_set_rimg(rop_to_forward, rop->rimg);
	if (list_empty(&rop_forwarding)) {
		forward_remote_image(rop_to_forward);
	}
	list_add_tail(&(rop_to_forward->l), &rop_forwarding);
}

static void finish_cache_write(struct roperation *rop)
{
	struct roperation *prop = get_rop_by_name(
	&rop_pending, rop->snapshot_id, rop->path);

	forwarding = false;
	event_set(epoll_fd, EPOLL_CTL_ADD, remote_sk, EPOLLIN, &remote_sk);

	// Add image to list of images.
	list_add_tail(&(rop->rimg->l), &rimg_head);

	if (prop != NULL) {
		pr_info("\t[fd=%d] Resuming pending %s for %s:%s\n",
			prop->fd, strflags(prop->flags),
			prop->snapshot_id, prop->path);

		// Write header for pending image.
		if (write_reply_header(prop->fd, 0) < 0) {
			pr_perror("Error writing reply header for %s:%s",
				prop->path, prop->snapshot_id);
			close(prop->fd);
			xfree(prop);
			return;
		}

		rop_set_rimg(prop, rop->rimg);
		list_del(&(prop->l));
		list_add_tail(&(prop->l), &rop_inprogress);
		event_set(epoll_fd, EPOLL_CTL_ADD, prop->fd, EPOLLOUT, prop);
	}
}

static void handle_roperation(struct epoll_event *event,
	struct roperation *rop)
{
	int64_t ret = (EPOLLOUT & event->events) ?
		send_image_async(rop) :
		recv_image_async(rop);

	if (ret > 0 || ret == EAGAIN || ret == EWOULDBLOCK) {
		event_set(
			epoll_fd,
			EPOLL_CTL_ADD,
			rop->fd,
			event->events,
			rop);
		return;
	}

	// Remove rop from list (either in progress or forwarding).
	list_del(&(rop->l));

	// Operation is finished.
	if (ret < 0) {
		pr_perror("Unable to %s %s:%s (returned %" PRId64 ")",
				event->events & EPOLLOUT ? "send" : "receive",
				rop->rimg->path, rop->rimg->snapshot_id, ret);
		goto err;
	} else {
		pr_info("[fd=%d] Finished %s %s:%s to CRIU (size %" PRIu64 ")\n",
				rop->fd,
				event->events & EPOLLOUT ? "sending" : "receiving",
				rop->rimg->path, rop->rimg->snapshot_id, rop->rimg->size);
	}

	// If receive operation is finished
	if (event->events & EPOLLIN) {
		// Cached side (finished receiving forwarded image)
		if (restoring) {
			finish_cache_write(rop);
		} else {
			// Proxy side (finished receiving local image)
			finish_proxy_write(rop);
		}
	} else {
		// Proxy side (Finished forwarding image or reading it locally).
		if (!restoring)
			finish_proxy_read(rop);
		// Nothing to be done when a read is finished on the cache side.
	}
err:
	xfree(rop);
}

static void check_pending()
{
	struct roperation *rop = NULL;
	struct rimage *rimg = NULL;

	list_for_each_entry(rop, &rop_pending, l) {
		rimg = get_rimg_by_name(rop->snapshot_id, rop->path);
		if (rimg != NULL) {
			rop_set_rimg(rop, rimg);
			if (restoring) {
				event_set(epoll_fd, EPOLL_CTL_ADD, rop->fd, EPOLLOUT, rop);
			} else {
				forward_remote_image(rop);
				return;
			}
		}
	}
}

void accept_image_connections() {
	int ret;

	epoll_fd = epoll_create(EPOLL_MAX_EVENTS);
	if (epoll_fd < 0) {
		pr_perror("Unable to open epoll");
		return;
	}

	events = calloc(EPOLL_MAX_EVENTS, sizeof(struct epoll_event));
	if (events == NULL) {
		pr_perror("Failed to allocated epoll events");
		goto end;
	}

	ret = event_set(epoll_fd, EPOLL_CTL_ADD, local_sk, EPOLLIN, &local_sk);
	if (ret) {
		pr_perror("Failed to add local fd to epoll");
		goto end;
	}

	// Only if we are restoring (cache-side) we need to add the remote sock to
	// the epoll.
	if (restoring) {
		ret = event_set(epoll_fd, EPOLL_CTL_ADD, remote_sk,
			EPOLLIN, &remote_sk);
		if (ret) {
			pr_perror("Failed to add proxy to cache fd to epoll");
			goto end;
		}
	}

	while (1) {
		int n_events, i;

		n_events = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 250);

		/* epoll_wait isn't restarted after interrupted by a signal */
		if (n_events < 0 && errno != EINTR) {
			pr_perror("Failed to epoll wait");
			goto end;
		}

		for (i = 0; i < n_events; i++) {
			// Accept from local dump/restore?
			if (events[i].data.ptr == &local_sk) {
				if (events[i].events & EPOLLHUP ||
					events[i].events & EPOLLERR) {
					if (!finished_local)
						pr_perror("Unable to accept more local image connections");
					goto end;
				}
				handle_local_accept(local_sk);
			} else if (restoring && !forwarding && events[i].data.ptr == &remote_sk) {
				event_set(epoll_fd, EPOLL_CTL_DEL, remote_sk, 0, 0);
				handle_remote_accept(remote_sk);
			} else {
				struct roperation *rop =
					(struct roperation*)events[i].data.ptr;
				event_set(epoll_fd, EPOLL_CTL_DEL, rop->fd, 0, 0);
				handle_roperation(&events[i], rop);
			}
		}

		// Check if there are any pending operations
		if (restoring || !forwarding)
			check_pending();

		// Check if we can close the tcp socket (this will unblock the cache
		// to answer "no image" to restore).
		if (!restoring &&
				finished_local &&
				!finished_remote &&
				list_empty(&rop_forwarding)) {
			close(remote_sk);
			finished_remote = true;
		}

		// If both local and remote sockets are closed, leave.
		if (finished_local && finished_remote) {
			pr_info("Finished both local and remote, exiting\n");
			goto end;
		}
	}
end:
	close(epoll_fd);
	close(local_sk);
	free(events);
}


/* Note: size is a limit on how much we want to read from the socket.  Zero means
 * read until the socket is closed.
 */
static int64_t recv_image_async(struct roperation *op)
{
	int fd = op->fd;
	struct rimage *rimg = op->rimg;
	uint64_t size = op->size;
	bool close_fd = op->close_fd;
	struct rbuf *curr_buf = op->curr_recv_buf;
	int n;

	n = read(fd,
			 curr_buf->buffer + curr_buf->nbytes,
			 size ?
				min((int) (size - rimg->size), BUF_SIZE - curr_buf->nbytes) :
				BUF_SIZE - curr_buf->nbytes);
	if (n == 0) {
		if (close_fd)
			close(fd);
		return n;
	} else if (n > 0) {
		curr_buf->nbytes += n;
		rimg->size += n;
		if (curr_buf->nbytes == BUF_SIZE) {
			struct rbuf *buf = xmalloc(sizeof(struct rbuf));
			if (buf == NULL) {
				if (close_fd)
					close(fd);
				return -1;
			}
			buf->nbytes = 0;
			list_add_tail(&(buf->l), &(rimg->buf_head));
			op->curr_recv_buf = buf;
			return n;
		}
		if (size && rimg->size == size) {
			if (close_fd)
				close(fd);
			return 0;
		}
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return errno;
	} else {
		pr_perror("Read for %s:%s socket on fd=%d failed",
			rimg->path, rimg->snapshot_id, fd);
		if (close_fd)
			close(fd);
		return -1;
	}
	return n;
}

static int64_t send_image_async(struct roperation *op)
{
	int fd = op->fd;
	struct rimage *rimg = op->rimg;
	bool close_fd = op->close_fd;
	int n;

	n = write(
		fd,
		op->curr_sent_buf->buffer + op->curr_sent_bytes,
		min(BUF_SIZE, op->curr_sent_buf->nbytes) - op->curr_sent_bytes);

	if (n > -1) {
		op->curr_sent_bytes += n;
		if (op->curr_sent_bytes == BUF_SIZE) {
			op->curr_sent_buf =
				list_entry(op->curr_sent_buf->l.next, struct rbuf, l);
			op->curr_sent_bytes = 0;
			return n;
		} else if (op->curr_sent_bytes == op->curr_sent_buf->nbytes) {
			if (close_fd)
				close(fd);
			return 0;
		}
		return n;
	} else if (errno == EPIPE || errno == ECONNRESET) {
		pr_warn("Connection for %s:%s was closed early than expected\n",
			rimg->path, rimg->snapshot_id);
		return 0;
	} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
		return errno;
	} else {
		pr_perror("Write on %s:%s socket failed",
			rimg->path, rimg->snapshot_id);
		return -1;
	}
}

int read_remote_image_connection(char *snapshot_id, char *path)
{
	int error = 0;
	int sockfd = setup_UNIX_client_socket(restoring ? DEFAULT_CACHE_SOCKET: DEFAULT_PROXY_SOCKET);

	if (sockfd < 0) {
		pr_err("Error opening local connection for %s:%s\n",
				path, snapshot_id);
		return -1;
	}

	if (write_header(sockfd, snapshot_id, path, O_RDONLY) < 0) {
		pr_err("Error writing header for %s:%s\n", path, snapshot_id);
		return -1;
	}

	if (read_reply_header(sockfd, &error) < 0) {
		pr_err("Error reading reply header for %s:%s\n",
				path, snapshot_id);
		return -1;
	}

	if (!error || (snapshot_id[0] == NULL_SNAPSHOT_ID && path[0] != FINISH))
		return sockfd;

	if (error == ENOENT) {
		pr_info("Image does not exist (%s:%s)\n", path, snapshot_id);
		close(sockfd);
		return -ENOENT;
	}
	pr_err("Unexpected error returned: %d (%s:%s)\n",
			error, path, snapshot_id);
	close(sockfd);
	return -1;
}

int write_remote_image_connection(char *snapshot_id, char *path, int flags)
{
	int sockfd = setup_UNIX_client_socket(DEFAULT_PROXY_SOCKET);

	if (sockfd < 0)
		return -1;

	if (write_header(sockfd, snapshot_id, path, flags) < 0) {
		pr_err("Error writing header for %s:%s\n", path, snapshot_id);
		return -1;
	}
	return sockfd;
}

int finish_remote_dump(void)
{
	pr_info("Dump side is calling finish\n");
	int fd = write_remote_image_connection(NULL_SNAPSHOT_ID, FINISH, O_WRONLY);

	if (fd == -1) {
		pr_err("Unable to open finish dump connection");
		return -1;
	}

	close(fd);
	return 0;
}

int finish_remote_restore(void)
{
	pr_info("Restore side is calling finish\n");
	int fd = read_remote_image_connection(NULL_SNAPSHOT_ID, FINISH);

	if (fd == -1) {
		pr_err("Unable to open finish restore connection\n");
		return -1;
	}

	close(fd);
	return 0;
}

int skip_remote_bytes(int fd, unsigned long len)
{
	static char buf[4096];
	int n = 0;
	unsigned long curr = 0;

	for (; curr < len; ) {
		n = read(fd, buf, min(len - curr, (unsigned long)4096));
		if (n == 0) {
			pr_perror("Unexpected end of stream (skipping %lx/%lx bytes)",
				curr, len);
			return -1;
		} else if (n > 0) {
			curr += n;
		} else {
			pr_perror("Error while skipping bytes from stream (%lx/%lx)",
				curr, len);
			return -1;
		}
	}

	if (curr != len) {
		pr_err("Unable to skip the current number of bytes: %lx instead of %lx\n",
			curr, len);
		return -1;
	}
	return 0;
}

static int pull_snapshot_ids(void)
{
	int n, sockfd;
	SnapshotIdEntry *ls;
	struct snapshot *s = NULL;

	sockfd = read_remote_image_connection(NULL_SNAPSHOT_ID, PARENT_IMG);

	/* The connection was successful but there is not file. */
	if (sockfd < 0) {
		if (errno != ENOENT) {
			pr_err("Unable to open snapshot id read connection\n");
			return -1;
		}
		return 0;
	}

	while (1) {
		n = pb_read_obj(sockfd, (void **)&ls, PB_SNAPSHOT_ID);
		if (!n) {
			close(sockfd);
			return n;
		} else if (n < 0) {
			pr_err("Unable to read remote snapshot ids\n");
			close(sockfd);
			return n;
		}

		s = new_snapshot(ls->snapshot_id);
		if (!s) {
			close(sockfd);
			return -1;
		}
		add_snapshot(s);
		pr_info("[read_snapshot ids] parent = %s\n", ls->snapshot_id);
	}
	free(ls);
	close(sockfd);
	return n;
}

int push_snapshot_id(void)
{
	int n;
	restoring = false;
	SnapshotIdEntry rn = SNAPSHOT_ID_ENTRY__INIT;
	int sockfd = write_remote_image_connection(NULL_SNAPSHOT_ID, PARENT_IMG, O_APPEND);

	if (sockfd < 0) {
		pr_err("Unable to open snapshot id push connection\n");
		return -1;
	}

	rn.snapshot_id = xmalloc(sizeof(char) * PATH_MAX);
	if (!rn.snapshot_id) {
		close(sockfd);
		return -1;
	}
	strncpy(rn.snapshot_id, snapshot_id, PATH_MAX);

	n = pb_write_obj(sockfd, &rn, PB_SNAPSHOT_ID);

	xfree(rn.snapshot_id);
	close(sockfd);
	return n;
}

void init_snapshot_id(char *si)
{
	snapshot_id = si;
}

char *get_curr_snapshot_id(void)
{
	return snapshot_id;
}

int get_curr_snapshot_id_idx(void)
{
	struct snapshot *si;
	int idx = 0;

	if (list_empty(&snapshot_head))
		pull_snapshot_ids();

	list_for_each_entry(si, &snapshot_head, l) {
		if (!strncmp(si->snapshot_id, snapshot_id, PATH_MAX))
			return idx;
		idx++;
	}

	pr_err("Error, could not find current snapshot id (%s) fd\n",
		snapshot_id);
	return -1;
}

char *get_snapshot_id_from_idx(int idx)
{
	struct snapshot *si;

	if (list_empty(&snapshot_head))
		pull_snapshot_ids();

	/* Note: if idx is the service fd then we need the current
	 * snapshot_id idx. Else we need a parent snapshot_id idx.
	 */
	if (idx == get_service_fd(IMG_FD_OFF))
		idx = get_curr_snapshot_id_idx();

	list_for_each_entry(si, &snapshot_head, l) {
		if (!idx)
			return si->snapshot_id;
		idx--;
	}

	pr_err("Error, could not find snapshot id for idx %d\n", idx);
	return NULL;
}

int get_curr_parent_snapshot_id_idx(void)
{
	return get_curr_snapshot_id_idx() - 1;
}
