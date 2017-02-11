#include <unistd.h>
#include <stdlib.h>

#include <semaphore.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "sys/un.h"
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>

#include "img-remote-proto.h"
#include "criu-log.h"
#include "common/compiler.h"

#include "protobuf.h"
#include "images/remote-image.pb-c.h"
#include "image.h"

LIST_HEAD(rimg_head);
pthread_mutex_t rimg_lock;

pthread_mutex_t proxy_to_cache_lock;

LIST_HEAD(workers_head);
pthread_mutex_t workers_lock;
sem_t workers_semph;

struct rimage * (*wait_for_image) (struct wthread *wt);

bool finished = false;
int writing = 0;
int forwarding = 0;
int proxy_to_cache_fd;
int local_req_fd;

struct rimage *get_rimg_by_name(const char *snapshot_id, const char *path)
{
	struct rimage *rimg = NULL;

	pthread_mutex_lock(&rimg_lock);
	list_for_each_entry(rimg, &rimg_head, l) {
		if (!strncmp(rimg->path, path, PATHLEN) &&
		    !strncmp(rimg->snapshot_id, snapshot_id, PATHLEN)) {
			pthread_mutex_unlock(&rimg_lock);
			return rimg;
		}
	}
	pthread_mutex_unlock(&rimg_lock);
	return NULL;
}

static struct wthread *get_wt_by_name(const char *snapshot_id, const char *path)
{
	struct wthread *wt = NULL;

	pthread_mutex_lock(&workers_lock);
	list_for_each_entry(wt, &workers_head, l) {
		if (!strncmp(wt->path, path, PATHLEN) &&
		   !strncmp(wt->snapshot_id, snapshot_id, PATHLEN)) {
			pthread_mutex_unlock(&workers_lock);
			return wt;
		}
	}
	pthread_mutex_unlock(&workers_lock);
	return NULL;
}

static int init_sync_structures(void)
{
	if (pthread_mutex_init(&rimg_lock, NULL) != 0) {
		pr_perror("Remote image list mutex init failed");
		return -1;
	}

	if (pthread_mutex_init(&proxy_to_cache_lock, NULL) != 0) {
		pr_perror("Remote image connection mutex init failed");
		return -1;
	}

	if (pthread_mutex_init(&workers_lock, NULL) != 0) {
		pr_perror("Workers mutex init failed");
		return -1;
	}

	if (sem_init(&workers_semph, 0, 0) != 0) {
		pr_perror("Workers semaphore init failed");
		return -1;
	}

	return 0;
}

void prepare_recv_rimg(void)
{
	pthread_mutex_lock(&rimg_lock);
	writing++;
	pthread_mutex_unlock(&rimg_lock);
}

void finalize_recv_rimg(struct rimage *rimg)
{

	pthread_mutex_lock(&rimg_lock);

	if (rimg)
		list_add_tail(&(rimg->l), &rimg_head);
	writing--;
	pthread_mutex_unlock(&rimg_lock);
	/* Wake thread waiting for this image. */
	if (rimg) {
		struct wthread *wt = get_wt_by_name(rimg->snapshot_id, rimg->path);
		if (wt)
			sem_post(&(wt->wakeup_sem));
	}
}

bool is_receiving(void)
{
	int ret;

	pthread_mutex_lock(&rimg_lock);
	ret = writing;
	pthread_mutex_unlock(&rimg_lock);
	return ret > 0;
}

static void prepare_fwd_rimg(void)
{
	pthread_mutex_lock(&rimg_lock);
	forwarding++;
	pthread_mutex_unlock(&rimg_lock);
}

static void finalize_fwd_rimg(void)
{
	pthread_mutex_lock(&rimg_lock);
	forwarding--;
	pthread_mutex_unlock(&rimg_lock);
}

static bool is_forwarding(void)
{
	int ret;

	pthread_mutex_lock(&rimg_lock);
	ret = forwarding;
	pthread_mutex_unlock(&rimg_lock);
	return ret > 0;
}

/* This function is called when no more images are coming. Threads still waiting
 * for images will be awaken to send a ENOENT (no such file) to the requester.
 */
void unlock_workers(void)
{
	struct wthread *wt = NULL;

	pthread_mutex_lock(&workers_lock);
	list_for_each_entry(wt, &workers_head, l)
		sem_post(&(wt->wakeup_sem));
	pthread_mutex_unlock(&workers_lock);
}

int init_daemon(bool background, struct rimage *(*wfi)(struct wthread*))
{
	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}
	wait_for_image = wfi;
	return init_sync_structures();
}

int setup_TCP_server_socket(int port)
{
	struct sockaddr_in serv_addr;
	int sockopt = 1;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0) {
		pr_perror("Unable to open image socket");
		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);

	if (setsockopt(
	    sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
		pr_perror("Unable to set SO_REUSEADDR");
		return -1;
	}

	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		pr_perror("Unable to bind image socket");
		return -1;
	}

	if (listen(sockfd, DEFAULT_LISTEN)) {
		pr_perror("Unable to listen image socket");
		return -1;
	}

	return sockfd;
}

int setup_TCP_client_socket(char *hostname, int port)
{
	int sockfd;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		pr_perror("Unable to open remote image socket");
		return -1;
	}

	server = gethostbyname(hostname);
	if (server == NULL) {
		pr_perror("Unable to get host by name (%s)", hostname);
		return -1;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *) server->h_addr,
	      (char *) &serv_addr.sin_addr.s_addr,
	      server->h_length);
	serv_addr.sin_port = htons(port);

	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		pr_perror("Unable to connect to remote %s", hostname);
		return -1;
	}

	return sockfd;
}

int setup_UNIX_server_socket(char *path)
{
	struct sockaddr_un addr;
	int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

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
		return -1;
	}

	if (listen(sockfd, 50) == -1) {
		pr_perror("Unable to listen image socket");
		return -1;
	}

	return sockfd;
}

int setup_UNIX_client_socket(char *path)
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

int64_t pb_write_obj(int fd, void *obj, int type)
{
	struct cr_img img;

	img._x.fd = fd;
	bfd_setraw(&img._x);
	return pb_write_one(&img, obj, type);
}

int64_t pb_read_obj(int fd, void **pobj, int type)
{
	struct cr_img img;

	img._x.fd = fd;
	bfd_setraw(&img._x);
	return do_pb_read_one(&img, pobj, type, true);
}

int64_t write_header(int fd, char *snapshot_id, char *path, int flags)
{
	LocalImageEntry li = LOCAL_IMAGE_ENTRY__INIT;

	li.name = path;
	li.snapshot_id = snapshot_id;
	li.open_mode = flags;
	return pb_write_obj(fd, &li, PB_LOCAL_IMAGE);
}

int64_t write_reply_header(int fd, int error)
{
	LocalImageReplyEntry lir = LOCAL_IMAGE_REPLY_ENTRY__INIT;

	lir.error = error;
	return pb_write_obj(fd, &lir, PB_LOCAL_IMAGE_REPLY);
}

int64_t write_remote_header(int fd, char *snapshot_id, char *path, int flags, uint64_t size)
{
	RemoteImageEntry ri = REMOTE_IMAGE_ENTRY__INIT;

	ri.name = path;
	ri.snapshot_id = snapshot_id;
	ri.open_mode = flags;
	ri.size = size;
	return pb_write_obj(fd, &ri, PB_REMOTE_IMAGE);
}

int64_t read_header(int fd, char *snapshot_id, char *path, int *flags)
{
	LocalImageEntry *li;
	int ret = pb_read_obj(fd, (void **)&li, PB_LOCAL_IMAGE);

	if (ret > 0) {
		strncpy(snapshot_id, li->snapshot_id, PATHLEN);
		strncpy(path, li->name, PATHLEN);
		*flags = li->open_mode;
	}
	free(li);
	return ret;
}

int64_t read_reply_header(int fd, int *error)
{
	LocalImageReplyEntry *lir;
	int ret = pb_read_obj(fd, (void **)&lir, PB_LOCAL_IMAGE_REPLY);

	if (ret > 0)
		*error = lir->error;
	free(lir);
	return ret;
}

int64_t read_remote_header(int fd, char *snapshot_id, char *path, int *flags, uint64_t *size)
{
	RemoteImageEntry *ri;
	int ret = pb_read_obj(fd, (void **)&ri, PB_REMOTE_IMAGE);

	if (ret > 0) {
		strncpy(snapshot_id, ri->snapshot_id, PATHLEN);
		strncpy(path, ri->name, PATHLEN);
		*flags = ri->open_mode;
		*size = ri->size;
	}
	free(ri);
	return ret;
}

static struct wthread *new_worker(void)
{
	struct wthread *wt = malloc(sizeof(struct wthread));

	if (!wt) {
		pr_perror("Unable to allocate worker thread structure");
		return NULL;
	}
	if (sem_init(&(wt->wakeup_sem), 0, 0) != 0) {
		pr_perror("Workers semaphore init failed");
		return NULL;
	}
	return wt;
}

static void add_worker(struct wthread *wt)
{
	pthread_mutex_lock(&workers_lock);
	list_add_tail(&(wt->l), &workers_head);
	pthread_mutex_unlock(&workers_lock);
	sem_post(&workers_semph);
}

void join_workers(void)
{
	struct wthread *wthread = NULL;

	while (! list_empty(&workers_head)) {
		wthread = list_entry(workers_head.next, struct wthread, l);
		pthread_join(wthread->tid, NULL);
		list_del(&(wthread->l));
		free(wthread);
	}
}

static struct rimage *new_remote_image(char *path, char *snapshot_id)
{
	struct rimage *rimg = malloc(sizeof(struct rimage));
	struct rbuf *buf = malloc(sizeof(struct rbuf));

	if (rimg == NULL) {
		pr_perror("Unable to allocate remote_image structures");
		return NULL;
	}

	if (buf == NULL) {
		pr_perror("Unable to allocate remote_buffer structures");
		return NULL;
	}

	strncpy(rimg->path, path, PATHLEN);
	strncpy(rimg->snapshot_id, snapshot_id, PATHLEN);
	rimg->size = 0;
	buf->nbytes = 0;
	INIT_LIST_HEAD(&(rimg->buf_head));
	list_add_tail(&(buf->l), &(rimg->buf_head));
	rimg->curr_sent_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
	rimg->curr_sent_bytes = 0;

	if (pthread_mutex_init(&(rimg->in_use), NULL) != 0) {
		pr_perror("Remote image in_use mutex init failed");
		return NULL;
	}
	return rimg;
}

/* Clears a remote image struct for reusing it. */
static struct rimage *clear_remote_image(struct rimage *rimg)
{
	pthread_mutex_lock(&(rimg->in_use));

	while (!list_is_singular(&(rimg->buf_head))) {
		struct rbuf *buf = list_entry(rimg->buf_head.prev, struct rbuf, l);

		list_del(rimg->buf_head.prev);
		free(buf);
	}

	list_entry(rimg->buf_head.next, struct rbuf, l)->nbytes = 0;
	rimg->size = 0;
	rimg->curr_sent_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
	rimg->curr_sent_bytes = 0;

	pthread_mutex_unlock(&(rimg->in_use));

	return rimg;
}

struct rimage *prepare_remote_image(char *path, char *snapshot_id, int open_mode)
{
	struct rimage *rimg = get_rimg_by_name(snapshot_id, path);
	/* There is no record of such image, create a new one. */

	if (rimg == NULL)
		return new_remote_image(path, snapshot_id);

	pthread_mutex_lock(&rimg_lock);
	list_del(&(rimg->l));
	pthread_mutex_unlock(&rimg_lock);

	/* There is already an image record. Simply return it for appending. */
	if (open_mode == O_APPEND)
		return rimg;
	/* There is already an image record. Clear it for writing. */
	else
		return clear_remote_image(rimg);
}

void *process_local_read(struct wthread *wt)
{
	struct rimage *rimg = NULL;
	int64_t ret;
	/* TODO - split wait_for_image
	 * in cache - improve the parent stuf
	 * in proxy - do not wait for anything, return no file
	 */
	rimg = wait_for_image(wt);
	if (!rimg) {
		pr_info("No image %s:%s.\n", wt->path, wt->snapshot_id);
		if (write_reply_header(wt->fd, ENOENT) < 0)
			pr_perror("Error writing reply header for unexisting image");
		close(wt->fd);
		return NULL;
	} else {
		if (write_reply_header(wt->fd, 0) < 0) {
			pr_perror("Error writing reply header for %s:%s",
					wt->path, wt->snapshot_id);
			close(wt->fd);
			return NULL;
		}
	}

	pthread_mutex_lock(&(rimg->in_use));
	ret = send_image(wt->fd, rimg, wt->flags, true);
	if (ret < 0)
		pr_perror("Unable to send %s:%s to CRIU (sent %ld bytes)",
				rimg->path, rimg->snapshot_id, (long)ret);
	else
		pr_info("Finished sending %s:%s to CRIU (sent %ld bytes)\n",
				rimg->path, rimg->snapshot_id, (long)ret);
	pthread_mutex_unlock(&(rimg->in_use));
	return NULL;
}

static void *process_local_image_connection(void *ptr)
{
	struct wthread *wt = (struct wthread *) ptr;
	struct rimage *rimg = NULL;
	int64_t ret;

	/* NOTE: the code inside this if is shared for both cache and proxy. */
	if (wt->flags == O_RDONLY)
		return process_local_read(wt);

	/* NOTE: IMAGE PROXY ONLY. The image cache receives write connections
	 * through TCP (see accept_remote_image_connections).
	 */
	rimg = prepare_remote_image(wt->path, wt->snapshot_id, wt->flags);
	ret = recv_image(wt->fd, rimg, 0, wt->flags, true);
	if (ret < 0) {
		pr_perror("Unable to receive %s:%s to CRIU (received %ld bytes)",
				rimg->path, rimg->snapshot_id, (long)ret);
		finalize_recv_rimg(NULL);
		return NULL;
	}
	finalize_recv_rimg(rimg);
	pr_info("Finished receiving %s:%s (received %ld bytes)\n",
			rimg->path, rimg->snapshot_id, (long)ret);


	if (!strncmp(rimg->path, DUMP_FINISH, sizeof(DUMP_FINISH))) {
		finished = true;
		shutdown(local_req_fd, SHUT_RD);
	} else {
		pthread_mutex_lock(&proxy_to_cache_lock);
		ret = forward_image(rimg);
		pthread_mutex_unlock(&proxy_to_cache_lock);
	}

	finalize_fwd_rimg();
	if (ret < 0) {
		pr_perror("Unable to forward %s:%s to Image Cache",
				rimg->path, rimg->snapshot_id);

		return NULL;
	}

	if (finished && !is_forwarding() && !is_receiving()) {
		pr_info("Closing connection to Image Cache.\n");
		close(proxy_to_cache_fd);
		unlock_workers();
	}
	return NULL;
}


void *accept_local_image_connections(void *port)
{
	int fd = *((int *) port);
	int cli_fd;
	struct sockaddr_in cli_addr;

	socklen_t clilen = sizeof(cli_addr);
	pthread_t tid;
	struct wthread *wt;

	while (1) {
		cli_fd = accept(fd, (struct sockaddr *) &cli_addr, &clilen);
		if (cli_fd < 0) {
			if (!finished)
				pr_err("Unable to accept local image connection");
			close(cli_fd);
			return NULL;
		}

		wt = new_worker();
		wt->fd = cli_fd;

		if (read_header(wt->fd, wt->snapshot_id, wt->path, &(wt->flags)) < 0) {
			pr_perror("Error reading local image header");
			return NULL;
		}

		pr_info("Received %s request for %s:%s\n",
		    wt->flags == O_RDONLY ? "read" :
			wt->flags == O_APPEND ? "append" : "write",
		    wt->path, wt->snapshot_id);

		/* These function calls are used to avoid other threads from
		 * thinking that there are no more images are coming.
		 */
		if (wt->flags != O_RDONLY) {
			prepare_recv_rimg();
			prepare_fwd_rimg();
		}

		/* We need to flock the last pid file to avoid stealing pids
		 * from restore.
		 */
		int fd = open_proc_rw(PROC_GEN, LAST_PID_PATH);
		if (fd < 0) {
			pr_perror("Can't open %s", LAST_PID_PATH);
		}

		if (flock(fd, LOCK_EX)) {
			close(fd);
			pr_perror("Can't lock %s", LAST_PID_PATH);
			return NULL;
		}

		if (pthread_create(
		    &tid, NULL, process_local_image_connection, (void *) wt)) {
			pr_perror("Unable to create worker thread");
			return NULL;
		}

		if (flock(fd, LOCK_UN))
			pr_perror("Can't unlock %s", LAST_PID_PATH);
		close(fd);

		wt->tid = tid;
		add_worker(wt);
	}
}

/* Note: size is a limit on how much we want to read from the socket.  Zero means
 * read until the socket is closed.
 */
int64_t recv_image(int fd, struct rimage *rimg, uint64_t size, int flags, bool close_fd)
{
	struct rbuf *curr_buf = NULL;
	int n;

	if (flags == O_APPEND)
		curr_buf = list_entry(rimg->buf_head.prev, struct rbuf, l);
	else
		curr_buf = list_entry(rimg->buf_head.next, struct rbuf, l);

	while (1) {
		n = read(fd,
			 curr_buf->buffer + curr_buf->nbytes,
			 size ?
			     min((int) (size - rimg->size), BUF_SIZE - curr_buf->nbytes) :
			     BUF_SIZE - curr_buf->nbytes);
		if (n == 0) {
			if (close_fd)
				close(fd);
			return rimg->size;
		} else if (n > 0) {
			curr_buf->nbytes += n;
			rimg->size += n;
			if (curr_buf->nbytes == BUF_SIZE) {
			  struct rbuf *buf = malloc(sizeof(struct rbuf));
				if (buf == NULL) {
					pr_perror("Unable to allocate remote_buffer structures");
					if (close_fd)
						close(fd);
					return -1;
				}
				buf->nbytes = 0;
				list_add_tail(&(buf->l), &(rimg->buf_head));
				curr_buf = buf;
			}
			if (size && rimg->size == size) {
				if (close_fd)
					close(fd);
				return rimg->size;
			}
		} else {
			pr_perror("Read on %s:%s socket failed",
				rimg->path, rimg->snapshot_id);
			if (close_fd)
				close(fd);
			return -1;
		}
	}
}

int64_t send_image(int fd, struct rimage *rimg, int flags, bool close_fd)
{

	int n, nblocks = 0;

	if (flags != O_APPEND) {
		rimg->curr_sent_buf = list_entry(rimg->buf_head.next, struct rbuf, l);
		rimg->curr_sent_bytes = 0;
	}

	while (1) {
		n = send(
		    fd,
		    rimg->curr_sent_buf->buffer + rimg->curr_sent_bytes,
		    min(BUF_SIZE, rimg->curr_sent_buf->nbytes) - rimg->curr_sent_bytes,
		    MSG_NOSIGNAL);
		if (n > -1) {
			rimg->curr_sent_bytes += n;
			if (rimg->curr_sent_bytes == BUF_SIZE) {
				rimg->curr_sent_buf =
				    list_entry(rimg->curr_sent_buf->l.next, struct rbuf, l);
				nblocks++;
				rimg->curr_sent_bytes = 0;
			} else if (rimg->curr_sent_bytes == rimg->curr_sent_buf->nbytes) {
				if (close_fd)
					close(fd);
				return nblocks*BUF_SIZE + rimg->curr_sent_buf->nbytes;
			}
		} else if (errno == EPIPE || errno == ECONNRESET) {
			pr_warn("Connection for %s:%s was closed early than expected\n",
				rimg->path, rimg->snapshot_id);
			return 0;
		} else {
			pr_perror("Write on %s:%s socket failed",
				rimg->path, rimg->snapshot_id);
			return -1;
		}
	}

}
