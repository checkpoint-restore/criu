#include <unistd.h>

#include "img-remote.h"
#include "criu-log.h"
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "cr_options.h"

static struct rimage *wait_for_image(struct wthread *wt)
{
	struct rimage *result;

	if (!strncmp(wt->path, RESTORE_FINISH, sizeof(RESTORE_FINISH))) {
		finished = true;
		shutdown(local_req_fd, SHUT_RD);
		return NULL;
	}

	result = get_rimg_by_name(wt->snapshot_id, wt->path);
	if (result != NULL && result->size > 0)
		return result;

	/* The file does not exist and we do not expect new files */
	if (finished && !is_receiving())
		return NULL;

	/* NOTE: at this point, when the thread wakes up, either the image is
	 * already in memory or it will never come (the dump is finished).
	 */
	sem_wait(&(wt->wakeup_sem));
	result = get_rimg_by_name(wt->snapshot_id, wt->path);
	if (result != NULL && result->size > 0)
		return result;
	else
		return NULL;
}

/* The image cache creates a thread that calls this function. It waits for remote
 * images from the image-cache.
 */
void *accept_remote_image_connections(void *port)
{
	int fd = *((int *) port);
	struct sockaddr_in cli_addr;
	socklen_t clilen = sizeof(cli_addr);
	char snapshot_id_buf[PATHLEN], path_buf[PATHLEN];
	uint64_t size;
	int64_t ret;
	int flags, proxy_fd;
	struct rimage *rimg;

	proxy_fd = accept(fd, (struct sockaddr *) &cli_addr, &clilen);
	if (proxy_fd < 0) {
		pr_perror("Unable to accept remote image connection from image proxy");
		return NULL;
	}
	while (1) {
		ret = read_remote_header(proxy_fd, snapshot_id_buf, path_buf, &flags, &size);
		if (ret < 0) {
			pr_perror("Unable to receive remote header from image proxy");
			return NULL;
		}
		/* This means that the no more images are coming. */
		else if (!ret) {
			pr_info("Image Proxy connection closed.\n");
			finished = true;
			unlock_workers();
			return NULL;
		}

		pr_info("Received %s request for %s:%s\n",
			flags == O_RDONLY ? "read" :
				flags == O_APPEND ? "append" : "write",
			path_buf, snapshot_id_buf);

		rimg = prepare_remote_image(path_buf, snapshot_id_buf, flags);

		prepare_recv_rimg();
		if (!size)
			ret = 0;
		else
			ret = recv_image(proxy_fd, rimg, size, flags, false);
		if (ret < 0) {
			pr_perror("Unable to receive %s:%s from image proxy",
				rimg->path, rimg->snapshot_id);
			finalize_recv_rimg(NULL);
			return NULL;
		} else if (ret != size) {
			pr_perror("Unable to receive %s:%s from image proxy (received %ld bytes, expected %lu bytes)",
				rimg->path, rimg->snapshot_id, (long)ret, (unsigned long)size);
			finalize_recv_rimg(NULL);
			return NULL;
		}
		finalize_recv_rimg(rimg);

		pr_info("Finished receiving %s:%s (received %ld bytes)\n",
			rimg->path, rimg->snapshot_id, (long)ret);
	}
}

int image_cache(bool background, char *local_cache_path, unsigned short cache_write_port)
{
	pthread_t local_req_thr, remote_req_thr;

	pr_info("Proxy to Cache Port %d, CRIU to Cache Path %s\n",
			cache_write_port, local_cache_path);


	if (opts.ps_socket != -1) {
		proxy_to_cache_fd = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", proxy_to_cache_fd);
	} else {
		proxy_to_cache_fd = setup_TCP_server_socket(cache_write_port);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
	}

	local_req_fd = setup_UNIX_server_socket(local_cache_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open cache to proxy UNIX socket");
		return -1;
	}

	if (init_daemon(background, wait_for_image)) {
		pr_perror("Unable to initialize daemon");
		return -1;
	}

	if (pthread_create(
		&remote_req_thr,
		NULL, accept_remote_image_connections,
		(void *) &proxy_to_cache_fd)) {
		pr_perror("Unable to create remote requests thread");
		return -1;
	}
	if (pthread_create(
		&local_req_thr,
		NULL,
		accept_local_image_connections,
		(void *) &local_req_fd)) {
		pr_perror("Unable to create local requests thread");
		return -1;
	}

	pthread_join(remote_req_thr, NULL);
	pthread_join(local_req_thr, NULL);
	join_workers();
	pr_info("Finished image cache.");
	return 0;
}
