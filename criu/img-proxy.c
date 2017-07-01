#include <unistd.h>

#include "img-remote.h"
#include "img-remote.h"
#include "criu-log.h"
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include "cr_options.h"

static struct rimage *wait_for_image(struct wthread *wt)
{
	return get_rimg_by_name(wt->snapshot_id, wt->path);
}

int64_t forward_image(struct rimage *rimg)
{
	int64_t ret;
	int fd = proxy_to_cache_fd;

	pthread_mutex_lock(&(rimg->in_use));
	pr_info("Forwarding %s:%s (%lu bytes)\n",
	    rimg->path, rimg->snapshot_id, (unsigned long)rimg->size);
	if (write_remote_header(
		fd, rimg->snapshot_id, rimg->path, O_APPEND, rimg->size) < 0) {
		pr_perror("Error writing header for %s:%s",
			rimg->path, rimg->snapshot_id);
		pthread_mutex_unlock(&(rimg->in_use));
		return -1;
	}

	ret = send_image(fd, rimg, O_APPEND, false);
	if (ret < 0) {
		pr_perror("Unable to send %s:%s to image cache",
			rimg->path, rimg->snapshot_id);
		pthread_mutex_unlock(&(rimg->in_use));
		return -1;
	} else if (ret != rimg->size) {
		pr_perror("Unable to send %s:%s to image proxy (sent %ld bytes, expected %lu bytes",
		    rimg->path, rimg->snapshot_id, (long)ret, (unsigned long)rimg->size);
		pthread_mutex_unlock(&(rimg->in_use));
		return -1;
	}
	pr_info("Finished forwarding %s:%s (sent %lu bytes)\n",
	    rimg->path, rimg->snapshot_id, (unsigned long)rimg->size);
	pthread_mutex_unlock(&(rimg->in_use));
	return ret;
}

int image_proxy(bool background, char *local_proxy_path, char *fwd_host, unsigned short fwd_port)
{
	pthread_t local_req_thr;

	pr_info("CRIU to Proxy Path: %s, Cache Address %s:%hu\n",
		local_proxy_path, fwd_host, fwd_port);

	local_req_fd = setup_UNIX_server_socket(local_proxy_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open CRIU to proxy UNIX socket");
		return -1;
	}

	if (opts.ps_socket != -1) {
		proxy_to_cache_fd = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", proxy_to_cache_fd);
	} else {
		proxy_to_cache_fd = setup_TCP_client_socket(fwd_host, fwd_port);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
	}

	if (init_daemon(background, wait_for_image))
		return -1;

	if (pthread_create(
	    &local_req_thr,
	    NULL,
	    accept_local_image_connections,
	    (void *) &local_req_fd)) {
		pr_perror("Unable to create local requests thread");
		return -1;
	}

	pthread_join(local_req_thr, NULL);
	join_workers();
	pr_info("Finished image proxy.");
	return 0;
}
