#include <unistd.h>

#include "img-remote.h"
#include "criu-log.h"
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "cr_options.h"
#include "util.h"

int image_cache(bool background, char *local_cache_path, unsigned short cache_write_port)
{
	pr_info("Proxy to Cache Port %d, CRIU to Cache Path %s\n",
			cache_write_port, local_cache_path);
	restoring = true;

	if (opts.ps_socket != -1) {
		proxy_to_cache_fd = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", proxy_to_cache_fd);
	} else {
		proxy_to_cache_fd = setup_tcp_server("image cache", NULL, &cache_write_port);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
		// Wait to accept connection from proxy.
		proxy_to_cache_fd = accept(proxy_to_cache_fd, NULL, 0);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to accept remote image connection"
				  " from image proxy");
			return -1; // TODO - should close other sockets.
		}
	}

	pr_info("Cache is connected to Proxy through fd %d\n", proxy_to_cache_fd);

	local_req_fd = setup_UNIX_server_socket(local_cache_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open cache to proxy UNIX socket");
		return -1; // TODO - should close other sockets.

	}

	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}

	accept_image_connections();
	pr_info("Finished image cache.");
	return 0;
}
