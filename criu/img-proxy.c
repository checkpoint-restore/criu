#include <unistd.h>

#include "img-remote.h"
#include "criu-log.h"
#include <fcntl.h>
#include <sys/socket.h>
#include "cr_options.h"
#include "util.h"

int image_proxy(bool background, char *local_proxy_path, char *fwd_host, unsigned short fwd_port)
{
	pr_info("CRIU to Proxy Path: %s, Cache Address %s:%hu\n",
		local_proxy_path, fwd_host, fwd_port);
	restoring = false;

	local_req_fd = setup_UNIX_server_socket(local_proxy_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open CRIU to proxy UNIX socket");
		return -1;
	}

	if (opts.ps_socket != -1) {
		proxy_to_cache_fd = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", proxy_to_cache_fd);
	} else {
		proxy_to_cache_fd = setup_tcp_client(fwd_host, fwd_port);
		if (proxy_to_cache_fd < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1; // TODO - should close other sockets.
		}
	}

	pr_info("Proxy is connected to Cache through fd %d\n", proxy_to_cache_fd);

	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}

	// TODO - local_req_fd and proxy_to_cache_fd send as args.
	accept_image_connections();
	pr_info("Finished image proxy.");
	return 0;
}
