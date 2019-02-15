#include <sys/socket.h>
#include <unistd.h>

#include "cr_options.h"
#include "img-remote.h"
#include "util.h"

int image_cache(bool background, char *local_cache_path)
{
	int tmp;

	pr_info("Proxy to Cache Port %u, CRIU to Cache Path %s\n",
			opts.port, local_cache_path);
	restoring = true;

	if (opts.ps_socket != -1) {
		pr_info("Re-using ps socket %d\n", opts.ps_socket);
	} else {
		tmp = setup_tcp_server("image cache");
		if (tmp < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
		/* Wait to accept connection from proxy. */
		opts.ps_socket = accept(tmp, NULL, 0);
		if (opts.ps_socket < 0) {
			pr_perror("Unable to accept remote image connection"
				  " from image proxy");
			close(tmp);
			return -1;
		}
	}

	pr_info("Cache is connected to Proxy through fd %d\n", opts.ps_socket);

	local_req_fd = setup_UNIX_server_socket(local_cache_path);
	if (local_req_fd < 0) {
		pr_perror("Unable to open cache to proxy UNIX socket");
		close(opts.ps_socket);
		return -1;

	}

	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}

	accept_image_connections();
	pr_info("Finished image cache\n");
	return 0;
}
