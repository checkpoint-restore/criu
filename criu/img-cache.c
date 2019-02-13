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
		remote_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", remote_sk);
	} else {
		remote_sk = setup_tcp_server("image cache");
		if (remote_sk < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			return -1;
		}
		// Wait to accept connection from proxy.
		tmp = accept(remote_sk, NULL, 0);
		if (tmp < 0) {
			pr_perror("Unable to accept remote image connection"
				  " from image proxy");
			close(remote_sk);
			return -1;
		}
		remote_sk = tmp;
	}

	pr_info("Cache is connected to Proxy through fd %d\n", remote_sk);

	local_sk = setup_UNIX_server_socket(local_cache_path);
	if (local_sk < 0) {
		pr_perror("Unable to open cache to proxy UNIX socket");
		close(remote_sk);
		return -1;

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
