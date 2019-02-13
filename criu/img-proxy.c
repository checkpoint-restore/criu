#include <unistd.h>

#include "cr_options.h"
#include "criu-log.h"
#include "img-remote.h"
#include "util.h"

int image_proxy(bool background, char *local_proxy_path)
{
	pr_info("CRIU to Proxy Path: %s, Cache Address %s:%u\n",
		local_proxy_path, opts.addr, opts.port);
	restoring = false;

	local_sk = setup_UNIX_server_socket(local_proxy_path);
	if (local_sk < 0) {
		pr_perror("Unable to open CRIU to proxy UNIX socket");
		return -1;
	}

	if (opts.ps_socket != -1) {
		remote_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", remote_sk);
	} else {
		remote_sk = setup_tcp_client();
		if (remote_sk < 0) {
			pr_perror("Unable to open proxy to cache TCP socket");
			close(local_sk);
			return -1;
		}
	}

	pr_info("Proxy is connected to Cache through fd %d\n", remote_sk);

	if (background) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			return -1;
		}
	}

	// TODO - local_sk and remote_sk send as args.
	accept_image_connections();
	pr_info("Finished image proxy.");
	return 0;
}
