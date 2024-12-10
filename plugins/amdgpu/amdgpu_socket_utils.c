#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "amdgpu_socket_utils.h"
#include "criu-log.h"
#include "common/scm.h"
#include "fdstore.h"
#include "util-pie.h"
#include "util.h"

int parallel_socket_addr_len;
struct sockaddr_un parallel_socket_addr;
int parallel_socket_id = 0;

static void amdgpu_socket_name_gen(struct sockaddr_un *addr, int *len)
{
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, UNIX_PATH_MAX, "x/criu-amdgpu-parallel-%s", criu_run_id);
	*len = SUN_LEN(addr);
	*addr->sun_path = '\0';
}

int install_parallel_sock(void)
{
	int ret = 0;
	int sock_fd;

	sock_fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock_fd < 0) {
		pr_perror("socket creation failed");
		return -1;
	}

	amdgpu_socket_name_gen(&parallel_socket_addr, &parallel_socket_addr_len);
	ret = bind(sock_fd, (struct sockaddr *)&parallel_socket_addr, parallel_socket_addr_len);
	if (ret < 0) {
		pr_perror("bind failed");
		goto err;
	}

	ret = listen(sock_fd, SOMAXCONN);
	if (ret < 0) {
		pr_perror("listen failed");
		goto err;
	}

	parallel_socket_id = fdstore_add(sock_fd);
	if (parallel_socket_id < 0) {
		ret = -1;
		goto err;
	}
err:
	close(sock_fd);
	return ret;
}