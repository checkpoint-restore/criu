#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

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

void parallel_restore_bo_add(int dmabuf_fd, int gpu_id, uint64_t size, uint64_t offset,
			     parallel_restore_cmd *restore_cmd)
{
	parallel_restore_entry *restore_entry = &restore_cmd->entries[restore_cmd->cmd_head.entry_num];
	restore_entry->gpu_id = gpu_id;
	restore_entry->write_id = restore_cmd->cmd_head.fd_write_num;
	restore_entry->write_offset = 0;
	restore_entry->read_offset = offset;
	restore_entry->size = size;

	restore_cmd->fds_write[restore_cmd->cmd_head.fd_write_num] = dmabuf_fd;

	restore_cmd->cmd_head.entry_num += 1;
	restore_cmd->cmd_head.fd_write_num += 1;
}

void parallel_restore_gpu_id_add(int gpu_id, int minor, parallel_restore_cmd *restore_cmd)
{
	restore_cmd->gpu_ids[restore_cmd->cmd_head.gpu_num] = (parallel_gpu_info){ gpu_id, minor };
	restore_cmd->cmd_head.gpu_num += 1;
}

static int send_metadata(int sock_fd, parallel_restore_cmd *restore_cmd)
{
	if (send(sock_fd, &restore_cmd->cmd_head, sizeof(parallel_restore_cmd_head), 0) < 0) {
		pr_perror("Send parallel restore command head fail");
		return -1;
	}
	return 0;
}

static int send_gpu_ids(int sock_fd, parallel_restore_cmd *restore_cmd)
{
	if (send(sock_fd, restore_cmd->gpu_ids, restore_cmd->cmd_head.gpu_num * sizeof(parallel_gpu_info), 0) < 0) {
		pr_perror("Send GPU ids of parallel restore command fail");
		return -1;
	}
	return 0;
}

static int send_cmds(int sock_fd, parallel_restore_cmd *restore_cmd)
{
	if (send(sock_fd, restore_cmd->entries, restore_cmd->cmd_head.entry_num * sizeof(parallel_restore_entry), 0) < 0) {
		pr_perror("Send parallel restore command fail");
		return -1;
	}
	return 0;
}

static int send_dmabuf_fds(int sock_fd, parallel_restore_cmd *restore_cmd)
{
	if (send_fds(sock_fd, NULL, 0, restore_cmd->fds_write, restore_cmd->cmd_head.fd_write_num, 0, 0) < 0) {
		pr_perror("Send dmabuf fds fail");
		return -1;
	}
	return 0;
}

int send_parallel_restore_cmd(parallel_restore_cmd *restore_cmd)
{
	int sock_fd;
	int ret = 0;

	sock_fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock_fd < 0) {
		pr_perror("Socket creation failed");
		return -1;
	}

	ret = connect(sock_fd, (struct sockaddr *)&parallel_socket_addr, parallel_socket_addr_len);
	if (ret < 0) {
		pr_perror("Connect failed");
		goto err;
	}

	ret = send_metadata(sock_fd, restore_cmd);
	if (ret) {
		goto err;
	}

	ret = send_gpu_ids(sock_fd, restore_cmd);
	if (ret) {
		goto err;
	}

	ret = send_cmds(sock_fd, restore_cmd);
	if (ret) {
		goto err;
	}

	ret = send_dmabuf_fds(sock_fd, restore_cmd);

err:
	close(sock_fd);
	return ret;
}

int init_parallel_restore_cmd(int num, int id, int gpu_num, parallel_restore_cmd *restore_cmd)
{
	restore_cmd->cmd_head.id = id;
	restore_cmd->cmd_head.fd_write_num = 0;
	restore_cmd->cmd_head.entry_num = 0;
	restore_cmd->cmd_head.gpu_num = 0;

	restore_cmd->gpu_ids = xzalloc(gpu_num * sizeof(parallel_gpu_info));
	if (!restore_cmd->gpu_ids)
		return -ENOMEM;
	restore_cmd->fds_write = xzalloc(num * sizeof(int));
	if (!restore_cmd->fds_write)
		return -ENOMEM;
	restore_cmd->entries = xzalloc(num * sizeof(parallel_restore_entry));
	if (!restore_cmd->entries)
		return -ENOMEM;
	return 0;
}

void free_parallel_restore_cmd(parallel_restore_cmd *restore_cmd)
{
	if (restore_cmd->gpu_ids)
		xfree(restore_cmd->gpu_ids);
	if (restore_cmd->fds_write)
		xfree(restore_cmd->fds_write);
	if (restore_cmd->entries)
		xfree(restore_cmd->entries);
}

static int init_parallel_restore_cmd_by_head(parallel_restore_cmd *restore_cmd)
{
	restore_cmd->gpu_ids = xzalloc(restore_cmd->cmd_head.gpu_num * sizeof(parallel_gpu_info));
	if (!restore_cmd->gpu_ids)
		return -ENOMEM;
	restore_cmd->fds_write = xzalloc(restore_cmd->cmd_head.fd_write_num * sizeof(int));
	if (!restore_cmd->fds_write)
		return -ENOMEM;
	restore_cmd->entries = xzalloc(restore_cmd->cmd_head.entry_num * sizeof(parallel_restore_entry));
	if (!restore_cmd->entries)
		return -ENOMEM;
	return 0;
}

static int check_quit_cmd(parallel_restore_cmd *restore_cmd)
{
	return restore_cmd->cmd_head.fd_write_num == 0;
}

static int recv_metadata(int client_fd, parallel_restore_cmd *restore_cmd)
{
	if (recv(client_fd, &restore_cmd->cmd_head, sizeof(parallel_restore_cmd_head), 0) < 0) {
		pr_perror("Recv parallel restore command head fail");
		return -1;
	}
	return 0;
}

static int recv_cmds(int client_fd, parallel_restore_cmd *restore_cmd)
{
	if (recv(client_fd, restore_cmd->entries, restore_cmd->cmd_head.entry_num * sizeof(parallel_restore_entry), 0) < 0) {
		pr_perror("Recv parallel restore command fail");
		return -1;
	}
	return 0;
}

static int recv_gpu_ids(int sock_fd, parallel_restore_cmd *restore_cmd)
{
	if (recv(sock_fd, restore_cmd->gpu_ids, restore_cmd->cmd_head.gpu_num * sizeof(parallel_gpu_info), 0) < 0) {
		pr_perror("Send GPU ids of parallel restore command fail");
		return -1;
	}
	return 0;
}

static int recv_dmabuf_fds(int client_fd, parallel_restore_cmd *restore_cmd)
{
	if (recv_fds(client_fd, restore_cmd->fds_write, restore_cmd->cmd_head.fd_write_num, 0, 0) < 0) {
		pr_perror("Recv dmabuf fds fail");
		return -1;
	}
	return 0;
}

int recv_parallel_restore_cmd(parallel_restore_cmd *restore_cmd)
{
	int sock_fd, client_fd;
	int ret = 0;

	sock_fd = fdstore_get(parallel_socket_id);
	if (sock_fd < 0)
		return -1;

	client_fd = accept(sock_fd, NULL, NULL);
	if (client_fd < 0) {
		ret = client_fd;
		goto err_accept;
	}

	ret = recv_metadata(client_fd, restore_cmd);
	if (ret) {
		goto err;
	}

	// Return 1 to quit
	if (check_quit_cmd(restore_cmd)) {
		ret = 1;
		goto err;
	}

	ret = init_parallel_restore_cmd_by_head(restore_cmd);
	if (ret) {
		goto err;
	}

	ret = recv_gpu_ids(client_fd, restore_cmd);
	if (ret) {
		goto err;
	}

	ret = recv_cmds(client_fd, restore_cmd);
	if (ret) {
		goto err;
	}

	ret = recv_dmabuf_fds(client_fd, restore_cmd);

err:
	close(client_fd);
err_accept:
	close(sock_fd);
	return ret;
}

int close_parallel_restore_server(void)
{
	int sock_fd;
	int ret = 0;
	parallel_restore_cmd_head cmd_head;

	sock_fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock_fd < 0) {
		pr_perror("Socket creation failed");
		return -1;
	}

	ret = connect(sock_fd, (struct sockaddr *)&parallel_socket_addr, parallel_socket_addr_len);
	if (ret < 0) {
		pr_perror("Connect failed");
		goto err;
	}

	memset(&cmd_head, 0, sizeof(parallel_restore_cmd_head));
	if (send(sock_fd, &cmd_head, sizeof(parallel_restore_cmd_head), 0) < 0) {
		pr_perror("Send parallel restore command head fail");
		return -1;
	}

err:
	close(sock_fd);
	return ret;
}