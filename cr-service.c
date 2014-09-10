#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "crtools.h"
#include "cr_options.h"
#include "util.h"
#include "log.h"
#include "pstree.h"
#include "cr-service.h"
#include "cr-service-const.h"
#include "sd-daemon.h"
#include "page-xfer.h"
#include "net.h"
#include "mount.h"
#include "cgroup.h"

unsigned int service_sk_ino = -1;

static int recv_criu_msg(int socket_fd, CriuReq **msg)
{
	unsigned char buf[CR_MAX_MSG_SIZE];
	int len;

	len = read(socket_fd, buf, CR_MAX_MSG_SIZE);
	if (len == -1) {
		pr_perror("Can't read request");
		return -1;
	}

	if (len == 0) {
		pr_info("Client exited unexpectedly\n");
		errno = ECONNRESET;
		return -1;
	}

	*msg = criu_req__unpack(NULL, len, buf);
	if (!*msg) {
		pr_perror("Failed unpacking request");
		return -1;
	}

	return 0;
}

static int send_criu_msg(int socket_fd, CriuResp *msg)
{
	unsigned char buf[CR_MAX_MSG_SIZE];
	int len;

	len = criu_resp__get_packed_size(msg);

	if (criu_resp__pack(msg, buf) != len) {
		pr_perror("Failed packing response");
		return -1;
	}

	if (write(socket_fd, buf, len)  == -1) {
		pr_perror("Can't send response");
		return -1;
	}

	return 0;
}

static void send_criu_err(int sk, char *msg)
{
	CriuResp resp = CRIU_RESP__INIT;

	pr_perror("RPC error: %s", msg);

	resp.type = CRIU_REQ_TYPE__EMPTY;
	resp.success = false;
	/* XXX -- add optional error code to CriuResp */

	send_criu_msg(sk, &resp);
}

int send_criu_dump_resp(int socket_fd, bool success, bool restored)
{
	CriuResp msg = CRIU_RESP__INIT;
	CriuDumpResp resp = CRIU_DUMP_RESP__INIT;

	msg.type = CRIU_REQ_TYPE__DUMP;
	msg.success = success;
	msg.dump = &resp;

	resp.has_restored = true;
	resp.restored = restored;

	return send_criu_msg(socket_fd, &msg);
}

static int send_criu_pre_dump_resp(int socket_fd, bool success)
{
	CriuResp msg = CRIU_RESP__INIT;

	msg.type = CRIU_REQ_TYPE__PRE_DUMP;
	msg.success = success;

	return send_criu_msg(socket_fd, &msg);
}

int send_criu_restore_resp(int socket_fd, bool success, int pid)
{
	CriuResp msg = CRIU_RESP__INIT;
	CriuRestoreResp resp = CRIU_RESTORE_RESP__INIT;

	msg.type = CRIU_REQ_TYPE__RESTORE;
	msg.success = success;
	msg.restore = &resp;

	resp.pid = pid;

	return send_criu_msg(socket_fd, &msg);
}

int send_criu_rpc_script(char *script, int fd)
{
	int ret;
	CriuResp msg = CRIU_RESP__INIT;
	CriuReq *req;
	CriuNotify cn = CRIU_NOTIFY__INIT;

	msg.type = CRIU_REQ_TYPE__NOTIFY;
	msg.success = true;
	msg.notify = &cn;
	cn.script = script;

	if (!strcmp(script, "setup-namespaces")) {
		/*
		 * FIXME pid is required only once on
		 * restore. Need some more sane way of
		 * checking this.
		 */
		cn.has_pid = true;
		cn.pid = root_item->pid.real;
	}

	ret = send_criu_msg(fd, &msg);
	if (ret < 0)
		return ret;

	ret = recv_criu_msg(fd, &req);
	if (ret < 0)
		return ret;

	if (req->type != CRIU_REQ_TYPE__NOTIFY || !req->notify_success) {
		pr_err("RPC client reported script error\n");
		return -1;
	}

	criu_req__free_unpacked(req, NULL);
	return 0;
}

static int setup_opts_from_req(int sk, CriuOpts *req)
{
	struct ucred ids;
	struct stat st;
	socklen_t ids_len = sizeof(struct ucred);
	char images_dir_path[PATH_MAX];
	char work_dir_path[PATH_MAX];
	int i;

	if (getsockopt(sk, SOL_SOCKET, SO_PEERCRED, &ids, &ids_len)) {
		pr_perror("Can't get socket options");
		return -1;
	}

	if (restrict_uid(ids.uid, ids.gid))
		return -1;

	if (fstat(sk, &st)) {
		pr_perror("Can't get socket stat");
		return -1;
	}

	BUG_ON(st.st_ino == -1);
	service_sk_ino = st.st_ino;

	/* open images_dir */
	sprintf(images_dir_path, "/proc/%d/fd/%d", ids.pid, req->images_dir_fd);

	if (req->parent_img)
		opts.img_parent = req->parent_img;

	if (open_image_dir(images_dir_path) < 0) {
		pr_perror("Can't open images directory");
		return -1;
	}

	/* chdir to work dir */
	if (req->has_work_dir_fd)
		sprintf(work_dir_path, "/proc/%d/fd/%d", ids.pid, req->work_dir_fd);
	else
		strcpy(work_dir_path, images_dir_path);

	if (chdir(work_dir_path)) {
		pr_perror("Can't chdir to work_dir");
		return -1;
	}

	/* initiate log file in work dir */
	if (req->log_file) {
		if (strchr(req->log_file, '/')) {
			pr_perror("No subdirs are allowed in log_file name");
			return -1;
		}

		opts.output = req->log_file;
	} else
		opts.output = DEFAULT_LOG_FILENAME;

	log_set_loglevel(req->log_level);
	if (log_init(opts.output) == -1) {
		pr_perror("Can't initiate log");
		return -1;
	}

	/* checking flags from client */
	if (req->has_leave_running && req->leave_running)
		opts.final_state = TASK_ALIVE;

	if (!req->has_pid) {
		req->has_pid = true;
		req->pid = ids.pid;
	}

	if (req->has_ext_unix_sk)
		opts.ext_unix_sk = req->ext_unix_sk;

	if (req->root)
		opts.root = req->root;

	if (req->has_rst_sibling) {
		if (!opts.swrk_restore) {
			pr_err("rst_sibling is not allowed in standalone service\n");
			return -1;
		}

		opts.restore_sibling = req->rst_sibling;
	}

	if (req->has_tcp_established)
		opts.tcp_established_ok = req->tcp_established;

	if (req->has_evasive_devices)
		opts.evasive_devices = req->evasive_devices;

	if (req->has_shell_job)
		opts.shell_job = req->shell_job;

	if (req->has_file_locks)
		opts.handle_file_locks = req->file_locks;

	if (req->has_track_mem)
		opts.track_mem = req->track_mem;

	if (req->has_link_remap)
		opts.link_remap_ok = req->link_remap;

	if (req->has_auto_dedup)
		opts.auto_dedup = req->auto_dedup;

	if (req->has_force_irmap)
		opts.force_irmap = req->force_irmap;

	if (req->n_exec_cmd > 0) {
		opts.exec_cmd = xmalloc((req->n_exec_cmd + 1) * sizeof(char *));
		memcpy(opts.exec_cmd, req->exec_cmd, req->n_exec_cmd * sizeof(char *));
		opts.exec_cmd[req->n_exec_cmd] = NULL;
	}

	if (req->ps) {
		opts.use_page_server = true;
		opts.addr = req->ps->address;
		opts.ps_port = htons((short)req->ps->port);
	}

	if (req->notify_scripts) {
		struct script *script;

		script = xmalloc(sizeof(struct script));
		if (script == NULL)
			return -1;

		script->path = SCRIPT_RPC_NOTIFY;
		script->arg = sk;
		list_add(&script->node, &opts.scripts);
	}

	for (i = 0; i < req->n_veths; i++) {
		if (veth_pair_add(req->veths[i]->if_in, req->veths[i]->if_out))
			return -1;
	}

	for (i = 0; i < req->n_ext_mnt; i++) {
		if (ext_mount_add(req->ext_mnt[i]->key, req->ext_mnt[i]->val))
			return -1;
	}

	for (i = 0; i < req->n_cg_root; i++) {
		if (new_cg_root_add(req->cg_root[i]->ctrl,
					req->cg_root[i]->path))
			return -1;
	}

	if (req->has_cpu_cap)
		opts.cpu_cap = req->cpu_cap;

	if (req->has_manage_cgroups)
		opts.manage_cgroups = req->manage_cgroups;

	return 0;
}

static int dump_using_req(int sk, CriuOpts *req)
{
	bool success = false;
	bool self_dump = !req->pid;

	if (setup_opts_from_req(sk, req))
		goto exit;

	/*
	 * FIXME -- cr_dump_tasks() may return code from custom
	 * scripts, that can be positive. However, right now we
	 * don't have ability to push scripts via RPC, so psitive
	 * ret values are impossible here.
	 */
	if (cr_dump_tasks(req->pid))
		goto exit;

	success = true;
exit:
	if (req->leave_running  || !self_dump || !success) {
		if (send_criu_dump_resp(sk, success, false) == -1) {
			pr_perror("Can't send response");
			success = false;
		}
	}

	return success ? 0 : 1;
}

static int restore_using_req(int sk, CriuOpts *req)
{
	bool success = false;

	/*
	 * We can't restore processes under arbitrary task yet.
	 * Thus for now we force the detached restore under the
	 * cr service task.
	 */

	opts.restore_detach = true;

	if (setup_opts_from_req(sk, req))
		goto exit;

	if (cr_restore_tasks())
		goto exit;

	success = true;
exit:
	if (send_criu_restore_resp(sk, success,
				   root_item ? root_item->pid.real : -1) == -1) {
		pr_perror("Can't send response");
		success = false;
	}

	if (success && opts.exec_cmd) {
		int logfd;

		logfd = log_get_fd();
		if (dup2(logfd, STDOUT_FILENO) == -1 || dup2(logfd, STDERR_FILENO) == -1) {
			pr_perror("Failed to redirect stdout and stderr to the logfile");
			return 1;
		}

		close_pid_proc();
		close(sk);

		execvp(opts.exec_cmd[0], opts.exec_cmd);
		pr_perror("Failed to exec cmd %s", opts.exec_cmd[0]);
		success = false;
	}

	return success ? 0 : 1;
}

static int check(int sk)
{
	CriuResp resp = CRIU_RESP__INIT;

	resp.type = CRIU_REQ_TYPE__CHECK;

	/* Check only minimal kernel support */
	opts.check_ms_kernel = true;

	if (!cr_check())
		resp.success = true;

	return send_criu_msg(sk, &resp);
}

static int pre_dump_using_req(int sk, CriuOpts *req)
{
	int pid, status;
	bool success = false;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (pid == 0) {
		int ret = 1;

		if (setup_opts_from_req(sk, req))
			goto cout;

		if (cr_pre_dump_tasks(req->pid))
			goto cout;

		ret = 0;
cout:
		exit(ret);
	}

	wait(&status);
	if (!WIFEXITED(status))
		goto out;
	if (WEXITSTATUS(status) != 0)
		goto out;

	success = true;
out:
	if (send_criu_pre_dump_resp(sk, success) == -1) {
		pr_perror("Can't send pre-dump resp");
		success = false;
	}

	return success ? 0 : -1;
}

static int pre_dump_loop(int sk, CriuReq *msg)
{
	int ret;

	do {
		ret = pre_dump_using_req(sk, msg->opts);
		if (ret < 0)
			return ret;

		criu_req__free_unpacked(msg, NULL);
		if (recv_criu_msg(sk, &msg) == -1) {
			pr_perror("Can't recv request");
			return -1;
		}
	} while (msg->type == CRIU_REQ_TYPE__PRE_DUMP);

	if (msg->type != CRIU_REQ_TYPE__DUMP) {
		send_criu_err(sk, "Bad req seq");
		return -1;
	}

	return dump_using_req(sk, msg->opts);
}

static int start_page_server_req(int sk, CriuOpts *req)
{
	int ret;
	bool success = false;
	CriuResp resp = CRIU_RESP__INIT;
	CriuPageServerInfo ps = CRIU_PAGE_SERVER_INFO__INIT;

	if (!req->ps) {
		pr_err("No page server info in message\n");
		goto out;
	}

	if (setup_opts_from_req(sk, req))
		goto out;

	pr_debug("Starting page server\n");

	ret = cr_page_server(true);
	if (ret > 0) {
		success = true;
		ps.has_pid = true;
		ps.pid = ret;
		resp.ps = &ps;
	}

	pr_debug("Page server started\n");
out:
	resp.type = CRIU_REQ_TYPE__PAGE_SERVER;
	resp.success = success;
	return send_criu_msg(sk, &resp);
}

int cr_service_work(int sk)
{
	CriuReq *msg = 0;

	if (recv_criu_msg(sk, &msg) == -1) {
		pr_perror("Can't recv request");
		goto err;
	}

	switch (msg->type) {
	case CRIU_REQ_TYPE__DUMP:
		return dump_using_req(sk, msg->opts);
	case CRIU_REQ_TYPE__RESTORE:
		return restore_using_req(sk, msg->opts);
	case CRIU_REQ_TYPE__CHECK:
		return check(sk);
	case CRIU_REQ_TYPE__PRE_DUMP:
		return pre_dump_loop(sk, msg);
	case CRIU_REQ_TYPE__PAGE_SERVER:
		return start_page_server_req(sk, msg->opts);

	default:
		send_criu_err(sk, "Invalid req");
		goto err;
	}

err:
	return -1;
}

static void reap_worker(int signo)
{
	int saved_errno;
	int status;
	pid_t pid;

	saved_errno = errno;

	/*
	 * As we block SIGCHLD, lets wait for every child that has
	 * already changed state.
	 */
	while (1) {
		pid = waitpid(-1, &status, WNOHANG);

		if (pid <= 0) {
			errno = saved_errno;
			return;
		}

		if (WIFEXITED(status))
			pr_info("Worker(pid %d) exited with %d\n",
				pid, WEXITSTATUS(status));
		else if (WIFSIGNALED(status))
			pr_info("Worker(pid %d) was killed by %d\n",
				pid, WTERMSIG(status));
	}
}

static int setup_sigchld_handler()
{
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGCHLD);
	action.sa_handler	= reap_worker;
	action.sa_flags		= SA_RESTART;

	if (sigaction(SIGCHLD, &action, NULL)) {
		pr_perror("Can't setup SIGCHLD handler");
		return -1;
	}

	return 0;
}

static int restore_sigchld_handler()
{
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGCHLD);
	action.sa_handler	= SIG_DFL;
	action.sa_flags		= SA_RESTART;

	if (sigaction(SIGCHLD, &action, NULL)) {
		pr_perror("Can't restore SIGCHLD handler");
		return -1;
	}

	return 0;
}

int cr_service(bool daemon_mode)
{
	int server_fd = -1, n;
	int child_pid;

	struct sockaddr_un client_addr;
	socklen_t client_addr_len;

	n = sd_listen_fds(0);
	if (n > 1) {
		pr_err("Too many file descriptors (%d) recieved", n);
		goto err;
	} else if (n == 1)
		server_fd = SD_LISTEN_FDS_START + 0;
	else {
		struct sockaddr_un server_addr;
		socklen_t server_addr_len;

		server_fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
		if (server_fd == -1) {
			pr_perror("Can't initialize service socket");
			goto err;
		}

		memset(&server_addr, 0, sizeof(server_addr));
		memset(&client_addr, 0, sizeof(client_addr));
		server_addr.sun_family = AF_LOCAL;

		if (opts.addr == NULL)
			opts.addr = CR_DEFAULT_SERVICE_ADDRESS;

		strcpy(server_addr.sun_path, opts.addr);

		server_addr_len = strlen(server_addr.sun_path)
				+ sizeof(server_addr.sun_family);
		client_addr_len = sizeof(client_addr);

		unlink(server_addr.sun_path);

		if (bind(server_fd, (struct sockaddr *) &server_addr,
						server_addr_len) == -1) {
			pr_perror("Can't bind");
			goto err;
		}

		pr_info("The service socket is bound to %s\n", server_addr.sun_path);

		/* change service socket permissions, so anyone can connect to it */
		if (chmod(server_addr.sun_path, 0666)) {
			pr_perror("Can't change permissions of the service socket");
			goto err;
		}

		if (listen(server_fd, 16) == -1) {
			pr_perror("Can't listen for socket connections");
			goto err;
		}
	}

	if (daemon_mode) {
		if (daemon(1, 0) == -1) {
			pr_perror("Can't run service server in the background");
			goto err;
		}
	}

	if (opts.pidfile) {
		if (write_pidfile(getpid()) == -1) {
			pr_perror("Can't write pidfile");
			goto err;
		}
	}

	if (setup_sigchld_handler())
		goto err;

	while (1) {
		int sk;

		pr_info("Waiting for connection...\n");

		sk = accept(server_fd, &client_addr, &client_addr_len);
		if (sk == -1) {
			pr_perror("Can't accept connection");
			goto err;
		}

		pr_info("Connected.\n");
		child_pid = fork();
		if (child_pid == 0) {
			int ret;

			if (restore_sigchld_handler())
				exit(1);

			close(server_fd);
			init_opts();
			ret = cr_service_work(sk);
			close(sk);
			exit(ret != 0);
		}

		if (child_pid < 0)
			pr_perror("Can't fork a child");

		close(sk);
	}

err:
	close_safe(&server_fd);

	return 1;
}
