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
#include <arpa/inet.h>
#include <sched.h>

#include "version.h"
#include "crtools.h"
#include "cr_options.h"
#include "external.h"
#include "util.h"
#include "criu-log.h"
#include "cpu.h"
#include "files.h"
#include "pstree.h"
#include "cr-service.h"
#include "cr-service-const.h"
#include "page-xfer.h"
#include "net.h"
#include "mount.h"
#include "filesystems.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "action-scripts.h"
#include "sockets.h"
#include "irmap.h"
#include "kerndat.h"
#include "proc_parse.h"
#include "common/scm.h"
#include "uffd.h"

#include "setproctitle.h"

#include "cr-errno.h"
#include "namespaces.h"

unsigned int service_sk_ino = -1;

static int recv_criu_msg(int socket_fd, CriuReq **req)
{
	unsigned char *buf;
	int len;

	len = recv(socket_fd, NULL, 0, MSG_TRUNC | MSG_PEEK);
	if (len == -1) {
		pr_perror("Can't read request");
		return -1;
	}

	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	len = recv(socket_fd, buf, len, MSG_TRUNC);
	if (len == -1) {
		pr_perror("Can't read request");
		goto err;
	}

	if (len == 0) {
		pr_info("Client exited unexpectedly\n");
		errno = ECONNRESET;
		goto err;
	}

	*req = criu_req__unpack(NULL, len, buf);
	if (!*req) {
		pr_perror("Failed unpacking request");
		goto err;
	}

	xfree(buf);
	return 0;
err:
	xfree(buf);
	return -1;
}

static int send_criu_msg_with_fd(int socket_fd, CriuResp *msg, int fd)
{
	unsigned char *buf;
	int len, ret;

	len = criu_resp__get_packed_size(msg);

	buf = xmalloc(len);
	if (!buf)
		return -ENOMEM;

	if (criu_resp__pack(msg, buf) != len) {
		pr_perror("Failed packing response");
		goto err;
	}

	if (fd >= 0) {
		ret = send_fds(socket_fd, NULL, 0, &fd, 1, buf, len);
	} else
		ret = write(socket_fd, buf, len);
	if (ret < 0) {
		pr_perror("Can't send response");
		goto err;
	}

	xfree(buf);
	return 0;
err:
	xfree(buf);
	return -1;
}

static int send_criu_msg(int socket_fd, CriuResp *msg)
{
	return send_criu_msg_with_fd(socket_fd, msg, -1);
}

static void set_resp_err(CriuResp *resp)
{
	resp->cr_errno = get_cr_errno();
	resp->has_cr_errno = resp->cr_errno ? true : false;
	resp->cr_errmsg = log_first_err();
}

static void send_criu_err(int sk, char *msg)
{
	CriuResp resp = CRIU_RESP__INIT;

	pr_perror("RPC error: %s", msg);

	resp.type = CRIU_REQ_TYPE__EMPTY;
	resp.success = false;
	set_resp_err(&resp);

	send_criu_msg(sk, &resp);
}

int send_criu_dump_resp(int socket_fd, bool success, bool restored)
{
	CriuResp msg = CRIU_RESP__INIT;
	CriuDumpResp resp = CRIU_DUMP_RESP__INIT;

	msg.type = CRIU_REQ_TYPE__DUMP;
	msg.success = success;
	set_resp_err(&msg);
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
	set_resp_err(&msg);

	return send_criu_msg(socket_fd, &msg);
}

int send_criu_restore_resp(int socket_fd, bool success, int pid)
{
	CriuResp msg = CRIU_RESP__INIT;
	CriuRestoreResp resp = CRIU_RESTORE_RESP__INIT;

	msg.type = CRIU_REQ_TYPE__RESTORE;
	msg.success = success;
	set_resp_err(&msg);
	msg.restore = &resp;

	resp.pid = pid;

	return send_criu_msg(socket_fd, &msg);
}

int send_criu_rpc_script(enum script_actions act, char *name, int sk, int fd)
{
	int ret;
	CriuResp msg = CRIU_RESP__INIT;
	CriuReq *req;
	CriuNotify cn = CRIU_NOTIFY__INIT;

	msg.type = CRIU_REQ_TYPE__NOTIFY;
	msg.success = true;
	msg.notify = &cn;
	cn.script = name;

	switch (act) {
	case ACT_SETUP_NS:
	case ACT_POST_RESTORE:
		/*
		 * FIXME pid is required only once on
		 * restore. Need some more sane way of
		 * checking this.
		 */
		cn.has_pid = true;
		cn.pid = root_item->pid->real;
		break;
	default:
		break;
	}

	ret = send_criu_msg_with_fd(sk, &msg, fd);
	if (ret < 0)
		return ret;

	ret = recv_criu_msg(sk, &req);
	if (ret < 0)
		return ret;

	if (req->type != CRIU_REQ_TYPE__NOTIFY || !req->notify_success) {
		pr_err("RPC client reported script error\n");
		return -1;
	}

	criu_req__free_unpacked(req, NULL);
	return 0;
}

static char images_dir[PATH_MAX];

static int setup_opts_from_req(int sk, CriuOpts *req)
{
	struct ucred ids;
	struct stat st;
	socklen_t ids_len = sizeof(struct ucred);
	char images_dir_path[PATH_MAX];
	char work_dir_path[PATH_MAX];
	char status_fd[PATH_MAX];
	bool output_changed_by_rpc_conf = false;
	bool work_changed_by_rpc_conf = false;
	bool imgs_changed_by_rpc_conf = false;
	int i;
	bool dummy = false;

	if (getsockopt(sk, SOL_SOCKET, SO_PEERCRED, &ids, &ids_len)) {
		pr_perror("Can't get socket options");
		goto err;
	}

	if (fstat(sk, &st)) {
		pr_perror("Can't get socket stat");
		goto err;
	}

	BUG_ON(st.st_ino == -1);
	service_sk_ino = st.st_ino;

	/*
	 * Evaluate an additional configuration file if specified.
	 * This needs to happen twice, because it is needed early to detect
	 * things like work_dir, imgs_dir and logfile. The second parsing
	 * of the optional RPC configuration file happens at the end and
	 * overwrites all options set via RPC.
	 */
	if (req->config_file) {
		char *tmp_output = opts.output;
		char *tmp_work = opts.work_dir;
		char *tmp_imgs = opts.imgs_dir;

		opts.output = NULL;
		opts.work_dir = NULL;
		opts.imgs_dir = NULL;

		rpc_cfg_file = req->config_file;
		i = parse_options(0, NULL, &dummy, &dummy, PARSING_RPC_CONF);
		if (i) {
			xfree(tmp_output);
			xfree(tmp_work);
			xfree(tmp_imgs);
			goto err;
		}
		/* If this is non-NULL, the RPC configuration file had a value, use it.*/
		if (opts.output)
			output_changed_by_rpc_conf = true;
		/* If this is NULL, use the old value if it was set. */
		if (!opts.output && tmp_output) {
			opts.output = tmp_output;
			tmp_output = NULL;
		}

		if (opts.work_dir)
			work_changed_by_rpc_conf = true;
		if (!opts.work_dir && tmp_work) {
			opts.work_dir = tmp_work;
			tmp_work = NULL;
		}

		if (opts.imgs_dir)
			imgs_changed_by_rpc_conf = true;
		/*
		 * As the images directory is a required RPC setting, it is not
		 * necessary to use the value from other configuration files.
		 * Either it is set in the RPC configuration file or it is set
		 * via RPC.
		 */
		xfree(tmp_output);
		xfree(tmp_work);
		xfree(tmp_imgs);
	}

	/*
	 * open images_dir - images_dir_fd is a required RPC parameter
	 *
	 * This assumes that if opts.imgs_dir is set we have a value
	 * from the configuration file parser. The test to see that
	 * imgs_changed_by_rpc_conf is true is used to make sure the value
	 * is from the RPC configuration file.
	 * The idea is that only the RPC configuration file is able to
	 * overwrite RPC settings:
	 *  * apply_config(global_conf)
	 *  * apply_config(user_conf)
	 *  * apply_config(environment variable)
	 *  * apply_rpc_options()
	 *  * apply_config(rpc_conf)
	 */
	if (imgs_changed_by_rpc_conf)
		strncpy(images_dir_path, opts.imgs_dir, PATH_MAX - 1);
	else
		sprintf(images_dir_path, "/proc/%d/fd/%d", ids.pid, req->images_dir_fd);

	if (req->parent_img)
		SET_CHAR_OPTS(img_parent, req->parent_img);

	if (open_image_dir(images_dir_path) < 0) {
		pr_perror("Can't open images directory");
		goto err;
	}

	/* get full path to images_dir to use in process title */
	if (readlink(images_dir_path, images_dir, PATH_MAX) == -1) {
		pr_perror("Can't readlink %s", images_dir_path);
		goto err;
	}

	/* chdir to work dir */
	if (work_changed_by_rpc_conf)
		/* Use the value from the RPC configuration file first. */
		strncpy(work_dir_path, opts.work_dir, PATH_MAX - 1);
	else if (req->has_work_dir_fd)
		/* Use the value set via RPC. */
		sprintf(work_dir_path, "/proc/%d/fd/%d", ids.pid, req->work_dir_fd);
	else if (opts.work_dir)
		/* Use the value from one of the other configuration files. */
		strncpy(work_dir_path, opts.work_dir, PATH_MAX - 1);
	else
		/* Use the images directory a work directory. */
		strcpy(work_dir_path, images_dir_path);

	if (chdir(work_dir_path)) {
		pr_perror("Can't chdir to work_dir");
		goto err;
	}

	/* initiate log file in work dir */
	if (req->log_file && !output_changed_by_rpc_conf) {
		/*
		 * If RPC sets a log file and if there nothing from the
		 * RPC configuration file, use the RPC value.
		 */
		if (strchr(req->log_file, '/')) {
			pr_perror("No subdirs are allowed in log_file name");
			goto err;
		}

		SET_CHAR_OPTS(output, req->log_file);
	} else if (!opts.output) {
		SET_CHAR_OPTS(output, DEFAULT_LOG_FILENAME);
	}

	/* This is needed later to correctly set the log_level */
	opts.log_level = req->log_level;
	log_set_loglevel(req->log_level);
	if (log_init(opts.output) == -1) {
		pr_perror("Can't initiate log");
		goto err;
	}

	if (req->config_file) {
		pr_debug("Overwriting RPC settings with values from %s\n", req->config_file);
	}

	if (kerndat_init())
		return 1;

	if (log_keep_err()) {
		pr_perror("Can't tune log");
		goto err;
	}

	/* checking flags from client */
	if (req->has_leave_running && req->leave_running)
		opts.final_state = TASK_ALIVE;

	if (!req->has_pid) {
		req->has_pid = true;
		req->pid = ids.pid;
	}

	if (req->has_ext_unix_sk) {
		opts.ext_unix_sk = req->ext_unix_sk;
		for (i = 0; i < req->n_unix_sk_ino; i++) {
			if (unix_sk_id_add((unsigned int)req->unix_sk_ino[i]->inode) < 0)
				goto err;
		}
	}

	if (req->root)
		SET_CHAR_OPTS(root, req->root);

	if (req->has_rst_sibling) {
		if (!opts.swrk_restore) {
			pr_err("rst_sibling is not allowed in standalone service\n");
			goto err;
		}

		opts.restore_sibling = req->rst_sibling;
	}

	if (req->has_tcp_established)
		opts.tcp_established_ok = req->tcp_established;

	if (req->has_tcp_skip_in_flight)
		opts.tcp_skip_in_flight = req->tcp_skip_in_flight;

	if (req->has_tcp_close)
		opts.tcp_close = req->tcp_close;

	if (req->has_weak_sysctls)
		opts.weak_sysctls = req->weak_sysctls;

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

	if (req->has_lazy_pages) {
		opts.lazy_pages = req->lazy_pages;
	}

	if (req->ps) {
		opts.port = (short)req->ps->port;

		if (!opts.lazy_pages) {
			opts.use_page_server = true;
			if (req->ps->address)
				SET_CHAR_OPTS(addr, req->ps->address);
			else
				opts.addr = NULL;

			if (req->ps->has_fd) {
				if (!opts.swrk_restore)
					goto err;

				opts.ps_socket = req->ps->fd;
			}
		}
	}

	if (req->notify_scripts && add_rpc_notify(sk))
		goto err;

	for (i = 0; i < req->n_veths; i++) {
		if (veth_pair_add(req->veths[i]->if_in, req->veths[i]->if_out))
			goto err;
	}

	for (i = 0; i < req->n_ext_mnt; i++) {
		if (ext_mount_add(req->ext_mnt[i]->key, req->ext_mnt[i]->val))
			goto err;
	}

	for (i = 0; i < req->n_join_ns; i++) {
		if (join_ns_add(req->join_ns[i]->ns, req->join_ns[i]->ns_file, req->join_ns[i]->extra_opt))
			goto err;
	}

	if (req->n_inherit_fd && !opts.swrk_restore) {
		pr_err("inherit_fd is not allowed in standalone service\n");
		goto err;
	}
	for (i = 0; i < req->n_inherit_fd; i++) {
		if (inherit_fd_add(req->inherit_fd[i]->fd, req->inherit_fd[i]->key))
			goto err;
	}

	for (i = 0; i < req->n_external; i++)
		if (add_external(req->external[i]))
			goto err;

	for (i = 0; i < req->n_cg_root; i++) {
		if (new_cg_root_add(req->cg_root[i]->ctrl,
					req->cg_root[i]->path))
			goto err;
	}

	for (i = 0; i < req->n_enable_fs; i++) {
		if (!add_fsname_auto(req->enable_fs[i]))
			goto err;
	}

	for (i = 0; i < req->n_skip_mnt; i++) {
		if (!add_skip_mount(req->skip_mnt[i]))
			goto err;
	}

	if (req->has_cpu_cap) {
		opts.cpu_cap = req->cpu_cap;
		opts.cpu_cap |= CPU_CAP_IMAGE;
	}

	/*
	 * FIXME: For backward compatibility we setup
	 * soft mode here, need to enhance to support
	 * other modes as well via separate option
	 * probably.
	 */
	if (req->has_manage_cgroups)
		opts.manage_cgroups = req->manage_cgroups ? CG_MODE_SOFT : CG_MODE_IGNORE;

	/* Override the manage_cgroup if mode is set explicitly */
	if (req->has_manage_cgroups_mode) {
		unsigned int mode;

		switch (req->manage_cgroups_mode) {
		case CRIU_CG_MODE__IGNORE:
			mode = CG_MODE_IGNORE;
			break;
		case CRIU_CG_MODE__CG_NONE:
			mode = CG_MODE_NONE;
			break;
		case CRIU_CG_MODE__PROPS:
			mode = CG_MODE_PROPS;
			break;
		case CRIU_CG_MODE__SOFT:
			mode = CG_MODE_SOFT;
			break;
		case CRIU_CG_MODE__FULL:
			mode = CG_MODE_FULL;
			break;
		case CRIU_CG_MODE__STRICT:
			mode = CG_MODE_STRICT;
			break;
		case CRIU_CG_MODE__DEFAULT:
			mode = CG_MODE_DEFAULT;
			break;
		default:
			goto err;
		}

		opts.manage_cgroups = mode;
	}

	if (req->freeze_cgroup)
		SET_CHAR_OPTS(freeze_cgroup, req->freeze_cgroup);

	if (req->lsm_profile) {
		opts.lsm_supplied = true;
		SET_CHAR_OPTS(lsm_profile, req->lsm_profile);
	}

	if (req->has_timeout)
		opts.timeout = req->timeout;

	if (req->cgroup_props)
		SET_CHAR_OPTS(cgroup_props, req->cgroup_props);

	if (req->cgroup_props_file)
		SET_CHAR_OPTS(cgroup_props_file, req->cgroup_props_file);

	for (i = 0; i < req->n_cgroup_dump_controller; i++) {
		if (!cgp_add_dump_controller(req->cgroup_dump_controller[i]))
			goto err;
	}

	if (req->tls_cacert)
		SET_CHAR_OPTS(tls_cacert, req->tls_cacert);
	if (req->tls_cacrl)
		SET_CHAR_OPTS(tls_cacrl, req->tls_cacrl);
	if (req->tls_cert)
		SET_CHAR_OPTS(tls_cert, req->tls_cert);
	if (req->tls_key)
		SET_CHAR_OPTS(tls_key, req->tls_key);
	if (req->tls)
		opts.tls = req->tls;
	if (req->tls_no_cn_verify)
		opts.tls_no_cn_verify = req->tls_no_cn_verify;

	if (req->has_auto_ext_mnt)
		opts.autodetect_ext_mounts = req->auto_ext_mnt;

	if (req->has_ext_sharing)
		opts.enable_external_sharing = req->ext_sharing;

	if (req->has_ext_masters)
		opts.enable_external_masters = req->ext_masters;

	if (req->has_ghost_limit)
		opts.ghost_limit = req->ghost_limit;

	if (req->has_empty_ns) {
		opts.empty_ns = req->empty_ns;
		if (req->empty_ns & ~(CLONE_NEWNET))
			goto err;
	}

	if (req->n_irmap_scan_paths) {
		for (i = 0; i < req->n_irmap_scan_paths; i++) {
			if (irmap_scan_path_add(req->irmap_scan_paths[i]))
				goto err;
		}
	}

	if (req->has_status_fd) {
		sprintf(status_fd, "/proc/%d/fd/%d", ids.pid, req->status_fd);
		opts.status_fd = open(status_fd, O_WRONLY);
		if (opts.status_fd < 0)
			goto err;
	}

	if (req->orphan_pts_master)
		opts.orphan_pts_master = true;


	/* Evaluate additional configuration file a second time to overwrite
	 * all RPC settings. */
	if (req->config_file) {
		rpc_cfg_file = req->config_file;
		i = parse_options(0, NULL, &dummy, &dummy, PARSING_RPC_CONF);
		if (i)
			goto err;
	}

	log_set_loglevel(opts.log_level);
	if (check_options())
		goto err;

	return 0;

err:
	set_cr_errno(EBADRQC);
	return -1;
}

static int dump_using_req(int sk, CriuOpts *req)
{
	bool success = false;
	bool self_dump = !req->pid;

	if (setup_opts_from_req(sk, req))
		goto exit;

	setproctitle("dump --rpc -t %d -D %s", req->pid, images_dir);

	/*
	 * FIXME -- cr_dump_tasks() may return code from custom
	 * scripts, that can be positive. However, right now we
	 * don't have ability to push scripts via RPC, so positive
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

	setproctitle("restore --rpc -D %s", images_dir);

	if (cr_restore_tasks())
		goto exit;

	success = true;
exit:
	if (send_criu_restore_resp(sk, success,
				   root_item ? root_item->pid->real : -1) == -1) {
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

static int check(int sk, CriuOpts *req)
{
	int pid, status;
	CriuResp resp = CRIU_RESP__INIT;

	resp.type = CRIU_REQ_TYPE__CHECK;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (pid == 0) {
		setproctitle("check --rpc");

		if (setup_opts_from_req(sk, req))
			exit(1);

		exit(!!cr_check());
	}
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait %d", pid);
		goto out;
	}
	if (status)
		goto out;

	resp.success = true;
out:
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

		setproctitle("pre-dump --rpc -t %d -D %s", req->pid, images_dir);

		if (cr_pre_dump_tasks(req->pid))
			goto cout;

		ret = 0;
cout:
		exit(ret);
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait %d", pid);
		goto out;
	}
	if (status != 0)
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

static int start_page_server_req(int sk, CriuOpts *req, bool daemon_mode)
{
	int ret = -1, pid, start_pipe[2];
	ssize_t count;
	bool success = false;
	CriuResp resp = CRIU_RESP__INIT;
	CriuPageServerInfo ps = CRIU_PAGE_SERVER_INFO__INIT;
	struct ps_info info;

	if (pipe(start_pipe)) {
		pr_perror("No start pipe");
		goto out;
	}

	pid = fork();
	if (pid == 0) {
		close(start_pipe[0]);

		if (setup_opts_from_req(sk, req))
			goto out_ch;

		setproctitle("page-server --rpc --address %s --port %hu", opts.addr, opts.port);

		pr_debug("Starting page server\n");

		pid = cr_page_server(daemon_mode, false, start_pipe[1]);
		if (pid < 0)
			goto out_ch;

		if (daemon_mode) {
			info.pid = pid;
			info.port = opts.port;

			count = write(start_pipe[1], &info, sizeof(info));
			if (count != sizeof(info))
				goto out_ch;
		}

		ret = 0;
out_ch:
		if (daemon_mode && ret < 0 && pid > 0)
			kill(pid, SIGKILL);
		close(start_pipe[1]);
		exit(ret);
	}

	close(start_pipe[1]);

	if (daemon_mode) {
		if (waitpid(pid, &ret, 0) != pid) {
			pr_perror("Unable to wait %d", pid);
			goto out;
		}
		if (WIFEXITED(ret)) {
			if (WEXITSTATUS(ret)) {
				pr_err("Child exited with an error\n");
				goto out;
			}
		} else {
			pr_err("Child wasn't terminated normally\n");
			goto out;
		}
	}

	count = read(start_pipe[0], &info, sizeof(info));
	close(start_pipe[0]);
	if (count != sizeof(info))
		goto out;

	ps.pid = info.pid;
	ps.has_port = true;
	ps.port = info.port;

	success = true;
	ps.has_pid = true;
	resp.ps = &ps;

	pr_debug("Page server started\n");
out:
	resp.type = CRIU_REQ_TYPE__PAGE_SERVER;
	resp.success = success;
	return send_criu_msg(sk, &resp);
}

static int chk_keepopen_req(CriuReq *msg)
{
	if (!msg->keep_open)
		return 0;

	/*
	 * Service may (well, it will) leave some
	 * resources leaked after processing e.g.
	 * dump or restore requests. Before we audit
	 * the code for this, let's first enable
	 * mreq RPCs for those requests we know do
	 * good work
	 */

	if (msg->type == CRIU_REQ_TYPE__PAGE_SERVER)
		/* This just fork()-s so no leaks */
		return 0;
	if (msg->type == CRIU_REQ_TYPE__PAGE_SERVER_CHLD)
		/* This just fork()-s so no leaks */
		return 0;
	else if (msg->type == CRIU_REQ_TYPE__CPUINFO_DUMP ||
		 msg->type == CRIU_REQ_TYPE__CPUINFO_CHECK)
		return 0;
	else if (msg->type == CRIU_REQ_TYPE__FEATURE_CHECK)
		return 0;
	else if (msg->type == CRIU_REQ_TYPE__VERSION)
		return 0;

	return -1;
}

/*
 * Return the version information, depending on the information
 * available in version.h
 */
static int handle_version(int sk, CriuReq * msg)
{
	CriuResp resp = CRIU_RESP__INIT;
	CriuVersion version = CRIU_VERSION__INIT;

	/* This assumes we will always have a major and minor version */
	version.major_number = CRIU_VERSION_MAJOR;
	version.minor_number = CRIU_VERSION_MINOR;
	if (strcmp(CRIU_GITID, "0")) {
		version.gitid = CRIU_GITID;
	}
#ifdef CRIU_VERSION_SUBLEVEL
	version.has_sublevel = 1;
	version.sublevel = CRIU_VERSION_SUBLEVEL;
#endif
#ifdef CRIU_VERSION_EXTRA
	version.has_extra = 1;
	version.extra = CRIU_VERSION_EXTRA;
#endif
#ifdef CRIU_VERSION_NAME
	/* This is not actually exported in version.h */
	version.name = CRIU_VERSION_NAME;
#endif
	resp.type = msg->type;
	resp.success = true;
	resp.version = &version;
	return send_criu_msg(sk, &resp);
}

/*
 * Generic function to handle CRIU_REQ_TYPE__FEATURE_CHECK.
 *
 * The function will have resp.success = true for most cases
 * and the actual result will be in resp.features.
 *
 * For each feature which has been requested in msg->features
 * the corresponding parameter will be set in resp.features.
 */
static int handle_feature_check(int sk, CriuReq * msg)
{
	CriuResp resp = CRIU_RESP__INIT;
	CriuFeatures feat = CRIU_FEATURES__INIT;
	int pid, status;
	int ret;

	/* enable setting of an optional message */
	feat.has_mem_track = 1;
	feat.mem_track = false;
	feat.has_lazy_pages = 1;
	feat.lazy_pages = false;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (pid == 0) {
		/* kerndat_init() is called from setup_opts_from_req() */
		if (setup_opts_from_req(sk, msg->opts))
			exit(1);

		setproctitle("feature-check --rpc");

		if ((msg->features->has_mem_track == 1) &&
		    (msg->features->mem_track == true))
			feat.mem_track = kdat.has_dirty_track;

		if ((msg->features->has_lazy_pages == 1) &&
		    (msg->features->lazy_pages == true))
			feat.lazy_pages = kdat.has_uffd && uffd_noncooperative();

		resp.features = &feat;
		resp.type = msg->type;
		/* The feature check is working, actual results are in resp.features */
		resp.success = true;

		/*
		 * If this point is reached the information about the features
		 * is transmitted from the forked CRIU process (here).
		 * If an error occurred earlier, the feature check response will be
		 * be send from the parent process.
		 */
		ret = send_criu_msg(sk, &resp);
		exit(!!ret);
	}
	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait %d", pid);
		goto out;
	}
	if (status != 0)
		goto out;

	/*
	 * The child process was not able to send an answer. Tell
	 * the RPC client that something did not work as expected.
	 */
out:
	resp.type = msg->type;
	resp.success = false;

	return send_criu_msg(sk, &resp);
}

static int handle_wait_pid(int sk, int pid)
{
	CriuResp resp = CRIU_RESP__INIT;
	bool success = false;
	int status;

	if (waitpid(pid, &status, 0) == -1) {
		resp.cr_errno = errno;
		pr_perror("Unable to wait %d", pid);
		goto out;
	}

	resp.status = status;
	resp.has_status = true;

	success = true;
out:
	resp.type = CRIU_REQ_TYPE__WAIT_PID;
	resp.success = success;

	return send_criu_msg(sk, &resp);
}

static int handle_cpuinfo(int sk, CriuReq *msg)
{
	CriuResp resp = CRIU_RESP__INIT;
	bool success = false;
	int pid, status;

	pid = fork();
	if (pid < 0) {
		pr_perror("Can't fork");
		goto out;
	}

	if (pid == 0) {
		int ret = 1;

		if (setup_opts_from_req(sk, msg->opts))
			goto cout;

		setproctitle("cpuinfo %s --rpc -D %s",
			     msg->type == CRIU_REQ_TYPE__CPUINFO_DUMP ?
			     "dump" : "check",
			     images_dir);

		if (msg->type == CRIU_REQ_TYPE__CPUINFO_DUMP)
			ret = cpuinfo_dump();
		else
			ret = cpuinfo_check();
cout:
		exit(ret);
	}

	if (waitpid(pid, &status, 0) != pid) {
		pr_perror("Unable to wait %d", pid);
		goto out;
	}
	if (!WIFEXITED(status))
		goto out;
	switch (WEXITSTATUS(status)) {
	case (-ENOTSUP & 0xff):
		resp.has_cr_errno = 1;
		/*
		 * Let's return the actual error code and
		 * not just (-ENOTSUP & 0xff)
		 */
		resp.cr_errno = ENOTSUP;
		break;
	case 0:
		success = true;
		break;
	default:
		break;
	}

out:
	resp.type = msg->type;
	resp.success = success;

	return send_criu_msg(sk, &resp);
}

int cr_service_work(int sk)
{
	int ret = -1;
	CriuReq *msg = 0;

more:
	if (recv_criu_msg(sk, &msg) != 0) {
		pr_perror("Can't recv request");
		goto err;
	}

	if (chk_keepopen_req(msg))
		goto err;

	switch (msg->type) {
	case CRIU_REQ_TYPE__DUMP:
		ret = dump_using_req(sk, msg->opts);
		break;
	case CRIU_REQ_TYPE__RESTORE:
		ret = restore_using_req(sk, msg->opts);
		break;
	case CRIU_REQ_TYPE__CHECK:
		ret = check(sk, msg->opts);
		break;
	case CRIU_REQ_TYPE__PRE_DUMP:
		ret = pre_dump_loop(sk, msg);
		break;
	case CRIU_REQ_TYPE__PAGE_SERVER:
		ret = start_page_server_req(sk, msg->opts, true);
		break;
	case CRIU_REQ_TYPE__PAGE_SERVER_CHLD:
		ret = start_page_server_req(sk, msg->opts, false);
		break;
	case CRIU_REQ_TYPE__WAIT_PID:
		ret =  handle_wait_pid(sk, msg->pid);
		break;
	case CRIU_REQ_TYPE__CPUINFO_DUMP:
	case CRIU_REQ_TYPE__CPUINFO_CHECK:
		ret = handle_cpuinfo(sk, msg);
		break;
	case CRIU_REQ_TYPE__FEATURE_CHECK:
		ret = handle_feature_check(sk, msg);
		break;
	case CRIU_REQ_TYPE__VERSION:
		ret = handle_version(sk, msg);
		break;

	default:
		send_criu_err(sk, "Invalid req");
		break;
	}

	if (!ret && msg->keep_open) {
		criu_req__free_unpacked(msg, NULL);
		ret = -1;
		goto more;
	}

err:
	return ret;
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
			pr_info("Worker(pid %d) was killed by %d: %s\n", pid,
				WTERMSIG(status), strsignal(WTERMSIG(status)));
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
	int server_fd = -1;
	int child_pid;

	struct sockaddr_un client_addr;
	socklen_t client_addr_len;

	{
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

		if (opts.addr == NULL) {
			pr_warn("Binding to local dir address!\n");
			SET_CHAR_OPTS(addr, CR_DEFAULT_SERVICE_ADDRESS);
		}

		strncpy(server_addr.sun_path, opts.addr,
				sizeof(server_addr.sun_path) - 1);

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

	if (close_status_fd())
		goto err;

	while (1) {
		int sk;

		pr_info("Waiting for connection...\n");

		sk = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
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
