#include "version.h"
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include "criu.h"
#include "rpc.pb-c.h"
#include "cr-service-const.h"

const char *criu_lib_version = CRIU_VERSION;

static char *service_address = CR_DEFAULT_SERVICE_ADDRESS;
static CriuOpts *opts;
static int (*notify)(char *action, criu_notify_arg_t na);
static int saved_errno;

void criu_set_service_address(char *path)
{
	if (path)
		service_address = path;
	else
		service_address = CR_DEFAULT_SERVICE_ADDRESS;
}

int criu_init_opts(void)
{
	if (opts) {
		notify = NULL;
		criu_opts__free_unpacked(opts, NULL);
	}

	opts = malloc(sizeof(CriuOpts));
	if (opts == NULL) {
		perror("Can't allocate memory for criu opts");
		return -1;
	}

	criu_opts__init(opts);
	return 0;
}

void criu_set_notify_cb(int (*cb)(char *action, criu_notify_arg_t na))
{
	notify = cb;
	opts->has_notify_scripts = true;
	opts->notify_scripts = true;
}

int criu_notify_pid(criu_notify_arg_t na)
{
	return na->has_pid ? na->pid : 0;
}

void criu_set_pid(int pid)
{
	opts->has_pid	= true;
	opts->pid	= pid;
}

void criu_set_images_dir_fd(int fd)
{
	opts->images_dir_fd = fd;
}

void criu_set_parent_images(char *path)
{
	opts->parent_img = strdup(path);
}

void criu_set_track_mem(bool track_mem)
{
	opts->has_track_mem = true;
	opts->track_mem = track_mem;
}

void criu_set_auto_dedup(bool auto_dedup)
{
	opts->has_auto_dedup = true;
	opts->auto_dedup = auto_dedup;
}

void criu_set_force_irmap(bool force_irmap)
{
	opts->has_force_irmap = true;
	opts->force_irmap = force_irmap;
}

void criu_set_link_remap(bool link_remap)
{
	opts->has_link_remap = true;
	opts->link_remap = link_remap;
}

void criu_set_work_dir_fd(int fd)
{
	opts->has_work_dir_fd	= true;
	opts->work_dir_fd	= fd;
}

void criu_set_leave_running(bool leave_running)
{
	opts->has_leave_running	= true;
	opts->leave_running	= leave_running;
}

void criu_set_ext_unix_sk(bool ext_unix_sk)
{
	opts->has_ext_unix_sk	= true;
	opts->ext_unix_sk	= ext_unix_sk;
}

void criu_set_tcp_established(bool tcp_established)
{
	opts->has_tcp_established	= true;
	opts->tcp_established		= tcp_established;
}

void criu_set_evasive_devices(bool evasive_devices)
{
	opts->has_evasive_devices	= true;
	opts->evasive_devices		= evasive_devices;
}

void criu_set_shell_job(bool shell_job)
{
	opts->has_shell_job	= true;
	opts->shell_job		= shell_job;
}

void criu_set_file_locks(bool file_locks)
{
	opts->has_file_locks	= true;
	opts->file_locks	= file_locks;
}

void criu_set_log_level(int log_level)
{
	opts->has_log_level	= true;
	opts->log_level		= log_level;
}

void criu_set_root(char *root)
{
	opts->root = strdup(root);
}

void criu_set_manage_cgroups(bool manage)
{
	opts->has_manage_cgroups = true;
	opts->manage_cgroups = manage;
}

void criu_set_log_file(char *log_file)
{
	opts->log_file = strdup(log_file);
}

void criu_set_cpu_cap(unsigned int cap)
{
	opts->has_cpu_cap	= true;
	opts->cpu_cap		= cap;
}

int criu_set_exec_cmd(int argc, char *argv[])
{
	int i;

	opts->n_exec_cmd = argc;
	opts->exec_cmd = malloc((argc) * sizeof(char *));

	if (opts->exec_cmd) {
		for (i = 0; i < argc; i++) {
			opts->exec_cmd[i] = strdup(argv[i]);
			if (!opts->exec_cmd[i]) {
				while (i > 0)
					free(opts->exec_cmd[i--]);
				free(opts->exec_cmd);
				opts->n_exec_cmd = 0;
				opts->exec_cmd = NULL;
				goto out;
			}
		}
		return 0;
	}

out:
	return -ENOMEM;
}

int criu_add_ext_mount(char *key, char *val)
{
	int nr;
	ExtMountMap **a, *m;

	m = malloc(sizeof(*m));
	if (!m)
		goto er;
	ext_mount_map__init(m);

	m->key = strdup(key);
	if (!m->key)
		goto er_n;
	m->val = strdup(val);
	if (!m->val)
		goto er_k;

	nr = opts->n_ext_mnt + 1;
	a = realloc(opts->ext_mnt, nr * sizeof(m));
	if (!a)
		goto er_v;

	a[nr - 1] = m;
	opts->ext_mnt = a;
	opts->n_ext_mnt = nr;
	return 0;

er_v:
	free(m->val);
er_k:
	free(m->key);
er_n:
	free(m);
er:
	return -ENOMEM;
}

int criu_add_cg_root(char *ctrl, char *path)
{
	int nr;
	CgroupRoot **a, *root;

	root = malloc(sizeof(*root));
	if (!root)
		goto er;
	cgroup_root__init(root);

	if (ctrl) {
		root->ctrl = strdup(ctrl);
		if (!root->ctrl)
			goto er_r;
	}

	root->path = strdup(path);
	if (!root->path)
		goto er_c;

	nr = opts->n_cg_root + 1;
	a = realloc(opts->cg_root, nr * sizeof(root));
	if (!a)
		goto er_p;

	a[nr - 1] = root;
	opts->cg_root = a;
	opts->n_cg_root = nr;
	return 0;

er_p:
	free(root->path);
er_c:
	if (root->ctrl)
		free(root->ctrl);
er_r:
	free(root);
er:
	return -ENOMEM;
}
int criu_add_veth_pair(char *in, char *out)
{
	int nr;
	CriuVethPair **a, *p;

	p = malloc(sizeof(*p));
	if (!p)
		goto er;
	criu_veth_pair__init(p);

	p->if_in = strdup(in);
	if (!p->if_in)
		goto er_p;
	p->if_out = strdup(out);
	if (!p->if_out)
		goto er_i;

	nr = opts->n_veths + 1;
	a = realloc(opts->veths, nr * sizeof(p));
	if (!a)
		goto er_o;

	a[nr - 1] = p;
	opts->veths = a;
	opts->n_veths = nr;
	return 0;

er_o:
	free(p->if_out);
er_i:
	free(p->if_in);
er_p:
	free(p);
er:
	return -ENOMEM;
}

static CriuResp *recv_resp(int socket_fd)
{
	unsigned char buf[CR_MAX_MSG_SIZE];
	int len;
	CriuResp *msg = 0;

	len = read(socket_fd, buf, CR_MAX_MSG_SIZE);
	if (len == -1) {
		perror("Can't read response");
		goto err;
	}

	msg = criu_resp__unpack(NULL, len, buf);
	if (!msg) {
		perror("Failed unpacking response");
		goto err;
	}

	return msg;
err:
	saved_errno = errno;
	return NULL;
}

static int send_req(int socket_fd, CriuReq *req)
{
	unsigned char buf[CR_MAX_MSG_SIZE];
	int len;

	len = criu_req__get_packed_size(req);

	if (criu_req__pack(req, buf) != len) {
		perror("Failed packing request");
		goto err;
	}

	if (write(socket_fd, buf, len)  == -1) {
		perror("Can't send request");
		goto err;
	}

	return 0;
err:
	saved_errno = errno;
	return -1;
}

static int send_notify_ack(int socket_fd, int ret)
{
	int send_ret;
	CriuReq req = CRIU_REQ__INIT;

	req.type = CRIU_REQ_TYPE__NOTIFY;
	req.has_notify_success = true;
	req.notify_success = (ret == 0);

	send_ret = send_req(socket_fd, &req);

	/*
	 * If we're failing the notification then report
	 * back the original error code (and it will be
	 * propagated back to user).
	 *
	 * If the notification was OK, then report the
	 * result of acking it.
	 */

	return ret ? : send_ret;
}

static int criu_connect(void)
{
	int fd, ret;
	struct sockaddr_un addr;
	socklen_t addr_len;

	fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		saved_errno = errno;
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;

	strncpy(addr.sun_path, service_address, sizeof(addr.sun_path));

	addr_len = strlen(addr.sun_path) + sizeof(addr.sun_family);

	ret = connect(fd, (struct sockaddr *) &addr, addr_len);
	if (ret < 0) {
		saved_errno = errno;
		perror("Can't connect to socket");
		close(fd);
		return -1;
	}

	return fd;
}

static int send_req_and_recv_resp_sk(int fd, CriuReq *req, CriuResp **resp)
{
	int ret = 0;

	if (send_req(fd, req) < 0) {
		ret = -ECOMM;
		goto exit;
	}

again:
	*resp = recv_resp(fd);
	if (!*resp) {
		perror("Can't receive response");
		ret = -ECOMM;
		goto exit;
	}

	if ((*resp)->type == CRIU_REQ_TYPE__NOTIFY) {
		if (notify)
			ret = notify((*resp)->notify->script, (*resp)->notify);

		ret = send_notify_ack(fd, ret);
		if (!ret)
			goto again;
		else
			goto exit;
	}

	if ((*resp)->type != req->type) {
		if ((*resp)->type == CRIU_REQ_TYPE__EMPTY &&
		    (*resp)->success == false)
			ret = -EINVAL;
		else {
			perror("Unexpected response type");
			ret = -EBADMSG;
		}
	}

exit:
	return ret;
}

static int send_req_and_recv_resp(CriuReq *req, CriuResp **resp)
{
	int fd;
	int ret	= 0;

	fd = criu_connect();
	if (fd < 0) {
		perror("Can't connect to criu");
		ret = -ECONNREFUSED;
	} else {
		ret = send_req_and_recv_resp_sk(fd, req, resp);
		close(fd);
	}

	return ret;
}

int criu_check(void)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__CHECK;

	ret = send_req_and_recv_resp(&req, &resp);
	if (ret)
		goto exit;

	ret = resp->success ? 0 : -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}

int criu_dump(void)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__DUMP;
	req.opts	= opts;

	ret = send_req_and_recv_resp(&req, &resp);
	if (ret)
		goto exit;

	if (resp->success) {
		if (resp->dump->has_restored && resp->dump->restored)
			ret = 1;
		else
			ret = 0;
	} else
		ret = -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}

int criu_dump_iters(int (*more)(criu_predump_info pi))
{
	int ret = -1, fd = -1, uret;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__PRE_DUMP;
	req.opts	= opts;

	ret = -EINVAL;
	/*
	 * Self-dump in iterable manner is tricky and
	 * not supported for the moment.
	 *
	 * Calls w/o iteration callback is, well, not
	 * allowed either.
	 */
	if (!opts->has_pid || !more)
		goto exit;

	ret = -ECONNREFUSED;
	fd = criu_connect();
	if (fd < 0)
		goto exit;

	while (1) {
		ret = send_req_and_recv_resp_sk(fd, &req, &resp);
		if (ret)
			goto exit;

		if (!resp->success) {
			ret = -EBADE;
			goto exit;
		}

		uret = more(NULL);
		if (uret < 0) {
			ret = uret;
			goto exit;
		}

		criu_resp__free_unpacked(resp, NULL);

		if (uret == 0)
			break;
	}

	req.type = CRIU_REQ_TYPE__DUMP;
	ret = send_req_and_recv_resp_sk(fd, &req, &resp);
	if (!ret)
		ret = (resp->success ? 0 : -EBADE);
exit:
	if (fd >= 0)
		close(fd);
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}

int criu_restore(void)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__RESTORE;
	req.opts	= opts;

	ret = send_req_and_recv_resp(&req, &resp);
	if (ret)
		goto exit;

	if (resp->success)
		ret = resp->restore->pid;
	else
		ret = -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	errno = saved_errno;

	return ret;
}

int criu_restore_child(void)
{
	int sks[2], pid, ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, sks))
		goto out;

	pid = fork();
	if (pid < 0)
		goto err;

	if (pid == 0) {
		sigset_t mask;
		char fds[11];

		/*
		 * Unblock SIGCHLD.
		 *
		 * The caller of this function is supposed to have
		 * this signal blocked. Otherwise it risks to get
		 * into situation, when this routine is not yet
		 * returned, but the restore subtree exits and
		 * emits the SIGCHLD.
		 *
		 * In turn, unblocked SIGCHLD is required to make
		 * criu restoration process work -- it catches
		 * subtasks restore errors in this handler.
		 */

		sigemptyset(&mask);
		sigaddset(&mask, SIGCHLD);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);

		close(sks[0]);
		sprintf(fds, "%d", sks[1]);

		execlp("criu", "criu", "swrk", fds, NULL);
		exit(1);
	}

	close(sks[1]);

	req.type	= CRIU_REQ_TYPE__RESTORE;
	req.opts	= opts;

	ret = send_req_and_recv_resp_sk(sks[0], &req, &resp);

	close(sks[0]);
	waitpid(pid, NULL, 0);

	if (!ret) {
		ret = resp->success ? resp->restore->pid : -EBADE;
		criu_resp__free_unpacked(resp, NULL);
	}

out:
	return ret;

err:
	close(sks[1]);
	close(sks[0]);
	goto out;
}
