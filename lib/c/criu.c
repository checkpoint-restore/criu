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
#include <string.h>

#include "criu.h"
#include "rpc.pb-c.h"
#include "cr-service-const.h"

#define CR_DEFAULT_SERVICE_BIN "criu"

const char *criu_lib_version = CRIU_VERSION;

struct criu_opts {
	CriuOpts		*rpc;
	int			(*notify)(char *action, criu_notify_arg_t na);
	enum criu_service_comm	service_comm;
	union {
		char		*service_address;
		int		service_fd;
		char		*service_binary;
	};
	int			swrk_pid;
};

static criu_opts *global_opts;
static int saved_errno;

void criu_local_set_service_comm(criu_opts *opts, enum criu_service_comm comm)
{
	opts->service_comm = comm;
}

void criu_set_service_comm(enum criu_service_comm comm)
{
	criu_local_set_service_comm(global_opts, comm);
}

void criu_local_set_service_address(criu_opts *opts, char *path)
{
	if (path)
		opts->service_address = path;
	else
		opts->service_address = CR_DEFAULT_SERVICE_ADDRESS;
}

void criu_set_service_address(char *path)
{
	criu_local_set_service_address(global_opts, path);
}

void criu_local_set_service_fd(criu_opts *opts, int fd)
{
	opts->service_fd = fd;
}

void criu_set_service_fd(int fd)
{
	criu_local_set_service_fd(global_opts, fd);
}

void criu_local_set_service_binary(criu_opts *opts, char *path)
{
	if (path)
		opts->service_binary = path;
	else
		opts->service_binary = CR_DEFAULT_SERVICE_BIN;
}

void criu_set_service_binary(char *path)
{
	criu_local_set_service_binary(global_opts, path);
}

int criu_local_init_opts(criu_opts **o)
{
	criu_opts *opts = NULL;
	CriuOpts *rpc = NULL;

	opts = *o;

	if (opts) {
		if (opts->rpc)
			criu_opts__free_unpacked(opts->rpc, NULL);

		free(opts);
		opts = NULL;
	}

	rpc = malloc(sizeof(CriuOpts));
	if (rpc == NULL) {
		perror("Can't allocate memory for criu RPC opts");
		return -1;
	}

	criu_opts__init(rpc);

	opts = malloc(sizeof(criu_opts));
	if (opts == NULL) {
		perror("Can't allocate memory for criu opts");
		criu_opts__free_unpacked(rpc, NULL);
		return -1;
	}

	opts->rpc	= rpc;
	opts->notify	= NULL;

	opts->service_comm	= CRIU_COMM_BIN;
	opts->service_address	= CR_DEFAULT_SERVICE_BIN;

	*o = opts;

	return 0;
}

int criu_init_opts(void)
{
	return criu_local_init_opts(&global_opts);
}

void criu_local_set_notify_cb(criu_opts *opts, int (*cb)(char *action, criu_notify_arg_t na))
{
	opts->notify = cb;
	opts->rpc->has_notify_scripts = true;
	opts->rpc->notify_scripts = true;
}

void criu_set_notify_cb(int (*cb)(char *action, criu_notify_arg_t na))
{
	criu_local_set_notify_cb(global_opts, cb);
}

int criu_notify_pid(criu_notify_arg_t na)
{
	return na->has_pid ? na->pid : 0;
}

void criu_local_set_pid(criu_opts *opts, int pid)
{
	opts->rpc->has_pid	= true;
	opts->rpc->pid		= pid;
}

void criu_set_pid(int pid)
{
	criu_local_set_pid(global_opts, pid);
}

void criu_local_set_images_dir_fd(criu_opts *opts, int fd)
{
	opts->rpc->images_dir_fd = fd;
}

void criu_set_images_dir_fd(int fd)
{
	criu_local_set_images_dir_fd(global_opts, fd);
}

void criu_local_set_parent_images(criu_opts *opts, char *path)
{
	opts->rpc->parent_img = strdup(path);
}

void criu_set_parent_images(char *path)
{
	criu_local_set_parent_images(global_opts, path);
}

void criu_local_set_track_mem(criu_opts *opts, bool track_mem)
{
	opts->rpc->has_track_mem = true;
	opts->rpc->track_mem = track_mem;
}

void criu_set_track_mem(bool track_mem)
{
	criu_local_set_track_mem(global_opts, track_mem);
}

void criu_local_set_auto_dedup(criu_opts *opts, bool auto_dedup)
{
	opts->rpc->has_auto_dedup = true;
	opts->rpc->auto_dedup = auto_dedup;
}

void criu_set_auto_dedup(bool auto_dedup)
{
	criu_local_set_auto_dedup(global_opts, auto_dedup);
}

void criu_local_set_force_irmap(criu_opts *opts, bool force_irmap)
{
	opts->rpc->has_force_irmap = true;
	opts->rpc->force_irmap = force_irmap;
}

void criu_set_force_irmap(bool force_irmap)
{
	criu_local_set_force_irmap(global_opts, force_irmap);
}

void criu_local_set_link_remap(criu_opts *opts, bool link_remap)
{
	opts->rpc->has_link_remap = true;
	opts->rpc->link_remap = link_remap;
}

void criu_set_link_remap(bool link_remap)
{
	criu_local_set_link_remap(global_opts, link_remap);
}

void criu_local_set_work_dir_fd(criu_opts *opts, int fd)
{
	opts->rpc->has_work_dir_fd = true;
	opts->rpc->work_dir_fd = fd;
}

void criu_set_work_dir_fd(int fd)
{
	criu_local_set_work_dir_fd(global_opts, fd);
}

void criu_local_set_leave_running(criu_opts *opts, bool leave_running)
{
	opts->rpc->has_leave_running	= true;
	opts->rpc->leave_running	= leave_running;
}

void criu_set_leave_running(bool leave_running)
{
	criu_local_set_leave_running(global_opts, leave_running);
}

void criu_local_set_ext_unix_sk(criu_opts *opts, bool ext_unix_sk)
{
	opts->rpc->has_ext_unix_sk	= true;
	opts->rpc->ext_unix_sk	= ext_unix_sk;
}

void criu_set_ext_unix_sk(bool ext_unix_sk)
{
	criu_local_set_ext_unix_sk(global_opts, ext_unix_sk);
}

int criu_local_add_unix_sk(criu_opts *opts, unsigned int inode)
{
	int nr;
	UnixSk **a, *u;

	/*if caller forgot enable ext_unix_sk option we do it*/
	if (!opts->rpc->has_ext_unix_sk) {
		criu_local_set_ext_unix_sk(opts, true);
	}

	/*if user disabled ext_unix_sk and try to add unixsk inode after that*/
	if (opts->rpc->has_ext_unix_sk && !opts->rpc->ext_unix_sk) {
		if (opts->rpc->n_unix_sk_ino > 0) {
			free(opts->rpc->unix_sk_ino);
			opts->rpc->n_unix_sk_ino = 0;
		}
		return -1;
	}

	u = malloc(sizeof(*u));
	if (!u)
		goto er;
	unix_sk__init(u);

	u->inode = inode;

	nr = opts->rpc->n_unix_sk_ino + 1;
	a = realloc(opts->rpc->unix_sk_ino, nr * sizeof(u));
	if (!a)
		goto er_u;

	a[nr - 1] = u;
	opts->rpc->unix_sk_ino = a;
	opts->rpc->n_unix_sk_ino = nr;
	return 0;

er_u:
	free(u);
er:
	return -ENOMEM;
}

int criu_add_unix_sk(unsigned int inode)
{
	return criu_local_add_unix_sk(global_opts, inode);
}

void criu_local_set_tcp_established(criu_opts *opts, bool tcp_established)
{
	opts->rpc->has_tcp_established	= true;
	opts->rpc->tcp_established	= tcp_established;
}

void criu_set_tcp_established(bool tcp_established)
{
	criu_local_set_tcp_established(global_opts, tcp_established);
}

void criu_local_set_tcp_skip_in_flight(criu_opts *opts, bool tcp_skip_in_flight)
{
	opts->rpc->has_tcp_skip_in_flight	= true;
	opts->rpc->tcp_skip_in_flight		= tcp_skip_in_flight;
}

void criu_set_tcp_skip_in_flight(bool tcp_skip_in_flight)
{
	criu_local_set_tcp_skip_in_flight(global_opts, tcp_skip_in_flight);
}

void criu_local_set_weak_sysctls(criu_opts *opts, bool val)
{
	opts->rpc->has_weak_sysctls = true;
	opts->rpc->weak_sysctls	= val;
}

void criu_set_weak_sysctls(bool val)
{
	criu_local_set_weak_sysctls(global_opts, val);
}

void criu_local_set_evasive_devices(criu_opts *opts, bool evasive_devices)
{
	opts->rpc->has_evasive_devices	= true;
	opts->rpc->evasive_devices	= evasive_devices;
}

void criu_set_evasive_devices(bool evasive_devices)
{
	criu_local_set_evasive_devices(global_opts, evasive_devices);
}

void criu_local_set_shell_job(criu_opts *opts, bool shell_job)
{
	opts->rpc->has_shell_job	= true;
	opts->rpc->shell_job		= shell_job;
}

void criu_set_shell_job(bool shell_job)
{
	criu_local_set_shell_job(global_opts, shell_job);
}

void criu_local_set_file_locks(criu_opts *opts, bool file_locks)
{
	opts->rpc->has_file_locks	= true;
	opts->rpc->file_locks		= file_locks;
}

void criu_set_file_locks(bool file_locks)
{
	criu_local_set_file_locks(global_opts, file_locks);
}

void criu_local_set_log_level(criu_opts *opts, int log_level)
{
	opts->rpc->has_log_level	= true;
	opts->rpc->log_level		= log_level;
}

void criu_set_log_level(int log_level)
{
	criu_local_set_log_level(global_opts, log_level);
}

void criu_local_set_root(criu_opts *opts, char *root)
{
	opts->rpc->root = strdup(root);
}

void criu_set_root(char *root)
{
	criu_local_set_root(global_opts, root);
}

void criu_local_set_manage_cgroups(criu_opts *opts, bool manage)
{
	opts->rpc->has_manage_cgroups = true;
	opts->rpc->manage_cgroups = manage;
}

void criu_set_manage_cgroups(bool manage)
{
	criu_local_set_manage_cgroups(global_opts, manage);
}

void criu_local_set_manage_cgroups_mode(criu_opts *opts, enum criu_cg_mode mode)
{
	opts->rpc->has_manage_cgroups_mode = true;
	opts->rpc->manage_cgroups_mode = (CriuCgMode)mode;
}

void criu_set_manage_cgroups_mode(enum criu_cg_mode mode)
{
	criu_local_set_manage_cgroups_mode(global_opts, mode);
}

void criu_local_set_freeze_cgroup(criu_opts *opts, char *name)
{
	opts->rpc->freeze_cgroup = name;
}

void criu_set_freeze_cgroup(char *name)
{
	criu_local_set_freeze_cgroup(global_opts, name);
}

void criu_local_set_timeout(criu_opts *opts, unsigned int timeout)
{
	opts->rpc->timeout = timeout;
}

void criu_set_timeout(unsigned int timeout)
{
	criu_local_set_timeout(global_opts, timeout);
}

void criu_local_set_auto_ext_mnt(criu_opts *opts, bool val)
{
	opts->rpc->has_auto_ext_mnt = true;
	opts->rpc->auto_ext_mnt = val;
}

void criu_set_auto_ext_mnt(bool val)
{
	criu_local_set_auto_ext_mnt(global_opts, val);
}

void criu_local_set_ext_sharing(criu_opts *opts, bool val)
{
	opts->rpc->has_ext_sharing = true;
	opts->rpc->ext_sharing = val;
}

void criu_set_ext_sharing(bool val)
{
	criu_local_set_ext_sharing(global_opts, val);
}

void criu_local_set_ext_masters(criu_opts *opts, bool val)
{
	opts->rpc->has_ext_masters = true;
	opts->rpc->ext_masters = val;
}

void criu_set_ext_masters(bool val)
{
	criu_local_set_ext_masters(global_opts, val);
}

void criu_local_set_log_file(criu_opts *opts, char *log_file)
{
	opts->rpc->log_file = strdup(log_file);
}

void criu_set_log_file(char *log_file)
{
	criu_local_set_log_file(global_opts, log_file);
}

void criu_local_set_cpu_cap(criu_opts *opts, unsigned int cap)
{
	opts->rpc->has_cpu_cap	= true;
	opts->rpc->cpu_cap	= cap;
}

void criu_set_cpu_cap(unsigned int cap)
{
	criu_local_set_cpu_cap(global_opts, cap);
}

int criu_local_set_exec_cmd(criu_opts *opts, int argc, char *argv[])
{
	int i;

	opts->rpc->n_exec_cmd = argc;
	opts->rpc->exec_cmd = malloc((argc) * sizeof(char *));

	if (opts->rpc->exec_cmd) {
		for (i = 0; i < argc; i++) {
			opts->rpc->exec_cmd[i] = strdup(argv[i]);
			if (!opts->rpc->exec_cmd[i]) {
				while (i > 0)
					free(opts->rpc->exec_cmd[i--]);
				free(opts->rpc->exec_cmd);
				opts->rpc->n_exec_cmd = 0;
				opts->rpc->exec_cmd = NULL;
				goto out;
			}
		}
		return 0;
	}

out:
	return -ENOMEM;
}

int criu_set_exec_cmd(int argc, char *argv[])
{
	return criu_local_set_exec_cmd(global_opts, argc, argv);
}

int criu_local_add_ext_mount(criu_opts *opts, char *key, char *val)
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

	nr = opts->rpc->n_ext_mnt + 1;
	a = realloc(opts->rpc->ext_mnt, nr * sizeof(m));
	if (!a)
		goto er_v;

	a[nr - 1] = m;
	opts->rpc->ext_mnt = a;
	opts->rpc->n_ext_mnt = nr;
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

int criu_add_ext_mount(char *key, char *val)
{
	return criu_local_add_ext_mount(global_opts, key, val);
}

int criu_local_add_cg_root(criu_opts *opts, char *ctrl, char *path)
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

	nr = opts->rpc->n_cg_root + 1;
	a = realloc(opts->rpc->cg_root, nr * sizeof(root));
	if (!a)
		goto er_p;

	a[nr - 1] = root;
	opts->rpc->cg_root = a;
	opts->rpc->n_cg_root = nr;
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

int criu_add_cg_root(char *ctrl, char *path)
{
	return criu_local_add_cg_root(global_opts, ctrl, path);
}

int criu_local_add_veth_pair(criu_opts *opts, char *in, char *out)
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

	nr = opts->rpc->n_veths + 1;
	a = realloc(opts->rpc->veths, nr * sizeof(p));
	if (!a)
		goto er_o;

	a[nr - 1] = p;
	opts->rpc->veths = a;
	opts->rpc->n_veths = nr;
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

int criu_add_veth_pair(char *in, char *out)
{
	return criu_local_add_veth_pair(global_opts, in, out);
}

int criu_local_add_enable_fs(criu_opts *opts, char *fs)
{
	int nr;
	char *str = NULL;
	char **ptr = NULL;

	str = strdup(fs);
	if (!str)
		goto err;

	nr = opts->rpc->n_enable_fs + 1;
	ptr = realloc(opts->rpc->enable_fs, nr * sizeof(*ptr));
	if (!ptr)
		goto err;

	ptr[nr - 1] = str;

	opts->rpc->n_enable_fs = nr;
	opts->rpc->enable_fs = ptr;

	return 0;

err:
	if (str)
		free(str);
	if (ptr)
		free(ptr);

	return -ENOMEM;
}

int criu_add_enable_fs(char *fs)
{
	return criu_local_add_enable_fs(global_opts, fs);
}


int criu_local_add_skip_mnt(criu_opts *opts, char *mnt)
{
	int nr;
	char *str = NULL;
	char **ptr = NULL;

	str = strdup(mnt);
	if (!str)
		goto err;

	nr = opts->rpc->n_skip_mnt + 1;
	ptr = realloc(opts->rpc->skip_mnt, nr * sizeof(*ptr));
	if (!ptr)
		goto err;

	ptr[nr - 1] = str;

	opts->rpc->n_skip_mnt = nr;
	opts->rpc->skip_mnt = ptr;

	return 0;

err:
	if (str)
		free(str);
	if (ptr)
		free(ptr);

	return -ENOMEM;
}

int criu_local_add_irmap_path(criu_opts *opts, char *path)
{
	int nr;
	char *my_path;
	char **m;

	if (!opts)
		return -1;

	my_path = strdup(path);
	if (!my_path)
		goto err;

	nr = opts->rpc->n_irmap_scan_paths + 1;
	m = realloc(opts->rpc->irmap_scan_paths, nr * sizeof(*m));
	if (!m)
		goto err;

	m[nr - 1] = my_path;

	opts->rpc->n_irmap_scan_paths = nr;
	opts->rpc->irmap_scan_paths = m;

	return 0;

err:
	if (my_path)
		free(my_path);

	return -ENOMEM;
}

int criu_local_add_cg_props(criu_opts *opts, char *stream)
{
	char *new;

	new = strdup(stream);
	if (!new)
		return -ENOMEM;

	free(opts->rpc->cgroup_props);
	opts->rpc->cgroup_props = new;
	return 0;
}

int criu_local_add_cg_props_file(criu_opts *opts, char *path)
{
	char *new;

	new = strdup(path);
	if (!new)
		return -ENOMEM;

	free(opts->rpc->cgroup_props_file);
	opts->rpc->cgroup_props_file = new;
	return 0;
}

int criu_local_add_cg_dump_controller(criu_opts *opts, char *name)
{
	char **new;
	size_t nr;

	nr = opts->rpc->n_cgroup_dump_controller + 1;
	new = realloc(opts->rpc->cgroup_dump_controller, nr * sizeof(char *));
	if (!new)
		return -ENOMEM;

	new[opts->rpc->n_cgroup_dump_controller] = strdup(name);
	if (!new[opts->rpc->n_cgroup_dump_controller])
		return -ENOMEM;

	opts->rpc->n_cgroup_dump_controller = nr;
	opts->rpc->cgroup_dump_controller = new;

	return 0;
}

int criu_add_skip_mnt(char *mnt)
{
	return criu_local_add_skip_mnt(global_opts, mnt);
}

void criu_local_set_ghost_limit(criu_opts *opts, unsigned int limit)
{
	opts->rpc->has_ghost_limit = true;
	opts->rpc->ghost_limit = limit;
}

void criu_set_ghost_limit(unsigned int limit)
{
	criu_local_set_ghost_limit(global_opts, limit);
}

int criu_add_irmap_path(char *path)
{
	return criu_local_add_irmap_path(global_opts, path);
}

int criu_local_add_inherit_fd(criu_opts *opts, int fd, char *key)
{
	int nr;
	InheritFd **a, *f;

	/* Inheriting is only supported with swrk mode */
	if (opts->service_comm != CRIU_COMM_BIN)
		return -1;

	f = malloc(sizeof(*f));
	if (!f)
		goto er;
	inherit_fd__init(f);

	f->fd = fd;
	f->key = strdup(key);
	if (!f->key)
		goto er_f;

	nr = opts->rpc->n_inherit_fd + 1;
	a = realloc(opts->rpc->inherit_fd, nr * sizeof(f));
	if (!a)
		goto err_k;

	a[nr - 1] = f;
	opts->rpc->inherit_fd = a;
	opts->rpc->n_inherit_fd = nr;
	return 0;
err_k:
	free(f->key);
er_f:
	free(f);
er:
	return -ENOMEM;
}

int criu_add_inherit_fd(int fd, char *key)
{
	return criu_local_add_inherit_fd(global_opts, fd, key);
}

int criu_local_add_external(criu_opts *opts, char *key)
{
	int nr;
	char **a, *e = NULL;

	e = strdup(key);
	if (!e)
		goto err;

	nr = opts->rpc->n_external + 1;
	a = realloc(opts->rpc->external, nr * sizeof(*a));
	if (!a)
		goto err;

	a[nr - 1] = e;
	opts->rpc->external = a;
	opts->rpc->n_external = nr;
	return 0;
err:
	if (e)
		free(e);
	return -ENOMEM;
}

int criu_add_external(char *key)
{
	return criu_local_add_external(global_opts, key);
}

static CriuResp *recv_resp(int socket_fd)
{
	unsigned char *buf = NULL;
	int len;
	CriuResp *msg = 0;

	len = recv(socket_fd, NULL, 0, MSG_TRUNC | MSG_PEEK);
	if (len == -1) {
		perror("Can't read request");
		goto err;
	}

	buf = malloc(len);
	if (!buf) {
		errno = ENOMEM;
		perror("Can't receive response");
		goto err;
	}

	len = recv(socket_fd, buf, len, MSG_TRUNC);
	if (len == -1) {
		perror("Can't read request");
		goto err;
	}

	msg = criu_resp__unpack(NULL, len, buf);
	if (!msg) {
		perror("Failed unpacking response");
		goto err;
	}

	free(buf);
	return msg;
err:
	free(buf);
	saved_errno = errno;
	return NULL;
}

static int send_req(int socket_fd, CriuReq *req)
{
	unsigned char *buf;
	int len;

	len = criu_req__get_packed_size(req);

	buf = malloc(len);
	if (!buf) {
		errno = ENOMEM;
		perror("Can't send request");
		goto err;
	}

	if (criu_req__pack(req, buf) != len) {
		perror("Failed packing request");
		goto err;
	}

	if (write(socket_fd, buf, len)  == -1) {
		perror("Can't send request");
		goto err;
	}

	free(buf);
	return 0;
err:
	free(buf);
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

static void swrk_wait(criu_opts *opts)
{
	if (opts->service_comm == CRIU_COMM_BIN)
		waitpid(opts->swrk_pid, NULL, 0);
}

static int swrk_connect(criu_opts *opts, bool d)
{
	int sks[2], pid, ret = -1;

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

		if (d)
			if (daemon(0, 1)) {
				perror("Can't detach for a self-dump");
				goto child_err;
			}

		pid = getpid();
		if (write(sks[1], &pid, sizeof(pid)) != sizeof(pid)) {
			perror("Can't write swrk pid");
			goto child_err;
		}

		execlp(opts->service_binary, opts->service_binary, "swrk", fds, NULL);
		perror("Can't exec criu swrk");
child_err:
		close(sks[1]);
		exit(1);
	}

	close(sks[1]);

	if (read(sks[0], &pid, sizeof(pid)) != sizeof(pid)) {
		perror("Can't read swrk pid");
		goto err;
	}

	opts->swrk_pid = pid;
	ret = sks[0];

out:
	return ret;

err:
	close(sks[0]);
	close(sks[1]);
	goto out;
}

static int criu_connect(criu_opts *opts, bool d)
{
	int fd, ret;
	struct sockaddr_un addr;
	socklen_t addr_len;

	if (opts->service_comm == CRIU_COMM_FD)
		return opts->service_fd;
	else if (opts->service_comm == CRIU_COMM_BIN)
		return swrk_connect(opts, d);

	fd = socket(AF_LOCAL, SOCK_SEQPACKET, 0);
	if (fd < 0) {
		saved_errno = errno;
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;

	strncpy(addr.sun_path, opts->service_address, sizeof(addr.sun_path));

	addr_len = strlen(opts->service_address) + sizeof(addr.sun_family);

	ret = connect(fd, (struct sockaddr *) &addr, addr_len);
	if (ret < 0) {
		saved_errno = errno;
		perror("Can't connect to socket");
		close(fd);
		return -1;
	}

	return fd;
}

static int send_req_and_recv_resp_sk(int fd, criu_opts *opts, CriuReq *req, CriuResp **resp)
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
		if (opts->notify)
			ret = opts->notify((*resp)->notify->script, (*resp)->notify);

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

	if ((*resp)->has_cr_errno)
		saved_errno = (*resp)->cr_errno;

exit:
	return ret;
}

static int send_req_and_recv_resp(criu_opts *opts, CriuReq *req, CriuResp **resp)
{
	int fd;
	int ret	= 0;
	bool d = false;

	if (req->type == CRIU_REQ_TYPE__DUMP && req->opts->has_pid == false)
		d = true;

	fd = criu_connect(opts, d);
	if (fd < 0) {
		perror("Can't connect to criu");
		ret = -ECONNREFUSED;
	} else {
		ret = send_req_and_recv_resp_sk(fd, opts, req, resp);
		close(fd);
	}

	return ret;
}

int criu_local_check(criu_opts *opts)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__CHECK;

	ret = send_req_and_recv_resp(opts, &req, &resp);
	if (ret)
		goto exit;

	ret = resp->success ? 0 : -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	swrk_wait(opts);

	errno = saved_errno;

	return ret;
}

int criu_check(void)
{
	return criu_local_check(global_opts);
}

int criu_local_dump(criu_opts *opts)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__DUMP;
	req.opts	= opts->rpc;

	ret = send_req_and_recv_resp(opts, &req, &resp);
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

	swrk_wait(opts);

	errno = saved_errno;

	return ret;
}

int criu_dump(void)
{
	return criu_local_dump(global_opts);
}

int criu_local_dump_iters(criu_opts *opts, int (*more)(criu_predump_info pi))
{
	int ret = -1, fd = -1, uret;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__PRE_DUMP;
	req.opts	= opts->rpc;

	ret = -EINVAL;
	/*
	 * Self-dump in iterable manner is tricky and
	 * not supported for the moment.
	 *
	 * Calls w/o iteration callback is, well, not
	 * allowed either.
	 */
	if (!opts->rpc->has_pid || !more)
		goto exit;

	ret = -ECONNREFUSED;
	fd = criu_connect(opts, false);
	if (fd < 0)
		goto exit;

	while (1) {
		ret = send_req_and_recv_resp_sk(fd, opts, &req, &resp);
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
	ret = send_req_and_recv_resp_sk(fd, opts, &req, &resp);
	if (!ret)
		ret = (resp->success ? 0 : -EBADE);
exit:
	if (fd >= 0)
		close(fd);
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	swrk_wait(opts);

	errno = saved_errno;

	return ret;
}

int criu_dump_iters(int (*more)(criu_predump_info pi))
{
	return criu_local_dump_iters((void *)global_opts, more);
}

int criu_local_restore(criu_opts *opts)
{
	int ret = -1;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__RESTORE;
	req.opts	= opts->rpc;

	ret = send_req_and_recv_resp(opts, &req, &resp);
	if (ret)
		goto exit;

	if (resp->success)
		ret = resp->restore->pid;
	else
		ret = -EBADE;

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	swrk_wait(opts);

	errno = saved_errno;

	return ret;
}

int criu_restore(void)
{
	return criu_local_restore(global_opts);
}

int criu_local_restore_child(criu_opts *opts)
{
	int sk, ret = -1;
	enum criu_service_comm saved_comm;
	char *saved_comm_data;
	bool save_comm;
	CriuReq req	= CRIU_REQ__INIT;
	CriuResp *resp	= NULL;

	/*
	 * restore_child is not possible with criu running as a system
	 * service, so we need to switch comm method to CRIU_COMM_BIN.
	 * We're doing so because of the backward compatibility, and we
	 * should probably consider requiring CRIU_COMM_BIN to be set by
	 * user at some point.
	 */
	save_comm = (opts->service_comm != CRIU_COMM_BIN);
	if (save_comm) {
		/* Save comm */
		saved_comm = opts->service_comm;
		saved_comm_data = opts->service_address;

		opts->service_comm = CRIU_COMM_BIN;
		opts->service_binary = CR_DEFAULT_SERVICE_BIN;
	}

	sk = swrk_connect(opts, false);
	if (save_comm) {
		/* Restore comm */
		opts->service_comm = saved_comm;
		opts->service_address = saved_comm_data;
	}

	if (sk < 0)
		return -1;

	saved_errno = 0;

	req.type	= CRIU_REQ_TYPE__RESTORE;
	req.opts	= opts->rpc;

	req.opts->has_rst_sibling = true;
	req.opts->rst_sibling = true;

	ret = send_req_and_recv_resp_sk(sk, opts, &req, &resp);

	swrk_wait(opts);

	if (!ret) {
		ret = resp->success ? resp->restore->pid : -EBADE;
		criu_resp__free_unpacked(resp, NULL);
	}

	close(sk);
	errno = saved_errno;
	return ret;
}

int criu_restore_child(void)
{
	return criu_local_restore_child(global_opts);
}
