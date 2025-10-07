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
	CriuOpts *rpc;
	int (*notify)(char *action, criu_notify_arg_t na);
	enum criu_service_comm service_comm;
	union {
		const char *service_address;
		int service_fd;
		const char *service_binary;
	};
	int swrk_pid;
};

static criu_opts *global_opts;
static int saved_errno;
static int orphan_pts_master_fd = -1;

void criu_free_service(criu_opts *opts)
{
	switch (opts->service_comm) {
	case CRIU_COMM_SK:
		free((void *)(opts->service_address));
		break;
	case CRIU_COMM_BIN:
		free((void *)(opts->service_binary));
		break;
	default:
		break;
	}
}

int criu_local_set_service_address(criu_opts *opts, const char *path)
{
	criu_free_service(opts);
	opts->service_comm = CRIU_COMM_SK;
	if (path) {
		opts->service_address = strdup(path);
	} else {
		opts->service_address = strdup(CR_DEFAULT_SERVICE_ADDRESS);
	}
	if (opts->service_address == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_service_address(const char *path)
{
	return criu_local_set_service_address(global_opts, path);
}

void criu_local_set_service_fd(criu_opts *opts, int fd)
{
	criu_free_service(opts);
	opts->service_comm = CRIU_COMM_FD;
	opts->service_fd = fd;
}

void criu_set_service_fd(int fd)
{
	criu_local_set_service_fd(global_opts, fd);
}

int criu_local_set_service_binary(criu_opts *opts, const char *path)
{
	criu_free_service(opts);
	opts->service_comm = CRIU_COMM_BIN;
	if (path) {
		opts->service_binary = strdup(path);
	} else {
		opts->service_binary = strdup(CR_DEFAULT_SERVICE_BIN);
	}
	if (opts->service_binary == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_service_binary(const char *path)
{
	return criu_local_set_service_binary(global_opts, path);
}

void criu_local_free_opts(criu_opts *opts)
{
	int i;

	if (!opts)
		return;
	if (!opts->rpc)
		return;

	if (opts->rpc->exec_cmd) {
		for (i = 0; i < opts->rpc->n_exec_cmd; i++) {
			free(opts->rpc->exec_cmd[i]);
		}
		free(opts->rpc->exec_cmd);
	}
	opts->rpc->n_exec_cmd = 0;

	if (opts->rpc->unix_sk_ino) {
		for (i = 0; i < opts->rpc->n_unix_sk_ino; i++) {
			free(opts->rpc->unix_sk_ino[i]);
		}
		free(opts->rpc->unix_sk_ino);
	}
	opts->rpc->n_unix_sk_ino = 0;

	if (opts->rpc->ext_mnt) {
		for (i = 0; i < opts->rpc->n_ext_mnt; i++) {
			if (opts->rpc->ext_mnt[i]) {
				free(opts->rpc->ext_mnt[i]->val);
				free(opts->rpc->ext_mnt[i]->key);
				free(opts->rpc->ext_mnt[i]);
			}
		}
		free(opts->rpc->ext_mnt);
	}
	opts->rpc->n_ext_mnt = 0;

	if (opts->rpc->cg_root) {
		for (i = 0; i < opts->rpc->n_cg_root; i++) {
			if (opts->rpc->cg_root[i]) {
				free(opts->rpc->cg_root[i]->ctrl);
				free(opts->rpc->cg_root[i]->path);
				free(opts->rpc->cg_root[i]);
			}
		}
		free(opts->rpc->cg_root);
	}
	opts->rpc->n_cg_root = 0;

	if (opts->rpc->veths) {
		for (i = 0; i < opts->rpc->n_veths; i++) {
			if (opts->rpc->veths[i]) {
				free(opts->rpc->veths[i]->if_in);
				free(opts->rpc->veths[i]->if_out);
				free(opts->rpc->veths[i]);
			}
		}
		free(opts->rpc->veths);
	}
	opts->rpc->n_veths = 0;

	if (opts->rpc->enable_fs) {
		for (i = 0; i < opts->rpc->n_enable_fs; i++) {
			free(opts->rpc->enable_fs[i]);
		}
		free(opts->rpc->enable_fs);
	}
	opts->rpc->n_enable_fs = 0;

	if (opts->rpc->skip_mnt) {
		for (i = 0; i < opts->rpc->n_skip_mnt; i++) {
			free(opts->rpc->skip_mnt[i]);
		}
		free(opts->rpc->skip_mnt);
	}
	opts->rpc->n_skip_mnt = 0;

	if (opts->rpc->irmap_scan_paths) {
		for (i = 0; i < opts->rpc->n_irmap_scan_paths; i++) {
			free(opts->rpc->irmap_scan_paths[i]);
		}
		free(opts->rpc->irmap_scan_paths);
	}
	opts->rpc->n_irmap_scan_paths = 0;

	if (opts->rpc->cgroup_dump_controller) {
		for (i = 0; i < opts->rpc->n_cgroup_dump_controller; i++) {
			free(opts->rpc->cgroup_dump_controller[i]);
		}
		free(opts->rpc->cgroup_dump_controller);
	}
	opts->rpc->n_cgroup_dump_controller = 0;

	if (opts->rpc->inherit_fd) {
		for (i = 0; i < opts->rpc->n_inherit_fd; i++) {
			if (opts->rpc->inherit_fd[i]) {
				free(opts->rpc->inherit_fd[i]->key);
				free(opts->rpc->inherit_fd[i]);
			}
		}
		free(opts->rpc->inherit_fd);
	}
	opts->rpc->n_inherit_fd = 0;

	if (opts->rpc->external) {
		for (i = 0; i < opts->rpc->n_external; i++) {
			free(opts->rpc->external[i]);
		}
		free(opts->rpc->external);
	}
	opts->rpc->n_external = 0;

	if (opts->rpc->join_ns) {
		for (i = 0; i < opts->rpc->n_join_ns; i++) {
			free(opts->rpc->join_ns[i]->ns);
			free(opts->rpc->join_ns[i]->ns_file);
			if (opts->rpc->join_ns[i]->extra_opt) {
				free(opts->rpc->join_ns[i]->extra_opt);
			}
			free(opts->rpc->join_ns[i]);
		}
	}
	opts->rpc->n_join_ns = 0;

	if (opts->rpc->ps) {
		free(opts->rpc->ps->address);
		free(opts->rpc->ps);
	}

	free(opts->rpc->cgroup_props_file);
	free(opts->rpc->cgroup_props);
	free(opts->rpc->parent_img);
	free(opts->rpc->root);
	free(opts->rpc->freeze_cgroup);
	free(opts->rpc->log_file);
	free(opts->rpc->lsm_profile);
	free(opts->rpc->lsm_mount_context);
	free(opts->rpc);
	criu_free_service(opts);
	free(opts);
}

int criu_local_init_opts(criu_opts **o)
{
	criu_opts *opts = NULL;
	CriuOpts *rpc = NULL;

	opts = *o;

	criu_local_free_opts(opts);
	*o = NULL;

	rpc = malloc(sizeof(CriuOpts));
	if (rpc == NULL) {
		perror("Can't allocate memory for criu RPC opts");
		return -1;
	}

	criu_opts__init(rpc);

	opts = malloc(sizeof(criu_opts));
	if (opts == NULL) {
		perror("Can't allocate memory for criu opts");
		criu_local_free_opts(opts);
		free(rpc);
		return -1;
	}

	opts->rpc = rpc;
	opts->notify = NULL;

	opts->service_comm = CRIU_COMM_BIN;
	opts->service_binary = strdup(CR_DEFAULT_SERVICE_BIN);

	if (opts->service_binary == NULL) {
		perror("Can't allocate memory for criu service setting");
		criu_local_free_opts(opts);
		return -1;
	}

	*o = opts;

	return 0;
}

int criu_init_opts(void)
{
	return criu_local_init_opts(&global_opts);
}

void criu_free_opts(void)
{
	criu_local_free_opts(global_opts);
	global_opts = NULL;
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
	opts->rpc->has_pid = true;
	opts->rpc->pid = pid;
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

int criu_local_set_parent_images(criu_opts *opts, const char *path)
{
	opts->rpc->parent_img = strdup(path);
	if (opts->rpc->parent_img == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_parent_images(const char *path)
{
	return criu_local_set_parent_images(global_opts, path);
}

int criu_local_set_pre_dump_mode(criu_opts *opts, enum criu_pre_dump_mode mode)
{
	if (mode == CRIU_PRE_DUMP_SPLICE || mode == CRIU_PRE_DUMP_READ) {
		opts->rpc->has_pre_dump_mode = true;
		opts->rpc->pre_dump_mode = (CriuPreDumpMode)mode;
		return 0;
	}
	return -1;
}

int criu_set_pre_dump_mode(enum criu_pre_dump_mode mode)
{
	return criu_local_set_pre_dump_mode(global_opts, mode);
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
	opts->rpc->has_leave_running = true;
	opts->rpc->leave_running = leave_running;
}

void criu_set_leave_running(bool leave_running)
{
	criu_local_set_leave_running(global_opts, leave_running);
}

void criu_local_set_ext_unix_sk(criu_opts *opts, bool ext_unix_sk)
{
	opts->rpc->has_ext_unix_sk = true;
	opts->rpc->ext_unix_sk = ext_unix_sk;
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
	opts->rpc->has_tcp_established = true;
	opts->rpc->tcp_established = tcp_established;
}

void criu_set_tcp_established(bool tcp_established)
{
	criu_local_set_tcp_established(global_opts, tcp_established);
}

void criu_local_set_tcp_skip_in_flight(criu_opts *opts, bool tcp_skip_in_flight)
{
	opts->rpc->has_tcp_skip_in_flight = true;
	opts->rpc->tcp_skip_in_flight = tcp_skip_in_flight;
}

void criu_set_tcp_skip_in_flight(bool tcp_skip_in_flight)
{
	criu_local_set_tcp_skip_in_flight(global_opts, tcp_skip_in_flight);
}

void criu_local_set_tcp_close(criu_opts *opts, bool tcp_close)
{
	opts->rpc->has_tcp_close = true;
	opts->rpc->tcp_close = tcp_close;
}

void criu_set_tcp_close(bool tcp_close)
{
	criu_local_set_tcp_close(global_opts, tcp_close);
}

void criu_local_set_weak_sysctls(criu_opts *opts, bool val)
{
	opts->rpc->has_weak_sysctls = true;
	opts->rpc->weak_sysctls = val;
}

void criu_set_weak_sysctls(bool val)
{
	criu_local_set_weak_sysctls(global_opts, val);
}

void criu_local_set_evasive_devices(criu_opts *opts, bool evasive_devices)
{
	opts->rpc->has_evasive_devices = true;
	opts->rpc->evasive_devices = evasive_devices;
}

void criu_set_evasive_devices(bool evasive_devices)
{
	criu_local_set_evasive_devices(global_opts, evasive_devices);
}

void criu_local_set_shell_job(criu_opts *opts, bool shell_job)
{
	opts->rpc->has_shell_job = true;
	opts->rpc->shell_job = shell_job;
}

void criu_set_shell_job(bool shell_job)
{
	criu_local_set_shell_job(global_opts, shell_job);
}

void criu_local_set_skip_file_rwx_check(criu_opts *opts, bool skip_file_rwx_check)
{
	opts->rpc->has_skip_file_rwx_check = true;
	opts->rpc->skip_file_rwx_check = skip_file_rwx_check;
}

void criu_set_skip_file_rwx_check(bool skip_file_rwx_check)
{
	criu_local_set_skip_file_rwx_check(global_opts, skip_file_rwx_check);
}

void criu_local_set_unprivileged(criu_opts *opts, bool unprivileged)
{
	opts->rpc->has_unprivileged = true;
	opts->rpc->unprivileged = unprivileged;
}

void criu_set_unprivileged(bool unprivileged)
{
	criu_local_set_unprivileged(global_opts, unprivileged);
}

void criu_local_set_orphan_pts_master(criu_opts *opts, bool orphan_pts_master)
{
	opts->rpc->has_orphan_pts_master = true;
	opts->rpc->orphan_pts_master = orphan_pts_master;
}

void criu_set_orphan_pts_master(bool orphan_pts_master)
{
	criu_local_set_orphan_pts_master(global_opts, orphan_pts_master);
}

void criu_local_set_file_locks(criu_opts *opts, bool file_locks)
{
	opts->rpc->has_file_locks = true;
	opts->rpc->file_locks = file_locks;
}

void criu_set_file_locks(bool file_locks)
{
	criu_local_set_file_locks(global_opts, file_locks);
}

void criu_local_set_log_level(criu_opts *opts, int log_level)
{
	opts->rpc->has_log_level = true;
	opts->rpc->log_level = log_level;
}

void criu_set_log_level(int log_level)
{
	criu_local_set_log_level(global_opts, log_level);
}

int criu_local_set_root(criu_opts *opts, const char *root)
{
	opts->rpc->root = strdup(root);
	if (opts->rpc->root == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_root(const char *root)
{
	return criu_local_set_root(global_opts, root);
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

int criu_local_set_freeze_cgroup(criu_opts *opts, const char *name)
{
	opts->rpc->freeze_cgroup = strdup(name);
	if (opts->rpc->freeze_cgroup == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_freeze_cgroup(const char *name)
{
	return criu_local_set_freeze_cgroup(global_opts, name);
}

int criu_local_set_lsm_profile(criu_opts *opts, const char *name)
{
	opts->rpc->lsm_profile = strdup(name);
	if (opts->rpc->lsm_profile == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_lsm_profile(const char *name)
{
	return criu_local_set_lsm_profile(global_opts, name);
}

int criu_local_set_lsm_mount_context(criu_opts *opts, const char *name)
{
	opts->rpc->lsm_mount_context = strdup(name);
	if (opts->rpc->lsm_mount_context == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_lsm_mount_context(const char *name)
{
	return criu_local_set_lsm_mount_context(global_opts, name);
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

int criu_local_set_log_file(criu_opts *opts, const char *log_file)
{
	opts->rpc->log_file = strdup(log_file);
	if (opts->rpc->log_file == NULL) {
		return -ENOMEM;
	}
	return 0;
}

int criu_set_log_file(const char *log_file)
{
	return criu_local_set_log_file(global_opts, log_file);
}

void criu_local_set_cpu_cap(criu_opts *opts, unsigned int cap)
{
	opts->rpc->has_cpu_cap = true;
	opts->rpc->cpu_cap = cap;
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

int criu_local_add_ext_mount(criu_opts *opts, const char *key, const char *val)
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

int criu_add_ext_mount(const char *key, const char *val)
{
	return criu_local_add_ext_mount(global_opts, key, val);
}

int criu_local_add_cg_root(criu_opts *opts, const char *ctrl, const char *path)
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

int criu_add_cg_root(const char *ctrl, const char *path)
{
	return criu_local_add_cg_root(global_opts, ctrl, path);
}

int criu_local_add_veth_pair(criu_opts *opts, const char *in, const char *out)
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

int criu_add_veth_pair(const char *in, const char *out)
{
	return criu_local_add_veth_pair(global_opts, in, out);
}

int criu_local_add_enable_fs(criu_opts *opts, const char *fs)
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

	return -ENOMEM;
}

int criu_add_enable_fs(const char *fs)
{
	return criu_local_add_enable_fs(global_opts, fs);
}

int criu_local_add_skip_mnt(criu_opts *opts, const char *mnt)
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

	return -ENOMEM;
}

int criu_local_add_irmap_path(criu_opts *opts, const char *path)
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

int criu_local_add_cg_props(criu_opts *opts, const char *stream)
{
	char *new;

	new = strdup(stream);
	if (!new)
		return -ENOMEM;

	free(opts->rpc->cgroup_props);
	opts->rpc->cgroup_props = new;
	return 0;
}

int criu_local_add_cg_props_file(criu_opts *opts, const char *path)
{
	char *new;

	new = strdup(path);
	if (!new)
		return -ENOMEM;

	free(opts->rpc->cgroup_props_file);
	opts->rpc->cgroup_props_file = new;
	return 0;
}

int criu_local_add_cg_dump_controller(criu_opts *opts, const char *name)
{
	char **new, *ctrl_name;
	size_t nr;

	ctrl_name = strdup(name);
	if (!ctrl_name)
		return -ENOMEM;

	nr = opts->rpc->n_cgroup_dump_controller + 1;
	new = realloc(opts->rpc->cgroup_dump_controller, nr * sizeof(char *));
	if (!new) {
		free(ctrl_name);
		return -ENOMEM;
	}

	new[opts->rpc->n_cgroup_dump_controller] = ctrl_name;

	opts->rpc->n_cgroup_dump_controller = nr;
	opts->rpc->cgroup_dump_controller = new;

	return 0;
}

int criu_local_add_cg_yard(criu_opts *opts, const char *path)
{
	char *new;

	new = strdup(path);
	if (!new)
		return -ENOMEM;

	free(opts->rpc->cgroup_yard);
	opts->rpc->cgroup_yard = new;
	return 0;
}

int criu_add_skip_mnt(const char *mnt)
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

int criu_add_irmap_path(const char *path)
{
	return criu_local_add_irmap_path(global_opts, path);
}

int criu_local_add_inherit_fd(criu_opts *opts, int fd, const char *key)
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

int criu_add_inherit_fd(int fd, const char *key)
{
	return criu_local_add_inherit_fd(global_opts, fd, key);
}

int criu_local_add_external(criu_opts *opts, const char *key)
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

int criu_add_external(const char *key)
{
	return criu_local_add_external(global_opts, key);
}

int criu_local_set_page_server_address_port(criu_opts *opts, const char *address, int port)
{
	opts->rpc->ps = malloc(sizeof(CriuPageServerInfo));
	if (opts->rpc->ps) {
		criu_page_server_info__init(opts->rpc->ps);

		opts->rpc->ps->address = strdup(address);
		if (!opts->rpc->ps->address) {
			free(opts->rpc->ps);
			opts->rpc->ps = NULL;
			goto out;
		}

		opts->rpc->ps->has_port = true;
		opts->rpc->ps->port = port;
	}

out:
	return -ENOMEM;
}

int criu_set_page_server_address_port(const char *address, int port)
{
	return criu_local_set_page_server_address_port(global_opts, address, port);
}

void criu_local_set_mntns_compat_mode(criu_opts *opts, bool val)
{
	opts->rpc->has_mntns_compat_mode = true;
	opts->rpc->mntns_compat_mode = val;
}

void criu_set_mntns_compat_mode(bool val)
{
	criu_local_set_mntns_compat_mode(global_opts, val);
}

static CriuResp *recv_resp(int socket_fd)
{
	struct msghdr msg_hdr = { 0 };
	unsigned char *buf = NULL;
	struct cmsghdr *cmsg;
	CriuResp *msg = 0;
	struct iovec io;
	int cmsg_len;
	int len;

	/* Check the size of the waiting data. */
	len = recv(socket_fd, NULL, 0, MSG_TRUNC | MSG_PEEK);
	if (len == -1) {
		perror("Can't read request");
		goto err;
	}

	/*
	 * If there is an FD attached to the protobuf message from CRIU
	 * the FD will be in the ancillary data. Let's reserve additional
	 * memory for that.
	 */
	cmsg_len = CMSG_LEN(sizeof(int));
	buf = malloc(len + cmsg_len);
	if (!buf) {
		errno = ENOMEM;
		perror("Can't receive response");
		goto err;
	}

	io.iov_base = buf;
	io.iov_len = len;
	msg_hdr.msg_iov = &io;
	msg_hdr.msg_iovlen = 1;
	msg_hdr.msg_control = buf + len;
	msg_hdr.msg_controllen = cmsg_len;
	len = recvmsg(socket_fd, &msg_hdr, MSG_TRUNC);

	if (len == -1) {
		perror("Can't read request");
		goto err;
	}

	/*
	 * This will be NULL if no FD is in the message. Currently
	 * only a response with script set to 'orphan-pts-master'
	 * has an FD in the ancillary data.
	 */
	cmsg = CMSG_FIRSTHDR(&msg_hdr);
	if (cmsg) {
		/* We probably got an FD from CRIU. */
		if (cmsg->cmsg_type != SCM_RIGHTS) {
			errno = EINVAL;
			goto err;
		}
		/* CTRUNC will be set if msg_hdr.msg_controllen is too small. */
		if (msg_hdr.msg_flags & MSG_CTRUNC) {
			errno = ENFILE;
			goto err;
		}
		/*
		 * Not using 'orphan_pts_master_fd = *(int *)CMSG_DATA(cmsg)'
		 * as that fails with some compilers with:
		 * 'error: dereferencing type-punned pointer will break strict-aliasing rules'
		 */
		memcpy(&orphan_pts_master_fd, CMSG_DATA(cmsg), sizeof(int));
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

	if (write(socket_fd, buf, len) == -1) {
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

	return ret ?: send_ret;
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

	addr_len = strlen(opts->service_address);
	if (addr_len >= sizeof(addr.sun_path)) {
		fprintf(stderr, "The service address %s is too long", opts->service_address);
		close(fd);
		return -1;
	}
	memcpy(addr.sun_path, opts->service_address, addr_len);

	addr_len += sizeof(addr.sun_family);

	ret = connect(fd, (struct sockaddr *)&addr, addr_len);
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
		if (!ret) {
			criu_resp__free_unpacked(*resp, NULL);
			goto again;
		} else
			goto exit;
	}

	if ((*resp)->type != req->type) {
		if ((*resp)->type == CRIU_REQ_TYPE__EMPTY && (*resp)->success == false)
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
	int ret = 0;
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
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;

	saved_errno = 0;

	req.type = CRIU_REQ_TYPE__CHECK;

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

static int dump(bool pre_dump, criu_opts *opts)
{
	int ret = -1;
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;

	saved_errno = 0;

	req.type = pre_dump ? CRIU_REQ_TYPE__SINGLE_PRE_DUMP : CRIU_REQ_TYPE__DUMP;
	req.opts = opts->rpc;

	ret = send_req_and_recv_resp(opts, &req, &resp);
	if (ret)
		goto exit;

	if (resp->success) {
		if (!pre_dump && resp->dump->has_restored && resp->dump->restored)
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

int criu_local_dump(criu_opts *opts)
{
	return dump(false, opts);
}

int criu_dump(void)
{
	return criu_local_dump(global_opts);
}

int criu_local_pre_dump(criu_opts *opts)
{
	return dump(true, opts);
}

int criu_pre_dump(void)
{
	return criu_local_pre_dump(global_opts);
}

int criu_local_dump_iters(criu_opts *opts, int (*more)(criu_predump_info pi))
{
	int ret = -1, fd = -1, uret;
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;

	saved_errno = 0;

	req.type = CRIU_REQ_TYPE__PRE_DUMP;
	req.opts = opts->rpc;

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
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;

	saved_errno = 0;

	req.type = CRIU_REQ_TYPE__RESTORE;
	req.opts = opts->rpc;

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
	const char *saved_comm_data;
	bool save_comm;
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;

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

	req.type = CRIU_REQ_TYPE__RESTORE;
	req.opts = opts->rpc;

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

int criu_local_get_version(criu_opts *opts)
{
	int ret = -1;
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;

	saved_errno = 0;

	req.type = CRIU_REQ_TYPE__VERSION;
	req.opts = opts->rpc;

	ret = send_req_and_recv_resp(opts, &req, &resp);
	if (ret)
		goto exit;

	if (resp->success) {
		ret = resp->version->major_number * 10000;
		ret += resp->version->minor_number * 100;
		if (resp->version->has_sublevel)
			ret += resp->version->sublevel;
		if (resp->version->gitid) {
			/* Taken from runc: a git release -> minor + 1 */
			ret -= (ret % 100);
			ret += 100;
		}
	} else {
		ret = -EBADE;
	}

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	swrk_wait(opts);

	errno = saved_errno;

	return ret;
}

int criu_get_version(void)
{
	return criu_local_get_version(global_opts);
}

int criu_local_check_version(criu_opts *opts, int minimum)
{
	int version;

	version = criu_local_get_version(opts);

	if (version < 0)
		return version;

	if (minimum <= version)
		return 1;

	return 0;
}

int criu_check_version(int minimum)
{
	return criu_local_check_version(global_opts, minimum);
}

int criu_get_orphan_pts_master_fd(void)
{
	return orphan_pts_master_fd;
}

void criu_local_set_pidfd_store_sk(criu_opts *opts, int sk)
{
	opts->rpc->has_pidfd_store_sk = true;
	opts->rpc->pidfd_store_sk = sk;
}

void criu_set_pidfd_store_sk(int sk)
{
	criu_local_set_pidfd_store_sk(global_opts, sk);
}

int criu_local_set_network_lock(criu_opts *opts, enum criu_network_lock_method method)
{
	if (method == CRIU_NETWORK_LOCK_IPTABLES || method == CRIU_NETWORK_LOCK_NFTABLES || method == CRIU_NETWORK_LOCK_SKIP) {
		opts->rpc->has_network_lock = true;
		opts->rpc->network_lock = (CriuNetworkLockMethod)method;
		return 0;
	}
	return -1;
}

int criu_set_network_lock(enum criu_network_lock_method method)
{
	return criu_local_set_network_lock(global_opts, method);
}

int criu_local_join_ns_add(criu_opts *opts, const char *ns, const char *ns_file, const char *extra_opt)
{
	int n_join_ns;
	char *_ns = NULL, *_ns_file = NULL, *_extra_opt = NULL;
	JoinNamespace **join_ns_arr, *join_ns = NULL;

	if (!ns) {
		fprintf(stderr, "ns parameter for join_ns is not specified");
		goto err;
	}

	_ns = strdup(ns);
	if (!_ns) {
		perror("Can't allocate memory for ns");
		goto err;
	}

	if (!ns_file) {
		fprintf(stderr, "ns parameter for join_ns is not specified");
		goto err;
	}

	_ns_file = strdup(ns_file);
	if (!_ns_file) {
		perror("Can't allocate memory for ns_file");
		goto err;
	}

	if (extra_opt) {
		_extra_opt = strdup(extra_opt);
		if (!_extra_opt) {
			perror("Can't allocate memory for extra_opt");
			goto err;
		}
	}

	join_ns = malloc(sizeof(JoinNamespace));
	if (!join_ns) {
		perror("Can't allocate memory for join_ns");
		goto err;
	}

	n_join_ns = opts->rpc->n_join_ns + 1;
	join_ns_arr = realloc(opts->rpc->join_ns, n_join_ns * sizeof(join_ns));
	if (!join_ns_arr) {
		perror("Can't allocate memory for join_ns_arr");
		goto err;
	}

	join_namespace__init(join_ns);
	join_ns->ns = _ns;
	join_ns->ns_file = _ns_file;
	if (_extra_opt) {
		join_ns->extra_opt = _extra_opt;
	}

	join_ns_arr[n_join_ns - 1] = join_ns;
	opts->rpc->join_ns = join_ns_arr;
	opts->rpc->n_join_ns = n_join_ns;

	return 0;

err:
	if (_ns)
		free(_ns);
	if (_ns_file)
		free(_ns_file);
	if (_extra_opt)
		free(_extra_opt);
	if (join_ns)
		free(join_ns);
	return -1;
}

int criu_join_ns_add(const char *ns, const char *ns_file, const char *extra_opt)
{
	return criu_local_join_ns_add(global_opts, ns, ns_file, extra_opt);
}

int criu_local_feature_check(criu_opts *opts, struct criu_feature_check *features, size_t size)
{
	CriuFeatures criu_features = CRIU_FEATURES__INIT;
	struct criu_feature_check features_copy = { 0 };
	CriuReq req = CRIU_REQ__INIT;
	CriuResp *resp = NULL;
	int ret = -1;

	saved_errno = 0;

	if (!features)
		goto exit;

	if (size > sizeof(struct criu_feature_check))
		goto exit;

	memcpy(&features_copy, features, size);

	req.type = CRIU_REQ_TYPE__FEATURE_CHECK;
	req.opts = opts->rpc;

	if (features_copy.mem_track) {
		criu_features.has_mem_track = true;
		criu_features.mem_track = true;
	}
	if (features_copy.lazy_pages) {
		criu_features.has_lazy_pages = true;
		criu_features.lazy_pages = true;
	}
	if (features_copy.pidfd_store) {
		criu_features.has_pidfd_store = true;
		criu_features.pidfd_store = true;
	}
	req.features = &criu_features;

	ret = send_req_and_recv_resp(opts, &req, &resp);
	if (ret)
		goto exit;

	memset(&features_copy, 0, sizeof(struct criu_feature_check));

	if (resp->success) {
		if (resp->features->has_mem_track) {
			features_copy.mem_track = resp->features->mem_track;
		}
		if (resp->features->has_lazy_pages) {
			features_copy.lazy_pages = resp->features->lazy_pages;
		}
		if (resp->features->has_pidfd_store) {
			features_copy.pidfd_store = resp->features->pidfd_store;
		}
		memcpy(features, &features_copy, size);
	} else {
		ret = -EBADE;
	}

exit:
	if (resp)
		criu_resp__free_unpacked(resp, NULL);

	swrk_wait(opts);

	errno = saved_errno;

	return ret;
}

int criu_feature_check(struct criu_feature_check *features, size_t size)
{
	return criu_local_feature_check(global_opts, features, size);
}

void criu_local_set_empty_ns(criu_opts *opts, int namespaces)
{
	opts->rpc->has_empty_ns = true;
	opts->rpc->empty_ns = namespaces;
}

void criu_set_empty_ns(int namespaces)
{
	criu_local_set_empty_ns(global_opts, namespaces);
}

int criu_local_set_config_file(criu_opts *opts, const char *path)
{
	char *new;

	new = strdup(path);
	if (!new)
		return -ENOMEM;

	free(opts->rpc->config_file);
	opts->rpc->config_file = new;

	return 0;
}

int criu_set_config_file(const char *path)
{
	return criu_local_set_config_file(global_opts, path);
}
