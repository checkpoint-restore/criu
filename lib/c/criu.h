/*
 * (C) Copyright 2013 Parallels, Inc. (www.parallels.com).
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, you can find it here:
 * www.gnu.org/licenses/lgpl.html
 */

#ifndef __CRIU_LIB_H__
#define __CRIU_LIB_H__

#include <stdbool.h>

#include "version.h"
#include "rpc.pb-c.h"

#ifdef __GNUG__
extern "C" {
#endif

#define CRIU_LOG_UNSET (-1)
#define CRIU_LOG_MSG   (0) /* Print message regardless of log level */
#define CRIU_LOG_ERROR (1) /* Errors only */
#define CRIU_LOG_WARN  (2) /* Warnings */
#define CRIU_LOG_INFO  (3) /* Informative */
#define CRIU_LOG_DEBUG (4) /* Debug only */

enum criu_service_comm { CRIU_COMM_SK, CRIU_COMM_FD, CRIU_COMM_BIN };

enum criu_cg_mode {
	CRIU_CG_MODE_IGNORE,
	CRIU_CG_MODE_NONE,
	CRIU_CG_MODE_PROPS,
	CRIU_CG_MODE_SOFT,
	CRIU_CG_MODE_FULL,
	CRIU_CG_MODE_STRICT,
	CRIU_CG_MODE_DEFAULT,
};

enum criu_network_lock_method {
	CRIU_NETWORK_LOCK_IPTABLES = 1,
	CRIU_NETWORK_LOCK_NFTABLES = 2,
	CRIU_NETWORK_LOCK_SKIP = 3,
};

enum criu_pre_dump_mode { CRIU_PRE_DUMP_SPLICE = 1, CRIU_PRE_DUMP_READ = 2 };

int criu_set_service_address(const char *path);
void criu_set_service_fd(int fd);
int criu_set_service_binary(const char *path);

/*
 * Set opts to defaults. _Must_ be called first before using any functions from
 * the list down below. 0 on success, -1 on fail.
 */
int criu_init_opts(void);
void criu_free_opts(void);

void criu_set_pid(int pid);
void criu_set_images_dir_fd(int fd); /* must be set for dump/restore */
int criu_set_parent_images(const char *path);
void criu_set_work_dir_fd(int fd);
void criu_set_leave_running(bool leave_running);
void criu_set_ext_unix_sk(bool ext_unix_sk);
int criu_add_unix_sk(unsigned int inode);
void criu_set_tcp_established(bool tcp_established);
void criu_set_tcp_skip_in_flight(bool tcp_skip_in_flight);
void criu_set_tcp_close(bool tcp_close);
void criu_set_weak_sysctls(bool val);
void criu_set_evasive_devices(bool evasive_devices);
void criu_set_shell_job(bool shell_job);
void criu_set_skip_file_rwx_check(bool skip_file_rwx_check);
void criu_set_unprivileged(bool unprivileged);
void criu_set_orphan_pts_master(bool orphan_pts_master);
void criu_set_file_locks(bool file_locks);
void criu_set_track_mem(bool track_mem);
void criu_set_auto_dedup(bool auto_dedup);
void criu_set_force_irmap(bool force_irmap);
void criu_set_link_remap(bool link_remap);
void criu_set_log_level(int log_level);
int criu_set_log_file(const char *log_file);
void criu_set_cpu_cap(unsigned int cap);
int criu_set_root(const char *root);
void criu_set_manage_cgroups(bool manage);
void criu_set_manage_cgroups_mode(enum criu_cg_mode mode);
int criu_set_freeze_cgroup(const char *name);
int criu_set_lsm_profile(const char *name);
int criu_set_lsm_mount_context(const char *name);
void criu_set_timeout(unsigned int timeout);
void criu_set_auto_ext_mnt(bool val);
void criu_set_ext_sharing(bool val);
void criu_set_ext_masters(bool val);
int criu_set_exec_cmd(int argc, char *argv[]);
int criu_add_ext_mount(const char *key, const char *val);
int criu_add_veth_pair(const char *in, const char *out);
int criu_add_cg_root(const char *ctrl, const char *path);
int criu_add_enable_fs(const char *fs);
int criu_add_skip_mnt(const char *mnt);
void criu_set_ghost_limit(unsigned int limit);
int criu_add_irmap_path(const char *path);
int criu_add_inherit_fd(int fd, const char *key);
int criu_add_external(const char *key);
int criu_set_page_server_address_port(const char *address, int port);
int criu_set_pre_dump_mode(enum criu_pre_dump_mode mode);
void criu_set_pidfd_store_sk(int sk);
int criu_set_network_lock(enum criu_network_lock_method method);
int criu_join_ns_add(const char *ns, const char *ns_file, const char *extra_opt);
void criu_set_mntns_compat_mode(bool val);

/*
 * The criu_notify_arg_t na argument is an opaque
 * value that callbacks (cb-s) should pass into
 * criu_notify_xxx() calls to fetch arbitrary values
 * from notification. If the value is not available
 * some non-existing one is reported.
 */

typedef CriuNotify *criu_notify_arg_t;
void criu_set_notify_cb(int (*cb)(char *action, criu_notify_arg_t na));

/* Get pid of root task. 0 if not available */
int criu_notify_pid(criu_notify_arg_t na);

/*
 * If CRIU sends and FD in the case of 'orphan-pts-master',
 * this FD can be retrieved with criu_get_orphan_pts_master_fd().
 *
 * If no FD has been received this will return -1.
 *
 * To make sure the FD returned is valid this function has to be
 * called after the callback with the 'action' 'orphan-pts-master'.
 */
int criu_get_orphan_pts_master_fd(void);

/* Here is a table of return values and errno's of functions
 * from the list down below.
 *
 * Return value  errno                Description
 * ----------------------------------------------------------------------------
 * 0             undefined            Success.
 *
 * >0            undefined            Success(criu_restore() only).
 *
 * -BADE         rpc err  (0 for now) RPC has returned fail.
 *
 * -ECONNREFUSED errno                Unable to connect to CRIU.
 *
 * -ECOMM        errno                Unable to send/recv msg to/from CRIU.
 *
 * -EINVAL       undefined            CRIU doesn't support this type of request.
 *                                    You should probably update CRIU.
 *
 * -EBADMSG      undefined            Unexpected response from CRIU.
 *                                    You should probably update CRIU.
 */
int criu_check(void);
int criu_dump(void);
int criu_pre_dump(void);
int criu_restore(void);
int criu_restore_child(void);

/*
 * Perform dumping but with preliminary iterations. Each
 * time an iteration ends the ->more callback is called.
 * The callback's return value is
 *   - positive -- one more iteration starts
 *   - zero     -- final dump is performed and call exits
 *   - negative -- dump is aborted, the value is returned
 *     back from criu_dump_iters
 *
 * The @pi argument is an opaque value that caller may
 * use to request pre-dump statistics (not yet implemented).
 */
typedef void *criu_predump_info;
int criu_dump_iters(int (*more)(criu_predump_info pi));

/*
 * Get the version of the actual binary used for RPC.
 *
 * As this library is just forwarding all tasks to an
 * independent (of this library) CRIU binary, the actual
 * version of the CRIU binary can be different then the
 * hardcoded values in the library (version.h).
 * To be able to easily check the version of the CRIU binary
 * the function criu_get_version() returns the version
 * in the following format:
 *
 * (major * 10000) + (minor * 100) + sublevel
 *
 * If the CRIU binary has been built from a git checkout
 * minor will increased by one.
 */
int criu_get_version(void);

/*
 * Check if the version of the CRIU binary is at least
 * 'minimum'. Version has to be in the same format as
 * described for criu_get_version().
 *
 * Returns 1 if CRIU is at least 'minimum'.
 * Returns 0 if CRIU is too old.
 * Returns < 0 if there was an error.
 */
int criu_check_version(int minimum);

/*
 * Same as the list above, but lets you have your very own options
 * structure and lets you set individual options in it.
 */
typedef struct criu_opts criu_opts;

int criu_local_init_opts(criu_opts **opts);
void criu_local_free_opts(criu_opts *opts);

int criu_local_set_service_address(criu_opts *opts, const char *path);
void criu_local_set_service_fd(criu_opts *opts, int fd);

void criu_local_set_service_fd(criu_opts *opts, int fd);

void criu_local_set_pid(criu_opts *opts, int pid);
void criu_local_set_images_dir_fd(criu_opts *opts, int fd); /* must be set for dump/restore */
int criu_local_set_parent_images(criu_opts *opts, const char *path);
int criu_local_set_service_binary(criu_opts *opts, const char *path);
void criu_local_set_work_dir_fd(criu_opts *opts, int fd);
void criu_local_set_leave_running(criu_opts *opts, bool leave_running);
void criu_local_set_ext_unix_sk(criu_opts *opts, bool ext_unix_sk);
int criu_local_add_unix_sk(criu_opts *opts, unsigned int inode);
void criu_local_set_tcp_established(criu_opts *opts, bool tcp_established);
void criu_local_set_tcp_skip_in_flight(criu_opts *opts, bool tcp_skip_in_flight);
void criu_local_set_tcp_close(criu_opts *opts, bool tcp_close);
void criu_local_set_weak_sysctls(criu_opts *opts, bool val);
void criu_local_set_evasive_devices(criu_opts *opts, bool evasive_devices);
void criu_local_set_shell_job(criu_opts *opts, bool shell_job);
void criu_local_set_skip_file_rwx_check(criu_opts *opts, bool skip_file_rwx_check);
void criu_local_set_orphan_pts_master(criu_opts *opts, bool orphan_pts_master);
void criu_local_set_file_locks(criu_opts *opts, bool file_locks);
void criu_local_set_track_mem(criu_opts *opts, bool track_mem);
void criu_local_set_auto_dedup(criu_opts *opts, bool auto_dedup);
void criu_local_set_force_irmap(criu_opts *opts, bool force_irmap);
void criu_local_set_link_remap(criu_opts *opts, bool link_remap);
void criu_local_set_log_level(criu_opts *opts, int log_level);
int criu_local_set_log_file(criu_opts *opts, const char *log_file);
void criu_local_set_cpu_cap(criu_opts *opts, unsigned int cap);
int criu_local_set_root(criu_opts *opts, const char *root);
void criu_local_set_manage_cgroups(criu_opts *opts, bool manage);
void criu_local_set_manage_cgroups_mode(criu_opts *opts, enum criu_cg_mode mode);
int criu_local_set_freeze_cgroup(criu_opts *opts, const char *name);
int criu_local_set_lsm_profile(criu_opts *opts, const char *name);
int criu_local_set_lsm_mount_context(criu_opts *opts, const char *name);
void criu_local_set_timeout(criu_opts *opts, unsigned int timeout);
void criu_local_set_auto_ext_mnt(criu_opts *opts, bool val);
void criu_local_set_ext_sharing(criu_opts *opts, bool val);
void criu_local_set_ext_masters(criu_opts *opts, bool val);
int criu_local_set_exec_cmd(criu_opts *opts, int argc, char *argv[]);
int criu_local_add_ext_mount(criu_opts *opts, const char *key, const char *val);
int criu_local_add_veth_pair(criu_opts *opts, const char *in, const char *out);
int criu_local_add_cg_root(criu_opts *opts, const char *ctrl, const char *path);
int criu_local_add_enable_fs(criu_opts *opts, const char *fs);
int criu_local_add_skip_mnt(criu_opts *opts, const char *mnt);
void criu_local_set_ghost_limit(criu_opts *opts, unsigned int limit);
int criu_local_add_irmap_path(criu_opts *opts, const char *path);
int criu_local_add_cg_props(criu_opts *opts, const char *stream);
int criu_local_add_cg_props_file(criu_opts *opts, const char *path);
int criu_local_add_cg_dump_controller(criu_opts *opts, const char *name);
int criu_local_add_cg_yard(criu_opts *opts, const char *path);
int criu_local_add_inherit_fd(criu_opts *opts, int fd, const char *key);
int criu_local_add_external(criu_opts *opts, const char *key);
int criu_local_set_page_server_address_port(criu_opts *opts, const char *address, int port);
int criu_local_set_pre_dump_mode(criu_opts *opts, enum criu_pre_dump_mode mode);
void criu_local_set_pidfd_store_sk(criu_opts *opts, int sk);
int criu_local_set_network_lock(criu_opts *opts, enum criu_network_lock_method method);
int criu_local_join_ns_add(criu_opts *opts, const char *ns, const char *ns_file, const char *extra_opt);
void criu_local_set_mntns_compat_mode(criu_opts *opts, bool val);

void criu_local_set_notify_cb(criu_opts *opts, int (*cb)(char *action, criu_notify_arg_t na));

int criu_local_check(criu_opts *opts);
int criu_local_dump(criu_opts *opts);
int criu_local_pre_dump(criu_opts *opts);
int criu_local_restore(criu_opts *opts);
int criu_local_restore_child(criu_opts *opts);
int criu_local_dump_iters(criu_opts *opts, int (*more)(criu_predump_info pi));

int criu_local_get_version(criu_opts *opts);
int criu_local_check_version(criu_opts *opts, int minimum);

/*
 * Feature checking allows the user to check if CRIU supports
 * certain features. There are CRIU features which do not depend
 * on the version of CRIU but on kernel features or architecture.
 *
 * One example is memory tracking. Memory tracking can be disabled
 * in the kernel or there are architectures which do not support
 * it (aarch64 for example). By using the feature check a libcriu
 * user can easily query CRIU if a certain feature is available.
 *
 * The features which should be checked can be marked in the
 * structure 'struct criu_feature_check'. Each structure member
 * that is set to true will result in CRIU checking for the
 * availability of that feature in the current combination of
 * CRIU/kernel/architecture.
 *
 * Available features will be set to true when the function
 * returns successfully. Missing features will be set to false.
 */

struct criu_feature_check {
	bool mem_track;
	bool lazy_pages;
	bool pidfd_store;
};

int criu_feature_check(struct criu_feature_check *features, size_t size);
int criu_local_feature_check(criu_opts *opts, struct criu_feature_check *features, size_t size);

void criu_local_set_empty_ns(criu_opts *opts, int namespaces);
void criu_set_empty_ns(int namespaces);

#ifdef __GNUG__
}
#endif

#endif /* __CRIU_LIB_H__ */
