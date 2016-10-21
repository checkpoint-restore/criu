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

#ifdef __GNUG__
       extern "C" {
#endif

enum criu_service_comm {
	CRIU_COMM_SK,
	CRIU_COMM_FD,
	CRIU_COMM_BIN
};

enum criu_cg_mode {
	CRIU_CG_MODE_IGNORE,
	CRIU_CG_MODE_NONE,
	CRIU_CG_MODE_PROPS,
	CRIU_CG_MODE_SOFT,
	CRIU_CG_MODE_FULL,
	CRIU_CG_MODE_STRICT,
	CRIU_CG_MODE_DEFAULT,
};

void criu_set_service_address(char *path);
void criu_set_service_fd(int fd);
void criu_set_service_binary(char *path);

/*
 * You can choose if you want libcriu to connect to service socket
 * by itself, use provided file descriptor or spawn swrk by itself
 */
void criu_set_service_comm(enum criu_service_comm);

/*
 * Set opts to defaults. _Must_ be called first before using any functions from
 * the list down below. 0 on success, -1 on fail.
 */
int criu_init_opts(void);

void criu_set_pid(int pid);
void criu_set_images_dir_fd(int fd); /* must be set for dump/restore */
void criu_set_parent_images(char *path);
void criu_set_work_dir_fd(int fd);
void criu_set_leave_running(bool leave_running);
void criu_set_ext_unix_sk(bool ext_unix_sk);
int criu_add_unix_sk(unsigned int inode);
void criu_set_tcp_established(bool tcp_established);
void criu_set_tcp_skip_in_flight(bool tcp_skip_in_flight);
void criu_set_evasive_devices(bool evasive_devices);
void criu_set_shell_job(bool shell_job);
void criu_set_file_locks(bool file_locks);
void criu_set_track_mem(bool track_mem);
void criu_set_auto_dedup(bool auto_dedup);
void criu_set_force_irmap(bool force_irmap);
void criu_set_link_remap(bool link_remap);
void criu_set_log_level(int log_level);
void criu_set_log_file(char *log_file);
void criu_set_cpu_cap(unsigned int cap);
void criu_set_root(char *root);
void criu_set_manage_cgroups(bool manage);
void criu_set_manage_cgroups_mode(enum criu_cg_mode mode);
void criu_set_freeze_cgroup(char *name);
void criu_set_timeout(unsigned int timeout);
void criu_set_auto_ext_mnt(bool val);
void criu_set_ext_sharing(bool val);
void criu_set_ext_masters(bool val);
int criu_set_exec_cmd(int argc, char *argv[]);
int criu_add_ext_mount(char *key, char *val);
int criu_add_veth_pair(char *in, char *out);
int criu_add_cg_root(char *ctrl, char *path);
int criu_add_enable_fs(char *fs);
int criu_add_skip_mnt(char *mnt);
void criu_set_ghost_limit(unsigned int limit);
int criu_add_irmap_path(char *path);
int criu_add_inherit_fd(int fd, char *key);
int criu_add_external(char *key);

/*
 * The criu_notify_arg_t na argument is an opaque
 * value that callbacks (cb-s) should pass into
 * criu_notify_xxx() calls to fetch arbitrary values
 * from notification. If the value is not available
 * some non-existing one is reported.
 */

typedef struct _CriuNotify *criu_notify_arg_t;
void criu_set_notify_cb(int (*cb)(char *action, criu_notify_arg_t na));

/* Get pid of root task. 0 if not available */
int criu_notify_pid(criu_notify_arg_t na);

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
 * Same as the list above, but lets you have your very own options
 * structure and lets you set individual options in it.
 */
typedef struct criu_opts criu_opts;

int criu_local_init_opts(criu_opts **opts);

void criu_local_set_service_address(criu_opts *opts, char *path);
void criu_local_set_service_fd(criu_opts *opts, int fd);
void criu_local_set_service_comm(criu_opts *opts, enum criu_service_comm);

void criu_local_set_service_fd(criu_opts *opts, int fd);

void criu_local_set_pid(criu_opts *opts, int pid);
void criu_local_set_images_dir_fd(criu_opts *opts, int fd); /* must be set for dump/restore */
void criu_local_set_parent_images(criu_opts *opts, char *path);
void criu_local_set_work_dir_fd(criu_opts *opts, int fd);
void criu_local_set_leave_running(criu_opts *opts, bool leave_running);
void criu_local_set_ext_unix_sk(criu_opts *opts, bool ext_unix_sk);
int criu_local_add_unix_sk(criu_opts *opts, unsigned int inode);
void criu_local_set_tcp_established(criu_opts *opts, bool tcp_established);
void criu_local_set_tcp_skip_in_flight(criu_opts *opts, bool tcp_skip_in_flight);
void criu_local_set_evasive_devices(criu_opts *opts, bool evasive_devices);
void criu_local_set_shell_job(criu_opts *opts, bool shell_job);
void criu_local_set_file_locks(criu_opts *opts, bool file_locks);
void criu_local_set_track_mem(criu_opts *opts, bool track_mem);
void criu_local_set_auto_dedup(criu_opts *opts, bool auto_dedup);
void criu_local_set_force_irmap(criu_opts *opts, bool force_irmap);
void criu_local_set_link_remap(criu_opts *opts, bool link_remap);
void criu_local_set_log_level(criu_opts *opts, int log_level);
void criu_local_set_log_file(criu_opts *opts, char *log_file);
void criu_local_set_cpu_cap(criu_opts *opts, unsigned int cap);
void criu_local_set_root(criu_opts *opts, char *root);
void criu_local_set_manage_cgroups(criu_opts *opts, bool manage);
void criu_local_set_manage_cgroups_mode(criu_opts *opts, enum criu_cg_mode mode);
void criu_local_set_freeze_cgroup(criu_opts *opts, char *name);
void criu_local_set_timeout(criu_opts *opts, unsigned int timeout);
void criu_local_set_auto_ext_mnt(criu_opts *opts, bool val);
void criu_local_set_ext_sharing(criu_opts *opts, bool val);
void criu_local_set_ext_masters(criu_opts *opts, bool val);
int criu_local_set_exec_cmd(criu_opts *opts, int argc, char *argv[]);
int criu_local_add_ext_mount(criu_opts *opts, char *key, char *val);
int criu_local_add_veth_pair(criu_opts *opts, char *in, char *out);
int criu_local_add_cg_root(criu_opts *opts, char *ctrl, char *path);
int criu_local_add_enable_fs(criu_opts *opts, char *fs);
int criu_local_add_skip_mnt(criu_opts *opts, char *mnt);
void criu_local_set_ghost_limit(criu_opts *opts, unsigned int limit);
int criu_local_add_irmap_path(criu_opts *opts, char *path);
int criu_local_add_cg_props(criu_opts *opts, char *stream);
int criu_local_add_cg_props_file(criu_opts *opts, char *path);
int criu_local_add_cg_dump_controller(criu_opts *opts, char *name);
int criu_local_add_inherit_fd(criu_opts *opts, int fd, char *key);
int criu_local_add_external(criu_opts *opts, char *key);

void criu_local_set_notify_cb(criu_opts *opts, int (*cb)(char *action, criu_notify_arg_t na));

int criu_local_check(criu_opts *opts);
int criu_local_dump(criu_opts *opts);
int criu_local_restore(criu_opts *opts);
int criu_local_restore_child(criu_opts *opts);
int criu_local_dump_iters(criu_opts *opts, int (*more)(criu_predump_info pi));

#ifdef __GNUG__
}
#endif

#endif /* __CRIU_LIB_H__ */
