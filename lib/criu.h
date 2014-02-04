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

void criu_set_service_address(char *path);

/*
 * Set opts to defaults. _Must_ be called first before using any functions from
 * the list down below. 0 on success, -1 on fail.
 */
int criu_init_opts(void);

void criu_set_pid(int pid);
void criu_set_images_dir_fd(int fd); /* must be set for dump/restore */
void criu_set_work_dir_fd(int fd);
void criu_set_leave_running(bool leave_running);
void criu_set_ext_unix_sk(bool ext_unix_sk);
void criu_set_tcp_established(bool tcp_established);
void criu_set_evasive_devices(bool evasive_devices);
void criu_set_shell_job(bool shell_job);
void criu_set_file_locks(bool file_locks);
void criu_set_log_level(int log_level);
void criu_set_log_file(char *log_file);

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

#endif /* __CRIU_LIB_H__ */
