/* This file contains dummy functions to make the unittest compile */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "servicefd.h"
#include "compel/infect-util.h"
#include "images/inventory.pb-c.h"

static int image_dir_fd = -1;

int add_external(char *key)
{
	return 0;
}

int irmap_scan_path_add(char *path)
{
	return 0;
}

bool add_fsname_auto(const char *names)
{
	return true;
}

bool add_skip_mount(const char *mountpoint)
{
	return true;
}

int check_add_feature(char *feat)
{
	return 0;
}

int inherit_fd_parse(char *optarg)
{
	return 0;
}

int new_cg_root_add(char *controller, char *newroot)
{
	return 0;
}

int add_script(char *path)
{
	return 0;
}

int veth_pair_add(char *in, char *out)
{
	return 0;
}

int unix_sk_ids_parse(char *optarg)
{
	return 0;
}

bool cgp_add_dump_controller(const char *name)
{
	return 0;
}

int join_ns_add(const char *type, char *ns_file, char *extra_opts)
{
	return 0;
}

int ext_mount_add(char *key, char *val)
{
	return 0;
}

int check_namespace_opts(void)
{
	return 0;
}

int get_service_fd(enum sfd_type type)
{
	return type == IMG_FD_OFF ? image_dir_fd : -1;
}

void *shmalloc(size_t bytes)
{
	return malloc(bytes);
}

int install_service_fd(enum sfd_type type, int fd)
{
	if (type != IMG_FD_OFF)
		return 0;
	close_service_fd(type);
	image_dir_fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	return image_dir_fd;
}

int close_service_fd(enum sfd_type type)
{
	if (type == IMG_FD_OFF && image_dir_fd >= 0) {
		close(image_dir_fd);
		image_dir_fd = -1;
	}
	return 0;
}

void compel_log_init(int log_fn, unsigned int level)
{
}

void set_cr_errno(int new_err)
{
}

struct ns_desc {};
struct ns_desc user_ns_desc;
int switch_ns(int pid, struct ns_desc *nd, int *rst)
{
	return -1;
}

enum script_actions { ACT_FAKE };
int run_scripts(enum script_actions act)
{
	return -1;
}

int clone_noasan(int (*fn)(void *), int flags, void *arg)
{
	return -1;
}

struct kerndat_s {
	unsigned int sysctl_nr_open;
};
struct kerndat_s kdat = {};

int service_fd_rlim_cur;

unsigned __page_size;

int check_mount_v2(void)
{
	return 0;
}

char compel_run_id[RUN_ID_HASH_LENGTH];

int pread_full(int fd, void *buf, size_t count, off_t offset)
{
	return -1;
}

/*
 * These helpers are linked by the image and protobuf code used by the
 * remote-parent unit tests. The tests do not exercise their subsystems.
 */
int parse_uptime(uint64_t *upt)
{
	return -1;
}

Lsmtype host_lsm_type(void)
{
	return LSMTYPE__NO_LSM;
}

struct pstree_item;
int get_task_ids(struct pstree_item *item)
{
	return -1;
}

struct parasite_dump_cgroup_args;
int dump_thread_cgroup(const struct pstree_item *item, uint32_t *cg_set,
		       struct parasite_dump_cgroup_args *args, int id)
{
	return -1;
}

int img_streamer_open(char *filename, int flags)
{
	return -1;
}

int img_streamer_init(const char *image_dir, int mode)
{
	return -1;
}

void img_streamer_finish(void)
{
}

unsigned long root_ns_mask;

typedef int (*uns_call_t)(void *arg, int fd, pid_t pid);
int __userns_call(const char *func_name, uns_call_t call, int flags, void *arg,
		  size_t arg_size, int fd)
{
	return -1;
}

void shfree_last(void *ptr)
{
	free(ptr);
}
