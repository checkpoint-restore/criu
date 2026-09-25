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

typedef struct VmaEntry VmaEntry;
struct VmaEntry {};
void vma_entry__init(VmaEntry *message)
{
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
