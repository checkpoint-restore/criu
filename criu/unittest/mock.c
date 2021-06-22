/* This file contains dummy functions to make the unittest compile */

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

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

int get_service_fd(int type)
{
	return -1;
}

void *shmalloc(size_t bytes)
{
	return malloc(bytes);
}

int install_service_fd(int type, int fd)
{
	return 0;
}

int close_service_fd(int type)
{
	return 0;
}

void compel_log_init(int log_fn, unsigned int level)
{
}
