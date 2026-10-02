/* This file contains dummy functions to make the unittest compile */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "compel/infect-util.h"

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

/* Used by seize.o, whose checkpoint_devices() unit.c tests */
bool alarm_timeouted(void)
{
	return false;
}

void *__alloc_pstree_item(bool rst)
{
	return NULL;
}

bool has_children(void *item)
{
	return false;
}

int pstree_alloc_cores(void *item)
{
	return -1;
}

int parse_children(pid_t pid, pid_t **_c, int *_n)
{
	return -1;
}

int parse_threads(int pid, void **_t, int *_n)
{
	return -1;
}

int seccomp_collect_entry(pid_t tid_real, unsigned int mode)
{
	return -1;
}

void timing_start(int t)
{
}

void timing_stop(int t)
{
}

int compel_interrupt_task(int pid)
{
	return -1;
}

int compel_parse_stop_signo(int pid)
{
	return -1;
}

int compel_resume_task_sig(pid_t pid, int orig_state, int state, int stop_signo)
{
	return -1;
}

int compel_wait_task(int pid, int ppid, void *get_status, void *free_status, void *ss, void *data)
{
	return -1;
}
