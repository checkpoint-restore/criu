#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "cuda_inherited.h"
#include "cuda_plugin.h"
#include "cuda_device_map.h"
#include "cuda.pb-c.h"
#include "criu-log.h"
#include "image.h"
#include "kcmp.h"
#include "pstree.h"
#include "xmalloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/major.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

#define CUDA_INHERITED_FILES_VERSION  1
#define CUDA_INHERITED_FILES_MAX_SIZE (16 * 1024 * 1024)

struct nvidia_mapping {
	uint64_t start;
	uint64_t end;
	uint64_t pgoff;
	dev_t rdev;
	dev_t dev;
	ino_t ino;
};

/* A task's mappings of and descriptors on NVIDIA devices. */
struct nvidia_state {
	int pid;
	struct nvidia_mapping *maps;
	size_t nr_maps;
	int *fds;
	size_t nr_fds;
};

struct cuda_ancestor {
	struct nvidia_state state;
	struct cuda_ancestor *parent;
	bool loaded;
};

static unsigned int *nvidia_majors;
static size_t nr_nvidia_majors;

static struct nvidia_state *inherited;
static size_t nr_inherited;

static uint32_t *dumped_ids;
static size_t nr_dumped_ids;
static CudaInheritedFiles *restore_files;

static void nvidia_state_free(struct nvidia_state *state)
{
	free(state->maps);
	free(state->fds);
	memset(state, 0, sizeof(*state));
}

/* /proc/devices lists registrations for the same major together, without minor ranges. */
static int read_nvidia_majors(void)
{
	unsigned int previous_major = UINT_MAX;
	bool chr = false;
	char line[128];
	FILE *f;
	int ret = 0;

	f = fopen("/proc/devices", "r");
	if (!f) {
		pr_perror("Unable to open /proc/devices");
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned int major;
		char name[64];
		bool nvidia;

		if (!strncmp(line, "Character devices:", 18)) {
			chr = true;
			continue;
		}
		if (!strncmp(line, "Block devices:", 14))
			break;
		if (!chr || sscanf(line, "%u %63[^\n]", &major, name) != 2)
			continue;
		nvidia = !strcmp(name, "nvidia") || !strcmp(name, "nvidiactl") || !strncmp(name, "nvidia-", 7);
		if (major == previous_major) {
			/* Leave shared majors to CRIU, regardless of which driver registered first. */
			if (!nvidia && nr_nvidia_majors && nvidia_majors[nr_nvidia_majors - 1] == major)
				nr_nvidia_majors--;
			continue;
		}
		previous_major = major;
		if (!nvidia)
			continue;
		if (xrealloc_safe(&nvidia_majors, (nr_nvidia_majors + 1) * sizeof(*nvidia_majors))) {
			ret = -1;
			break;
		}
		nvidia_majors[nr_nvidia_majors++] = major;
	}
	if (ferror(f)) {
		pr_perror("Unable to read /proc/devices");
		ret = -1;
	}
	fclose(f);
	return ret;
}

static bool is_nvidia_device(const struct stat *st)
{
	if (!S_ISCHR(st->st_mode))
		return false;
	for (size_t i = 0; i < nr_nvidia_majors; i++)
		if (major(st->st_rdev) == nvidia_majors[i])
			return true;
	return false;
}

/*
 * Following map_files links needs a capability in the initial user namespace.
 * Try the pathname shown in maps from the reader's root and the task's root.
 * Only a matching device and inode can supply metadata for this range. Leave
 * unresolvable mappings to CRIU's normal map handling.
 */
static bool stat_map_path(int pid, char *name, dev_t dev, uint64_t ino, struct stat *st)
{
	char path[PATH_MAX];
	char *newline = strchr(name, '\n');

	if (!newline)
		return false;
	*newline = '\0';
	if (!stat(name, st) && st->st_dev == dev && st->st_ino == ino)
		return true;
	if (snprintf(path, sizeof(path), "/proc/%d/root%s", pid, name) >= sizeof(path))
		return false;
	return !stat(path, st) && st->st_dev == dev && st->st_ino == ino;
}

/*
 * Read a task's mappings of NVIDIA devices from /proc/pid/maps. The device is
 * read with stat() through /proc/pid/map_files, which resolves to the mapped
 * file even when the task's /dev is in another mount namespace.
 */
static int read_nvidia_mappings(struct nvidia_state *state)
{
	char path[PATH_MAX], line[PATH_MAX + 128];
	FILE *f;
	int ret = 0;

	snprintf(path, sizeof(path), "/proc/%d/maps", state->pid);
	f = fopen(path, "r");
	if (!f) {
		pr_perror("Unable to open %s", path);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		struct nvidia_mapping map = {};
		unsigned int dev_major, dev_minor;
		uint64_t ino;
		struct stat st;
		int file_off = 0;

		if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %*s %" SCNx64 " %x:%x %" SCNu64 " %n", &map.start, &map.end,
			   &map.pgoff, &dev_major, &dev_minor, &ino, &file_off) != 6)
			continue;
		/* Anonymous and special mappings ([heap], [vdso]...) have no device file. */
		if (!ino || !file_off || line[file_off] != '/')
			continue;
		snprintf(path, sizeof(path), "/proc/%d/map_files/%" PRIx64 "-%" PRIx64, state->pid, map.start,
			 map.end);
		if (stat(path, &st)) {
			if (errno == ENOENT)
				continue;
			if (errno != EPERM) {
				pr_perror("Unable to stat %s", path);
				ret = -1;
				break;
			}
			if (!stat_map_path(state->pid, line + file_off, makedev(dev_major, dev_minor), ino, &st))
				continue;
		}
		if (!is_nvidia_device(&st))
			continue;
		map.rdev = st.st_rdev;
		map.dev = st.st_dev;
		map.ino = st.st_ino;
		if (xrealloc_safe(&state->maps, (state->nr_maps + 1) * sizeof(*state->maps))) {
			ret = -1;
			break;
		}
		state->maps[state->nr_maps++] = map;
	}
	if (ferror(f)) {
		pr_perror("Unable to read /proc/%d/maps", state->pid);
		ret = -1;
	}
	fclose(f);
	return ret;
}

static int read_nvidia_fds(struct nvidia_state *state)
{
	char path[PATH_MAX];
	struct dirent *de;
	DIR *dir;
	int ret = 0;

	snprintf(path, sizeof(path), "/proc/%d/fd", state->pid);
	dir = opendir(path);
	if (!dir) {
		pr_perror("Unable to open %s", path);
		return -1;
	}
	for (;;) {
		struct stat st;
		char *end;
		long fd;

		errno = 0;
		de = readdir(dir);
		if (!de) {
			if (errno) {
				pr_perror("Unable to enumerate /proc/%d/fd", state->pid);
				ret = -1;
			}
			break;
		}
		fd = strtol(de->d_name, &end, 10);
		if (errno || *end || end == de->d_name || fd < 0 || fd > INT_MAX)
			continue;
		snprintf(path, sizeof(path), "/proc/%d/fd/%ld", state->pid, fd);
		if (stat(path, &st)) {
			if (errno == ENOENT)
				continue;
			pr_perror("Unable to stat %s", path);
			ret = -1;
			break;
		}
		if (!is_nvidia_device(&st))
			continue;
		if (xrealloc_safe(&state->fds, (state->nr_fds + 1) * sizeof(*state->fds))) {
			ret = -1;
			break;
		}
		state->fds[state->nr_fds++] = fd;
	}
	closedir(dir);
	return ret;
}

static int read_nvidia_state(int pid, struct nvidia_state *state)
{
	memset(state, 0, sizeof(*state));
	state->pid = pid;
	if (read_nvidia_mappings(state) || read_nvidia_fds(state)) {
		nvidia_state_free(state);
		return -1;
	}
	return 0;
}

/* Return 1 for the same open file, 0 for different files, or an error. */
static int same_file(int pid1, int fd1, int pid2, int fd2)
{
	int ret = syscall(SYS_kcmp, pid1, pid2, KCMP_FILE, fd1, fd2);

	if (ret < 0) {
		pr_perror("Cannot compare fd %d of pid %d with fd %d of pid %d", fd1, pid1, fd2, pid2);
		return -1;
	}
	return ret == 0;
}

static void explain_not_inherited(void)
{
	pr_err("If a previous dump checkpointed and resumed the CUDA ancestor, "
	       "its files and mappings may have changed\n");
}

/*
 * A copy made by fork() is at the same address and offset of the same device
 * file as the parent's mapping, and a descriptor copied by fork() is the same
 * open file as the parent's. A match cannot tell how the task acquired it.
 */
static int check_inherited(const struct nvidia_state *task, struct cuda_ancestor *ancestor)
{
	struct cuda_ancestor *a;

	for (a = ancestor; a; a = a->parent) {
		if (!a->loaded) {
			if (read_nvidia_state(a->state.pid, &a->state))
				return -1;
			a->loaded = true;
		}
	}

	for (size_t m = 0; m < task->nr_maps; m++) {
		const struct nvidia_mapping *map = &task->maps[m];
		bool found = false;

		for (a = ancestor; a && !found; a = a->parent) {
			for (size_t i = 0; i < a->state.nr_maps; i++) {
				const struct nvidia_mapping *a_map = &a->state.maps[i];

				if (a_map->start == map->start && a_map->end == map->end &&
				    a_map->pgoff == map->pgoff && a_map->rdev == map->rdev &&
				    a_map->dev == map->dev && a_map->ino == map->ino) {
					found = true;
					break;
				}
			}
		}
		if (!found) {
			pr_err("Task %d maps NVIDIA device %u:%u at %" PRIx64 "-%" PRIx64
			       " without CUDA state, and no CUDA ancestor maps it there\n",
			       task->pid, major(map->rdev), minor(map->rdev), map->start, map->end);
			explain_not_inherited();
			return -1;
		}
	}

	for (size_t f = 0; f < task->nr_fds; f++) {
		bool found = false;

		for (a = ancestor; a && !found; a = a->parent) {
			for (size_t i = 0; i < a->state.nr_fds; i++) {
				int ret = same_file(task->pid, task->fds[f], a->state.pid, a->state.fds[i]);

				if (ret < 0)
					return -1;
				if (ret) {
					found = true;
					break;
				}
			}
		}
		if (!found) {
			pr_err("Task %d has descriptor %d open on an NVIDIA device without CUDA state, "
			       "and it is not a CUDA ancestor's open file\n",
			       task->pid, task->fds[f]);
			explain_not_inherited();
			return -1;
		}
	}

	return 0;
}

static int scan_inherited_task(int pid, struct cuda_ancestor *ancestor)
{
	struct nvidia_state state;

	if (read_nvidia_state(pid, &state))
		return -1;
	if (!state.nr_maps && !state.nr_fds)
		return 0;

	if (check_inherited(&state, ancestor))
		goto err;
	if (xrealloc_safe(&inherited, (nr_inherited + 1) * sizeof(*inherited)))
		goto err;
	inherited[nr_inherited++] = state;
	pr_info("Task %d shares %zu NVIDIA mappings and %zu descriptors with a CUDA ancestor\n",
		pid, state.nr_maps, state.nr_fds);
	return 0;

err:
	nvidia_state_free(&state);
	return -1;
}

/*
 * PAUSE_DEVICES runs before seizure. Only the collected tree tells us which
 * tasks survived it and which CUDA tasks are ancestors of each live task.
 */
static int scan_subtree(struct pstree_item *item, struct cuda_ancestor *ancestor, bool (*is_cuda_task)(int pid))
{
	struct cuda_ancestor here = { .state.pid = item->pid->real, .parent = ancestor };
	struct pstree_item *subtask;
	int ret = 0;

	if (task_alive(item)) {
		if (is_cuda_task(item->pid->real))
			ancestor = &here;
		else if (ancestor && scan_inherited_task(item->pid->real, ancestor))
			return -1;
	}

	list_for_each_entry(subtask, &item->children, sibling) {
		ret = scan_subtree(subtask, ancestor, is_cuda_task);
		if (ret)
			break;
	}
	nvidia_state_free(&here.state);
	return ret;
}

int cuda_inherited_scan(bool (*is_cuda_task)(int pid), bool discard)
{
	if (read_nvidia_majors())
		return -1;
	if (!nr_nvidia_majors) {
		pr_warn("No NVIDIA character devices are registered; skipping inherited NVIDIA state\n");
		return 0;
	}

	if (scan_subtree(root_item, NULL, is_cuda_task))
		return -1;
	if (nr_inherited && !discard) {
		pr_err("Task %d holds NVIDIA state matching a CUDA ancestor. To omit its mappings and reopen "
		       "its descriptors on /dev/null, use --plugin-option=%s=discard\n",
		       inherited[0].pid, CUDA_PLUGIN_FORK_OPTION);
		return -1;
	}
	return 0;
}

bool cuda_inherited_omit_vma(int pid, uint64_t start, uint64_t end, const struct stat *st)
{
	for (size_t i = 0; i < nr_inherited; i++) {
		if (inherited[i].pid != pid)
			continue;
		for (size_t m = 0; m < inherited[i].nr_maps; m++) {
			const struct nvidia_mapping *map = &inherited[i].maps[m];

			if (map->start == start && map->end == end && map->rdev == st->st_rdev &&
			    map->dev == st->st_dev && map->ino == st->st_ino)
				return true;
		}
	}
	return false;
}

int cuda_inherited_dump_files(void)
{
	CudaInheritedFiles files = CUDA_INHERITED_FILES__INIT;
	uint8_t *data;
	size_t size;
	int fd, ret;

	if (!nr_dumped_ids)
		return cuda_remove_image(CUDA_INHERITED_FILES_IMAGE);

	files.has_version = true;
	files.version = CUDA_INHERITED_FILES_VERSION;
	files.n_ids = nr_dumped_ids;
	files.ids = dumped_ids;

	size = cuda_inherited_files__get_packed_size(&files);
	if (size > CUDA_INHERITED_FILES_MAX_SIZE) {
		pr_err("Invalid %s size %zu\n", CUDA_INHERITED_FILES_IMAGE, size);
		return -E2BIG;
	}
	data = malloc(size);
	if (!data)
		return -ENOMEM;
	cuda_inherited_files__pack(&files, data);

	fd = cuda_open_image(CUDA_INHERITED_FILES_IMAGE, true, &size);
	if (fd < 0) {
		free(data);
		return fd;
	}
	ret = cuda_img_write(fd, data, size);
	if (ret)
		pr_err("Unable to write %s: %s\n", CUDA_INHERITED_FILES_IMAGE, strerror(-ret));
	if (close(fd) && !ret) {
		ret = -errno;
		pr_perror("Unable to close %s", CUDA_INHERITED_FILES_IMAGE);
	}
	free(data);
	if (!ret && add_inventory_plugin(CUDA_PLUGIN_INHERITED_FILES)) {
		pr_err("Unable to add %s to the image inventory\n", CUDA_PLUGIN_INHERITED_FILES);
		return -1;
	}
	return ret;
}

int cuda_inherited_dump_file(int fd, int id)
{
	uint32_t *ids;

	for (size_t i = 0; i < nr_inherited; i++) {
		for (size_t f = 0; f < inherited[i].nr_fds; f++) {
			int ret = same_file(getpid(), fd, inherited[i].pid, inherited[i].fds[f]);

			if (ret < 0)
				return -1;
			if (!ret)
				continue;

			ids = realloc(dumped_ids, (nr_dumped_ids + 1) * sizeof(*ids));
			if (!ids)
				return -ENOMEM;
			dumped_ids = ids;
			dumped_ids[nr_dumped_ids++] = id;
			pr_info("Descriptor %d of task %d (file id %#x) is inherited NVIDIA state; it is restored on /dev/null\n",
				inherited[i].fds[f], inherited[i].pid, id);
			return 0;
		}
	}
	return -ENOTSUP;
}

int cuda_inherited_restore_init(void)
{
	CudaInheritedFiles *files;
	uint8_t *data;
	size_t size = 0;
	int fd, ret;

	fd = cuda_open_image(CUDA_INHERITED_FILES_IMAGE, false, &size);
	if (fd == -ENOENT)
		pr_err("Missing required %s\n", CUDA_INHERITED_FILES_IMAGE);
	if (fd < 0)
		return fd;
	if (!size || size > CUDA_INHERITED_FILES_MAX_SIZE) {
		pr_err("Invalid %s size %zu\n", CUDA_INHERITED_FILES_IMAGE, size);
		close(fd);
		return -EINVAL;
	}
	data = malloc(size);
	if (!data) {
		close(fd);
		return -ENOMEM;
	}
	ret = cuda_img_read(fd, data, size);
	if (!ret)
		ret = cuda_img_at_eof(fd);
	if (close(fd) && !ret)
		ret = -errno;
	if (ret) {
		pr_err("Unable to read %s: %d\n", CUDA_INHERITED_FILES_IMAGE, ret);
		free(data);
		return ret;
	}

	files = cuda_inherited_files__unpack(NULL, size, data);
	free(data);
	if (!files) {
		pr_err("Unable to unpack %s\n", CUDA_INHERITED_FILES_IMAGE);
		return -EINVAL;
	}
	if (files->version != CUDA_INHERITED_FILES_VERSION) {
		pr_err("Unsupported %s version %u\n", CUDA_INHERITED_FILES_IMAGE, files->version);
		cuda_inherited_files__free_unpacked(files, NULL);
		return -EINVAL;
	}
	if (!files->n_ids) {
		pr_err("No file IDs in required %s\n", CUDA_INHERITED_FILES_IMAGE);
		cuda_inherited_files__free_unpacked(files, NULL);
		return -EINVAL;
	}
	restore_files = files;
	return 0;
}

int cuda_inherited_restore_file(int id)
{
	struct stat st;
	int fd;

	if (!restore_files)
		return -ENOTSUP;
	for (size_t i = 0; i < restore_files->n_ids; i++) {
		if (restore_files->ids[i] != (uint32_t)id)
			continue;
		/*
		 * Keep the descriptor number occupied after discarding the NVIDIA
		 * file. Open nonblocking until we have verified the device.
		 */
		fd = open("/dev/null", O_RDWR | O_NONBLOCK | O_NOCTTY);
		if (fd < 0) {
			pr_perror("Unable to open /dev/null for inherited NVIDIA descriptor %#x", id);
			return -1;
		}
		if (fstat(fd, &st)) {
			pr_perror("Unable to stat /dev/null");
			goto err;
		}
		if (!S_ISCHR(st.st_mode) || st.st_rdev != makedev(MEM_MAJOR, 3)) {
			pr_err("/dev/null is not the null character device\n");
			goto err;
		}
		if (fcntl(fd, F_SETFL, 0) < 0) {
			pr_perror("Unable to clear O_NONBLOCK on /dev/null");
			goto err;
		}
		return fd;
	}
	return -ENOTSUP;

err:
	close(fd);
	return -1;
}

void cuda_inherited_fini(void)
{
	for (size_t i = 0; i < nr_inherited; i++)
		nvidia_state_free(&inherited[i]);
	free(inherited);
	inherited = NULL;
	nr_inherited = 0;
	free(dumped_ids);
	dumped_ids = NULL;
	nr_dumped_ids = 0;
	if (restore_files)
		cuda_inherited_files__free_unpacked(restore_files, NULL);
	restore_files = NULL;
	free(nvidia_majors);
	nvidia_majors = NULL;
	nr_nvidia_majors = 0;
}
