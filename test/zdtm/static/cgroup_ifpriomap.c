#include <fcntl.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>

#include "zdtmtst.h"

const char *test_doc	= "Check preserving multiline cgroup controller's property net_prio/net_prio.ifpriomap";
const char *test_author	= "Dmitry Safonov <dsafonov@virtuozzo.com>";

char *dirname;
TEST_OPTION(dirname, string, "cgroup directory name", 1);

static const char *cgname = "zdtmtst";

#define BUF_SZ		1024
#define PRIOMAPS_SZ	40

struct ifpriomap_t {
	char		*ifname;
	uint32_t	prio;
};
struct ifpriomap_t maps[PRIOMAPS_SZ], new_maps[PRIOMAPS_SZ];

static int mount_cg(const char *controller)
{
	char mnt_point[BUF_SZ], subdir[BUF_SZ];
	char tasks_path[BUF_SZ], pid_str[BUF_SZ];
	int fd;

	sprintf(mnt_point, "%s/%s", dirname, controller);
	sprintf(subdir, "%s/%s/%s", dirname, controller, cgname);
	sprintf(pid_str, "%d", getpid());
	sprintf(tasks_path, "%s/%s/%s/tasks", dirname, controller, cgname);

	if (mkdir(dirname, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir");
		return -1;
	}
	if (mkdir(mnt_point, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir `%s'", mnt_point);
		return -1;
	}
	if (mount("none", mnt_point, "cgroup", 0, controller)) {
		pr_perror("Can't mount `%s' cgroup", controller);
		goto err_rm;
	}
	if (mkdir(subdir, 0700) < 0 && errno != EEXIST) {
		pr_perror("Can't make dir `%s'", subdir);
		goto err_umount;
	}

	/* Add self to newly created cgroup */
	fd = open(tasks_path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Failed to open `%s'", tasks_path);
		goto err_controller;
	}
	if (write(fd, pid_str, strlen(pid_str)) != strlen(pid_str)) {
		pr_perror("failed to write `%s' to `%s'", pid_str, tasks_path);
		close(fd);
		goto err_controller;
	}

	close(fd);
	return 0;

err_controller:
	rmdir(subdir);
err_umount:
	umount(mnt_point);
err_rm:
	rmdir(mnt_point);
	return -1;
}

static int umount_cg(const char *controller)
{
	char mnt_point[BUF_SZ], subdir[BUF_SZ];

	sprintf(mnt_point, "%s/%s", dirname, controller);
	sprintf(subdir, "%s/%s/%s", dirname, controller, cgname);

	rmdir(subdir);

	return umount(mnt_point);
}

static int read_one_priomap(char *prop_line, struct ifpriomap_t *out)
{
	char *space;
	size_t len;

	space = strchr(prop_line, ' ');
	if (!space) {
		pr_err("Broken ifpriomap file line: `%s'\n", prop_line);
		return -1;
	}
	len = space - prop_line;

	out->ifname = malloc(len + 1);
	if (!out->ifname) {
		pr_perror("malloc() failed\n");
		return -1;
	}

	strncpy(out->ifname, prop_line, len);
	out->ifname[len] = '\0'; /* poor man's strlcpy() */
	out->prio = (uint32_t)strtol(space + 1, NULL, 10);

	return 0;
}

static int read_map(const char *path, struct ifpriomap_t *out, size_t out_sz)
{
	char buf[BUF_SZ];
	FILE *fpriomap;
	size_t i;

	fpriomap = fopen(path, "r");
	if (!fpriomap) {
		pr_perror("Failed to open `%s'", path);
		return -1;
	}

	for (i = 0; i < out_sz; i++) {
		if (!fgets(buf, BUF_SZ, fpriomap))
			break;

		if (read_one_priomap(buf, &out[i])) {
			fclose(fpriomap);
			return -1;
		}
	}

	if (fclose(fpriomap)) {
		pr_perror("Failed to close `%s'", path);
		return -1;
	}

	return 0;
}

static int write_map(const char *path, struct ifpriomap_t *out, size_t out_sz)
{
	char buf[BUF_SZ];
	ssize_t written;
	size_t i;
	int fd;

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		pr_perror("Failed to open `%s'", path);
		return -1;
	}

	for (i = 0; i < out_sz; i++) {
		struct ifpriomap_t *p = &out[i];

		if (!p->ifname)
			break;

		snprintf(buf, BUF_SZ, "%s %lu",
			p->ifname, (unsigned long)p->prio);

		written = write(fd, buf, strlen(buf));
		if (written < 0) {
			pr_perror("Failed to write `%s' to `%s'", buf, path);
			close(fd);
			return -1;
		}
	}

	if (close(fd)) {
		pr_perror("Failed to close `%s'", path);
		return -1;
	}

	return 0;
}

static void randomize_map(struct ifpriomap_t *out, size_t out_sz)
{
	size_t i;

	for (i = 0; i < out_sz; i++) {
		struct ifpriomap_t *p = &out[i];

		if (!p->ifname)
			return;

		p->prio += rand();
	}
}

static int compare_maps(void)
{
	size_t i, j;

	for (i = 0; i < PRIOMAPS_SZ; i++) {
		struct ifpriomap_t *a = &maps[i];

		if (!a->ifname)
			return 0;

		for (j = 0; j < PRIOMAPS_SZ; j++) {
			struct ifpriomap_t *b = &new_maps[j];

			if (!b->ifname)
				break;

			if (strcmp(a->ifname, b->ifname) == 0) {
				if (a->prio != b->prio) {
					pr_err("`%s' prio: %lu != %lu\n",
						a->ifname,
						(unsigned long)a->prio,
						(unsigned long)b->prio);
					return -1;
				}
			}
		}
	}

	return 0;
}

static ssize_t parse_cgroup_line(FILE *fcgroup, size_t *buf_sz, char **buf)
{
	ssize_t line_sz;

	/* Reading cgroup mount nr */
	errno = 0;
	line_sz = getdelim(buf, buf_sz, ':', fcgroup);
	if (errno) {
		pr_perror("failed to read from file");
		return -1;
	}

	if (line_sz == -1) /* EOF */
		return 0;

	/* Reading mounted controller name */
	errno = 0;
	line_sz = getdelim(buf, buf_sz, ':', fcgroup);
	if (line_sz == -1) { /* no EOF here */
		pr_perror("failed to read from file");
		return -1;
	}

	/*
	 * Reading the rest of the line.
	 * It's zdtm's test, no need to optimize = use fgetc()
	 */
	do {
		int c = fgetc(fcgroup);

		if (c == '\n' || c == EOF)
			break;
	} while (true);

	return line_sz;
}

/*
 * Controller's name may differ depending on the kernel's config:
 * `net_prio' if only CONFIG_CGROUP_NET_PRIO is set
 * `net_cls,net_prio' if also CONFIG_CGROUP_NET_CLASSID is set
 */
static int get_controller_name(char **name)
{
	FILE *self_cgroup = fopen("/proc/self/cgroup", "r");
	size_t buf_sz = 0;
	int ret = -1;

	*name = NULL;
	if (!self_cgroup) {
		pr_perror("failed to open self/cgroup");
		return -1;
	}

	do {
		ssize_t len = parse_cgroup_line(self_cgroup, &buf_sz, name);

		if (len < 0) {
			free(*name);
			goto out_close;
		}

		if (len == 0) /* EOF */
			break;

		if (strstr(*name, "net_prio")) {
			/* erasing ':' delimiter */
			(*name)[len-1] = '\0';
			ret = 0;
			goto out_close;
		}
	} while(1);

	/* self/cgroup has no mount for net_prio - try to map it */
	*name = "net_prio";
	ret = 0;

out_close:
	fclose(self_cgroup);
	return ret;
}

int main(int argc, char **argv)
{
	char subdir[PATH_MAX];
	char path[PATH_MAX];
	int ret = -1;
	char *controller_name;

	srand(time(NULL));

	test_init(argc, argv);

	if (get_controller_name(&controller_name))
		return -1;

	if (mount_cg(controller_name) < 0)
		return -1;

	sprintf(path, "%s/%s/%s/net_prio.ifpriomap",
		dirname, controller_name, cgname);

	if (read_map(path, maps, PRIOMAPS_SZ))
		goto out_umount;

	randomize_map(maps, PRIOMAPS_SZ);

	if (write_map(path, maps, PRIOMAPS_SZ))
		goto out_umount;

	test_daemon();
	test_waitsig();

	if (read_map(path, new_maps, PRIOMAPS_SZ)) {
		fail("Can't read ifpriomap after C/R");
		goto out_umount;
	}

	if (!compare_maps()) {
		ret = 0;
		pass();
	} else {
		fail("ifpriomap differs before/after C/R");
	}

out_umount:
	sprintf(subdir, "%s/%s/%s", dirname, "net_prio", cgname);
	rmdir(subdir);
	umount_cg("net_prio");
	free(controller_name);

	return ret;
}
