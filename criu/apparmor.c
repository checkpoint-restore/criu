#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ftw.h>

#include "common/config.h"
#include "imgset.h"
#include "pstree.h"
#include "util.h"
#include "string.h"
#include "lsm.h"
#include "cr_options.h"
#include "kerndat.h"

#include "protobuf.h"
#include "images/inventory.pb-c.h"
#include "images/apparmor.pb-c.h"

/*
 * Apparmor stacked profile checkpoint restore. Previously, we just saved the
 * profile that was in use by the task, and we expected it to be present on the
 * target host. Now with stacking, containers are able to load their own
 * profiles, so we can't rely on this.
 *
 * The basic idea here is that there is some (collection) of (potentially
 * nested) namespaces that a container uses. We don't collect everything on the
 * host level, but we *do* collect everything inside the namespace; a container
 * could have loaded a profile but not yet used it when we start to checkpoint.
 *
 * Thus, the old code that saves and restores AA profiles is still relevant, we
 * just need to add the new code in this file to walk the namespace and dump
 * any blobs in that AA namespace, and then restore these blobs on restore so
 * that the profiles the old code tries to use are actualy present.
 */

static AaNamespace **namespaces = NULL;
static int n_namespaces = 0;

static AaNamespace *new_namespace(char *name, AaNamespace *parent)
{
	void *m;
	AaNamespace *ret;

	ret = xmalloc(sizeof(*ret));
	if (!ret)
		return NULL;
	aa_namespace__init(ret);

	ret->name = xstrdup(name);
	if (!ret->name) {
		xfree(ret);
		return NULL;
	}

	if (parent) {
		m = xrealloc(parent->namespaces, sizeof(*parent->namespaces) * (parent->n_namespaces + 1));
		if (!m) {
			xfree(ret->name);
			xfree(ret);
			return NULL;
		}

		parent->namespaces = m;
		parent->namespaces[parent->n_namespaces++] = ret;
	}

	m = xrealloc(namespaces, sizeof(*namespaces) * (n_namespaces + 1));
	if (!m) {
		if (parent)
			parent->n_namespaces--;

		xfree(ret->name);
		xfree(ret);
		return NULL;
	}

	namespaces = m;
	namespaces[n_namespaces++] = ret;

	return ret;
}

static int collect_profile(char *path, int offset, char *dir, AaNamespace *ns)
{
	AaPolicy *cur;
	int fd, my_offset, ret;
	struct stat sb;
	ssize_t n;
	void *m;
	FILE *f;

	my_offset = snprintf(path + offset, PATH_MAX - offset, "%s/", dir);
	if (my_offset < 0 || my_offset >= PATH_MAX - offset) {
		pr_err("snprintf failed\n");
		return -1;
	}
	my_offset += offset;

	pr_info("dumping profile %s\n", path);

	cur = xmalloc(sizeof(*cur));
	if (!cur)
		return -1;
	aa_policy__init(cur);

	strlcat(path + my_offset, "name", PATH_MAX - my_offset);
	f = fopen(path, "r");
	if (!f) {
		xfree(cur);
		pr_perror("failed to open %s", path);
		return -1;
	}

	ret = fscanf(f, "%ms", &cur->name);
	fclose(f);
	if (ret != 1) {
		xfree(cur);
		pr_perror("couldn't scanf %s", path);
		return -1;
	}

	strlcpy(path + my_offset, "raw_data", PATH_MAX - my_offset);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		pr_perror("failed to open aa policy %s", path);
		goto err;
	}

	if (fstat(fd, &sb) < 0) {
		pr_perror("failed to stat %s", path);
		goto close;
	}

	cur->blob.len = sb.st_size;
	cur->blob.data = xmalloc(sb.st_size);
	if (!cur->blob.data)
		goto close;

	n = read(fd, cur->blob.data, sb.st_size);
	if (n < 0) {
		pr_perror("failed to read %s", path);
		goto close;
	}

	if (n != sb.st_size) {
		pr_err("didn't read all of %s\n", path);
		goto close;
	}

	close(fd);

	m = xrealloc(ns->policies, sizeof(*ns->policies) * (ns->n_policies + 1));
	if (!m)
		goto err;
	ns->policies = m;
	ns->policies[ns->n_policies++] = cur;

	return 0;

close:
	close(fd);

err:
	xfree(cur->name);
	xfree(cur);
	return -1;
}

char *ns_path;
int sort_err;

static int no_dirdots(const struct dirent *de)
{
	return !dir_dots(de);
}

static int by_time(const struct dirent **de1, const struct dirent **de2)
{
	char path[PATH_MAX];
	struct stat sb1, sb2;

	snprintf(path, sizeof(path), "%s/%s", ns_path, (*de1)->d_name);
	if (stat(path, &sb1) < 0) {
		pr_perror("couldn't stat %s", path);
		sort_err = errno;
		return 0;
	}

	snprintf(path, sizeof(path), "%s/%s", ns_path, (*de2)->d_name);
	if (stat(path, &sb2) < 0) {
		pr_perror("couldn't state %s", path);
		sort_err = errno;
		return 0;
	}

	if (sb1.st_mtim.tv_sec == sb2.st_mtim.tv_sec) {
		if (sb1.st_mtim.tv_nsec < sb2.st_mtim.tv_nsec)
			return -1;
		if (sb1.st_mtim.tv_nsec == sb2.st_mtim.tv_nsec)
			return 0;
		return 1;
	} else {
		if (sb1.st_mtim.tv_sec < sb2.st_mtim.tv_sec)
			return -1;
		if (sb1.st_mtim.tv_sec == sb2.st_mtim.tv_sec)
			return 0;
		return 1;
	}
}

static int walk_namespace(char *path, size_t offset, AaNamespace *ns)
{
	DIR *dir = NULL;
	struct dirent *de, **namelist = NULL;
	int ret = -1, n_names = 0, i;
	size_t my_offset;

	/* collect all the child namespaces */
	strcat(path, "/namespaces/");
	my_offset = offset + 12;

	dir = opendir(path);
	if (!dir)
		goto out;

	while ((de = readdir(dir))) {
		AaNamespace *cur;

		if (dir_dots(de))
			continue;

		path[my_offset] = '\0';
		strcat(path, de->d_name);

		cur = new_namespace(de->d_name, ns);
		if (!cur)
			goto out;

		if (walk_namespace(path, my_offset + strlen(de->d_name), cur) < 0) {
			aa_namespace__free_unpacked(cur, NULL);
			ns->n_namespaces--;
			goto out;
		}
	}

	closedir(dir);
	dir = NULL;

	/* now collect the profiles for this namespace */
	path[offset] = '\0';
	strcat(path, "/profiles/");
	my_offset = offset + 10;

	sort_err = 0;
	ns_path = path;
	n_names = scandir(path, &namelist, no_dirdots, by_time);
	if (n_names < 0 || sort_err != 0) {
		pr_perror("scandir failed");
		goto out;
	}

	for (i = 0; i < n_names; i++) {
		de = namelist[i];

		path[my_offset] = 0;
		if (collect_profile(path, my_offset, de->d_name, ns) < 0)
			goto out;
	}

	ret = 0;
out:
	if (dir)
		closedir(dir);

	if (namelist) {
		for (i = 0; i < n_names; i++)
			xfree(namelist[i]);
		xfree(namelist);
	}

	return ret;
}

int collect_aa_namespace(char *profile)
{
	char path[PATH_MAX], *namespace, *end;
	int ret, i;
	AaNamespace *ns;

	if (!profile)
		return 0;

	namespace = strchr(profile, ':');
	if (!namespace)
		return 0; /* no namespace to dump */
	namespace ++;

	if (!kdat.apparmor_ns_dumping_enabled) {
		pr_warn("Apparmor namespace present but dumping not enabled\n");
		return 0;
	}

	/* XXX: this is not strictly correct; if something is using namespace
	 * views, extra //s can indicate a namespace separation. However, I
	 * think only the apparmor developers use this feature :)
	 */
	end = strchr(namespace, ':');
	if (!end) {
		pr_err("couldn't find AA namespace end in: %s\n", namespace);
		return -1;
	}

	*end = '\0';

	for (i = 0; i < n_namespaces; i++) {
		/* did we already dump this namespace? */
		if (!strcmp(namespaces[i]->name, namespace)) {
			*end = ':';
			return 0;
		}
	}

	pr_info("dumping AA namespace %s\n", namespace);

	ns = new_namespace(namespace, NULL);
	*end = ':';
	if (!ns)
		return -1;

	ret = snprintf(path, sizeof(path), AA_SECURITYFS_PATH "/policy/namespaces/%s", ns->name);
	if (ret < 0 || ret >= sizeof(path)) {
		pr_err("snprintf failed?\n");
		goto err;
	}

	if (walk_namespace(path, ret, ns) < 0) {
		pr_err("walking AA namespace %s failed\n", ns->name);
		goto err;
	}

	return 0;

err:
	aa_namespace__free_unpacked(ns, NULL);
	n_namespaces--;
	return -1;
}

int dump_aa_namespaces(void)
{
	ApparmorEntry *ae = NULL;
	int ret;

	if (n_namespaces == 0)
		return 0;

	ae = xmalloc(sizeof(*ae));
	if (!ae)
		return -1;
	apparmor_entry__init(ae);

	ae->n_namespaces = n_namespaces;
	ae->namespaces = namespaces;

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_APPARMOR), ae, PB_APPARMOR);

	apparmor_entry__free_unpacked(ae, NULL);
	n_namespaces = -1;
	namespaces = NULL;

	return ret;
}

bool check_aa_ns_dumping(void)
{
	char contents[48];
	int major, minor, ret;
	FILE *f;

	f = fopen(AA_SECURITYFS_PATH "/features/domain/stack", "r");
	if (!f)
		return false;

	ret = fscanf(f, "%48s", contents);
	fclose(f);
	if (ret != 1) {
		pr_err("scanning aa stack feature failed\n");
		return false;
	}

	if (strcmp("yes", contents)) {
		pr_warn("aa stack featured disabled: %s\n", contents);
		return false;
	}

	f = fopen(AA_SECURITYFS_PATH "/features/domain/version", "r");
	if (!f)
		return false;

	ret = fscanf(f, "%d.%d", &major, &minor);
	fclose(f);
	if (ret != 2) {
		pr_err("scanning aa stack version failed\n");
		return false;
	}

	return major >= 1 && minor >= 2;
}

static int restore_aa_namespace(AaNamespace *ns, char *path, int offset)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		pr_perror("fork failed");
		return -1;
	}

	if (!pid) {
		int i, my_offset, ret, fd;
		char buf[1024];

		ret = snprintf(buf, sizeof(buf), "changeprofile :%s:", ns->name);
		if (ret < 0 || ret >= sizeof(buf)) {
			pr_err("profile %s too big\n", ns->name);
			exit(1);
		}

		my_offset = snprintf(path + offset, PATH_MAX - offset, "/namespaces/%s", ns->name);
		if (my_offset < 0 || my_offset >= PATH_MAX - offset) {
			pr_err("snprintf'd too many characters\n");
			exit(1);
		}

		if (mkdir(path, 0755) < 0) {
			if (errno == EEXIST) {
				pr_warn("apparmor namespace %s already exists, restoring into it\n", path);
			} else {
				pr_perror("failed to create namespace %s", path);
				exit(1);
			}
		}

		fd = open_proc_rw(PROC_SELF, "attr/current");
		if (fd < 0) {
			pr_perror("couldn't open attr/current");
			goto fail;
		}

		errno = 0;
		ret = write(fd, buf, strlen(buf));
		close(fd);
		if (ret != strlen(buf)) {
			pr_perror("failed to change aa namespace %s", buf);
			goto fail;
		}

		for (i = 0; i < ns->n_namespaces; i++) {
			if (restore_aa_namespace(ns, path, offset + my_offset) < 0)
				goto fail;
		}

		for (i = 0; i < ns->n_policies; i++) {
			int fd, n;
			AaPolicy *p = ns->policies[i];

			fd = open(AA_SECURITYFS_PATH "/.replace", O_WRONLY);
			if (fd < 0) {
				pr_perror("couldn't open apparmor load file");
				goto fail;
			}

			n = write(fd, p->blob.data, p->blob.len);
			close(fd);
			if (n != p->blob.len) {
				pr_perror("write AA policy failed");
				goto fail;
			}
		}

		exit(0);
	fail:
		rmdir(path);
		exit(1);
	}

	if (waitpid(pid, &status, 0) < 0) {
		pr_perror("waitpid failed");
		return -1;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;

	pr_err("failed to restore aa namespace, worker exited: %d\n", status);
	return -1;
}

int prepare_apparmor_namespaces(void)
{
	struct cr_img *img;
	int ret, i;
	ApparmorEntry *ae;

	img = open_image(CR_FD_APPARMOR, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &ae, PB_APPARMOR);
	close_image(img);
	if (ret <= 0)
		return 0; /* there was no AA namespace entry */

	if (!ae) {
		pr_err("missing aa namespace entry\n");
		return -1;
	}

	/* no real reason we couldn't do this in parallel, but in usually we
	 * expect one namespace so there's probably not a lot to be gained.
	 */
	for (i = 0; i < ae->n_namespaces; i++) {
		char path[PATH_MAX] = AA_SECURITYFS_PATH "/policy";

		if (restore_aa_namespace(ae->namespaces[i], path, strlen(path)) < 0) {
			ret = -1;
			goto out;
		}
	}

	ret = 0;
out:
	apparmor_entry__free_unpacked(ae, NULL);
	return ret;
}
