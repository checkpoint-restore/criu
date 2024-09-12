#define LOG_PREFIX "cg: "
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
#include <sched.h>
#include <sys/wait.h>

#include "common/list.h"
#include "xmalloc.h"
#include "cgroup.h"
#include "cgroup-props.h"
#include "cr_options.h"
#include "pstree.h"
#include "criu-log.h"
#include "util.h"
#include "imgset.h"
#include "util-pie.h"
#include "namespaces.h"
#include "seize.h"
#include "string.h"
#include "protobuf.h"
#include "images/core.pb-c.h"
#include "images/cgroup.pb-c.h"
#include "kerndat.h"
#include "linux/mount.h"

/*
 * This structure describes set of controller groups
 * a task lives in. The cg_ctl entries are stored in
 * the @ctls list sorted by the .name field and then
 * by the .path field.
 */

struct cg_set {
	u32 id;
	struct list_head l;
	unsigned int n_ctls;
	struct list_head ctls;
};

static LIST_HEAD(cg_sets);
static unsigned int n_sets;
static CgSetEntry **rst_sets;
static unsigned int n_controllers;
static CgControllerEntry **controllers;
static char *cg_yard;
static struct cg_set *root_cgset; /* Set root item lives in */
static struct cg_set *criu_cgset; /* Set criu process lives in */
static u32 cg_set_ids = 1;

static LIST_HEAD(cgroups);
static unsigned int n_cgroups;
static pid_t cgroupd_pid;

static CgSetEntry *find_rst_set_by_id(u32 id)
{
	int i;

	for (i = 0; i < n_sets; i++)
		if (rst_sets[i]->id == id)
			return rst_sets[i];

	return NULL;
}

#define CGCMP_MATCH 1 /* check for exact match */
#define CGCMP_ISSUB 2 /* check set is subset of ctls */

static bool cg_set_compare(struct cg_set *set, struct list_head *ctls, int what)
{
	struct list_head *l1 = &set->ctls, *l2 = ctls;

	while (1) {
		struct cg_ctl *c1 = NULL, *c2 = NULL;

		if (l1->next != &set->ctls)
			c1 = list_first_entry(l1, struct cg_ctl, l);
		if (l2->next != ctls)
			c2 = list_first_entry(l2, struct cg_ctl, l);

		if (!c1 || !c2)		   /* Nowhere to move next */
			return !c1 && !c2; /* Both lists scanned -- match */

		if (strcmp(c1->name, c2->name))
			return false;

		switch (what) {
		case CGCMP_MATCH:
			/* must have the same cgns prefix to be considered equal */
			if (c1->cgns_prefix != c2->cgns_prefix)
				return false;

			if (strcmp(c1->path, c2->path))
				return false;

			break;
		case CGCMP_ISSUB:
			if (!strstartswith(c1->path, c2->path))
				return false;

			break;
		}

		l1 = l1->next;
		l2 = l2->next;
	}
}

static int collect_cgroups(struct list_head *ctls);

static struct cg_set *get_cg_set(struct list_head *ctls, unsigned int n_ctls, bool collect)
{
	struct cg_set *cs;

	list_for_each_entry(cs, &cg_sets, l)
		if (cg_set_compare(cs, ctls, CGCMP_MATCH)) {
			pr_debug(" `- Existing css %d found\n", cs->id);
			put_ctls(ctls);
			return cs;
		}

	pr_debug(" `- New css ID %d\n", cg_set_ids);
	cs = xmalloc(sizeof(*cs));
	if (cs) {
		cs->id = cg_set_ids++;
		INIT_LIST_HEAD(&cs->ctls);
		list_splice_init(ctls, &cs->ctls);
		cs->n_ctls = n_ctls;
		list_add_tail(&cs->l, &cg_sets);
		n_sets++;

		if (!pr_quelled(LOG_DEBUG)) {
			struct cg_ctl *ctl;

			list_for_each_entry(ctl, &cs->ctls, l)
				pr_debug("    `- [%s] -> [%s] [%u]\n", ctl->name, ctl->path, ctl->cgns_prefix);
		}

		if (collect && collect_cgroups(&cs->ctls)) {
			list_del(&cs->l);
			n_sets--;
			put_ctls(&cs->ctls);
			xfree(cs);
			return NULL;
		}
	}

	return cs;
}

struct cg_controller *new_controller(const char *name)
{
	struct cg_controller *nc = xmalloc(sizeof(*nc));
	if (!nc)
		return NULL;

	nc->controllers = xmalloc(sizeof(char *));
	if (!nc->controllers) {
		xfree(nc);
		return NULL;
	}

	nc->controllers[0] = xstrdup(name);
	if (!nc->controllers[0]) {
		xfree(nc->controllers);
		xfree(nc);
		return NULL;
	}

	nc->n_controllers = 1;

	nc->n_heads = 0;
	nc->is_threaded = false;
	INIT_LIST_HEAD(&nc->heads);

	return nc;
}

int parse_cg_info(void)
{
	if (collect_controllers(&cgroups, &n_cgroups) < 0)
		return -1;

	return 0;
}

/* Check that co-mounted controllers from /proc/cgroups (e.g. cpu and cpuacct)
 * are contained in a comma separated string (e.g. from /proc/self/cgroup or
 * mount options). */
static bool cgroup_contains(char **controllers, unsigned int n_controllers, char *name, u64 *mask)
{
	unsigned int i;
	bool all_match = true;

	/* Check whether this cgroup2 or not.*/
	if (n_controllers == 1 && controllers[0][0] == 0) {
		bool match = name[0] == 0;

		if (mask && match)
			*mask &= ~(1ULL);

		return match;
	}

	for (i = 0; i < n_controllers; i++) {
		bool found = false;
		const char *loc = name;
		do {
			loc = strstr(loc, controllers[i]);
			if (loc) {
				loc += strlen(controllers[i]);
				switch (*loc) {
				case '\0':
				case ',':
					found = true;
					if (mask)
						*mask &= ~(1ULL << i);
					break;
				}
			}
		} while (loc);
		all_match &= found;
	}

	return all_match && n_controllers > 0;
}

/* This is for use in add_cgroup() as additional arguments for the ftw()
 * callback */
static struct cg_controller *current_controller;
static unsigned int path_pref_len;

#define EXACT_MATCH  0
#define PARENT_MATCH 1
#define NO_MATCH     2

static int find_dir(const char *path, struct list_head *dirs, struct cgroup_dir **rdir)
{
	struct cgroup_dir *d;
	list_for_each_entry(d, dirs, siblings) {
		if (strcmp(d->path, path) == 0) {
			*rdir = d;
			return EXACT_MATCH;
		}

		if (strstartswith(path, d->path)) {
			int ret = find_dir(path, &d->children, rdir);
			if (ret == NO_MATCH) {
				*rdir = d;
				return PARENT_MATCH;
			}
			return ret;
		}
	}

	return NO_MATCH;
}

/*
 * Strips trailing '\n' from the string
 */
static inline char *strip(char *str)
{
	char *e;

	e = strchr(str, '\0');
	if (e != str && *(e - 1) == '\n')
		*(e - 1) = '\0';

	return str;
}

/*
 * Currently this function only supports properties that have a string value
 * under 1024 chars.
 */
static int read_cgroup_prop(struct cgroup_prop *property, const char *fullpath)
{
	char buf[1024];
	int fd, ret;
	struct stat sb;

	fd = open(fullpath, O_RDONLY);
	if (fd == -1) {
		property->value = NULL;
		pr_perror("Failed opening %s", fullpath);
		return -1;
	}

	if (fstat(fd, &sb) < 0) {
		pr_perror("failed statting cgroup prop %s", fullpath);
		close(fd);
		return -1;
	}

	property->mode = sb.st_mode;
	property->uid = sb.st_uid;
	property->gid = sb.st_gid;

	/* skip dumping the value of these, since it doesn't make sense (we
	 * just want to restore the perms) */
	if (!strcmp(property->name, "cgroup.procs") || !strcmp(property->name, "tasks")) {
		ret = 0;
		/* libprotobuf segfaults if we leave a null pointer in a
		 * string, so let's not do that */
		property->value = xstrdup("");
		if (!property->value)
			ret = -1;

		close(fd);
		return ret;
	}

	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret == -1) {
		pr_perror("Failed scanning %s", fullpath);
		close(fd);
		return -1;
	}
	close(fd);

	buf[ret] = 0;

	if (strtoll(buf, NULL, 10) == LLONG_MAX)
		strcpy(buf, "-1");

	property->value = xstrdup(strip(buf));
	if (!property->value)
		return -1;
	return 0;
}

static struct cgroup_prop *create_cgroup_prop(const char *name)
{
	struct cgroup_prop *property;

	property = xmalloc(sizeof(*property));
	if (!property)
		return NULL;

	property->name = xstrdup(name);
	if (!property->name) {
		xfree(property);
		return NULL;
	}

	property->value = NULL;
	return property;
}

static void free_cgroup_prop(struct cgroup_prop *prop)
{
	xfree(prop->name);
	xfree(prop->value);
	xfree(prop);
}

static void free_all_cgroup_props(struct cgroup_dir *ncd)
{
	struct cgroup_prop *prop, *t;

	list_for_each_entry_safe(prop, t, &ncd->properties, list) {
		list_del(&prop->list);
		free_cgroup_prop(prop);
	}

	INIT_LIST_HEAD(&ncd->properties);
	ncd->n_properties = 0;
}

static int dump_cg_props_array(const char *fpath, struct cgroup_dir *ncd, const cgp_t *cgp,
			       struct cg_controller *controller)
{
	int j;
	char buf[PATH_MAX];
	struct cgroup_prop *prop;

	for (j = 0; cgp && j < cgp->nr_props; j++) {
		if (snprintf(buf, PATH_MAX, "%s/%s", fpath, cgp->props[j]) >= PATH_MAX) {
			pr_err("snprintf output was truncated\n");
			return -1;
		}

		if (access(buf, F_OK) < 0 && errno == ENOENT) {
			pr_info("Couldn't open %s. This cgroup property may not exist on this kernel\n", buf);
			continue;
		}

		prop = create_cgroup_prop(cgp->props[j]);
		if (!prop) {
			free_all_cgroup_props(ncd);
			return -1;
		}

		if (read_cgroup_prop(prop, buf) < 0) {
			free_cgroup_prop(prop);
			free_all_cgroup_props(ncd);
			return -1;
		}

		if (!strcmp("memory.oom_control", cgp->props[j])) {
			char *new;
			int disable;

			if (sscanf(prop->value, "oom_kill_disable %d\n", &disable) != 1) {
				pr_err("couldn't scan oom state from %s\n", prop->value);
				free_cgroup_prop(prop);
				free_all_cgroup_props(ncd);
				return -1;
			}

			if (asprintf(&new, "%d", disable) < 0) {
				pr_err("couldn't allocate new oom value\n");
				free_cgroup_prop(prop);
				free_all_cgroup_props(ncd);
				return -1;
			}

			xfree(prop->value);
			prop->value = new;
		}

		/*
		 * Set the is_threaded flag if cgroup.type's value is threaded
		 * or it is a cgroup v1 (it has a 'tasks' property).
		 * Ignore all other values.
		 */
		if ((!strcmp("cgroup.type", prop->name) && !strcmp("threaded", prop->value)) || !strcmp("tasks", prop->name))
			controller->is_threaded = true;

		pr_info("Dumping value %s from %s/%s\n", prop->value, fpath, prop->name);
		list_add_tail(&prop->list, &ncd->properties);
		ncd->n_properties++;
	}

	return 0;
}

static int add_cgroup_properties(const char *fpath, struct cgroup_dir *ncd, struct cg_controller *controller)
{
	int i;

	for (i = 0; i < controller->n_controllers; ++i) {
		const cgp_t *cgp = cgp_get_props(controller->controllers[i]);

		if (dump_cg_props_array(fpath, ncd, cgp, controller) < 0) {
			pr_err("dumping known properties failed\n");
			return -1;
		}
	}

	/* cgroup v2 */
	if (controller->controllers[0][0] == 0) {
		if (dump_cg_props_array(fpath, ncd, &cgp_global_v2, controller) < 0) {
			pr_err("dumping global properties v2 failed\n");
			return -1;
		}
	} else {
		if (dump_cg_props_array(fpath, ncd, &cgp_global, controller) < 0) {
			pr_err("dumping global properties failed\n");
			return -1;
		}
	}

	return 0;
}

static int add_cgroup(const char *fpath, const struct stat *sb, int typeflag)
{
	struct cgroup_dir *ncd = NULL, *match;
	int exit_code = -1;

	if (typeflag == FTW_D) {
		int mtype;

		pr_info("adding cgroup %s\n", fpath);

		ncd = xmalloc(sizeof(*ncd));
		if (!ncd)
			goto out;

		ncd->mode = sb->st_mode;
		ncd->uid = sb->st_uid;
		ncd->gid = sb->st_gid;

		/* chop off the first "/proc/self/fd/N" str */
		if (fpath[path_pref_len] == '\0')
			ncd->path = xstrdup("/");
		else
			ncd->path = xstrdup(fpath + path_pref_len);

		if (!ncd->path)
			goto out;

		mtype = find_dir(ncd->path, &current_controller->heads, &match);

		switch (mtype) {
		/* ignore co-mounted cgroups and already dumped cgroups */
		case EXACT_MATCH:
			exit_code = 0;
			goto out;
		case PARENT_MATCH:
			list_add_tail(&ncd->siblings, &match->children);
			match->n_children++;
			break;
		case NO_MATCH:
			list_add_tail(&ncd->siblings, &current_controller->heads);
			current_controller->n_heads++;
			break;
		default:
			BUG();
		}

		INIT_LIST_HEAD(&ncd->children);
		ncd->n_children = 0;

		INIT_LIST_HEAD(&ncd->properties);
		ncd->n_properties = 0;
		if (add_cgroup_properties(fpath, ncd, current_controller) < 0) {
			list_del(&ncd->siblings);
			if (mtype == PARENT_MATCH)
				match->n_children--;
			else if (mtype == NO_MATCH)
				current_controller->n_heads--;
			goto out;
		}
	}

	return 0;

out:
	if (ncd)
		xfree(ncd->path);
	xfree(ncd);
	return exit_code;
}

static int add_freezer_state(struct cg_controller *controller)
{
	struct cgroup_dir *it;

	/* There is one more case, that cgroup namespaces might
	  * generate "multiple" heads if nothing is actually in the
	  * root freezer cgroup, e.g. --freeze-cgroup=/lxc/foo and all
	  * tasks in either /lxc/foo/a or /lxc/foo/b.
	  *
	  * In this case
	  */
	list_for_each_entry(it, &controller->heads, siblings) {
		struct cgroup_dir *cg_head;
		struct cgroup_prop *prop;

		cg_head = list_first_entry(&controller->heads, struct cgroup_dir, siblings);

		prop = create_cgroup_prop("freezer.state");
		if (!prop)
			return -1;
		prop->value = xstrdup(get_real_freezer_state());
		if (!prop->value) {
			free_cgroup_prop(prop);
			return -1;
		}

		list_add_tail(&prop->list, &cg_head->properties);
		cg_head->n_properties++;
	}

	return 0;
}

static const char namestr[] = "name=";
static int __new_open_cgroupfs(struct cg_ctl *cc)
{
	const char *fstype = cc->name[0] == 0 ? "cgroup2" : "cgroup";
	int fsfd, fd;
	char *name;

	fsfd = cr_fsopen(fstype, 0);
	if (fsfd < 0) {
		pr_perror("Unable to open the cgroup file system");
		return -1;
	}

	if (strstartswith(cc->name, namestr)) {
		if (cr_fsconfig(fsfd, FSCONFIG_SET_STRING, "name", cc->name + strlen(namestr), 0)) {
			fsfd_dump_messages(fsfd);
			pr_perror("Unable to configure the cgroup (%s) file system", cc->name);
			goto err;
		}
	} else if (cc->name[0] != 0) { /* cgroup v1 */
		char *saveptr = NULL, *buf = strdupa(cc->name);
		name = strtok_r(buf, ",", &saveptr);
		while (name) {
			if (cr_fsconfig(fsfd, FSCONFIG_SET_FLAG, name, NULL, 0)) {
				fsfd_dump_messages(fsfd);
				pr_perror("Unable to configure the cgroup (%s) file system", name);
				goto err;
			}
			name = strtok_r(NULL, ",", &saveptr);
		}
	}

	if (cr_fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0)) {
		fsfd_dump_messages(fsfd);
		pr_perror("Unable to create the cgroup (%s) file system", cc->name);
		goto err;
	}

	fd = cr_fsmount(fsfd, 0, 0);
	if (fd < 0) {
		fsfd_dump_messages(fsfd);
		pr_perror("Unable to mount the cgroup (%s) file system", cc->name);
	}
	close(fsfd);

	return fd;
err:
	close(fsfd);
	return -1;
}

static int open_cgroupfs(struct cg_ctl *cc)
{
	const char *fstype = cc->name[0] == 0 ? "cgroup2" : "cgroup";
	char prefix[] = ".criu.cgmounts.XXXXXX";
	char mopts[1024];
	int fd;

	if (kdat.has_fsopen)
		return __new_open_cgroupfs(cc);

	if (strstartswith(cc->name, namestr))
		snprintf(mopts, sizeof(mopts), "none,%s", cc->name);
	else
		snprintf(mopts, sizeof(mopts), "%s", cc->name);

	if (mkdtemp(prefix) == NULL) {
		pr_perror("can't make dir for cg mounts");
		return -1;
	}

	if (mount("none", prefix, fstype, 0, mopts[0] ? mopts : NULL) < 0) {
		pr_perror("Unable to mount %s %s", fstype, mopts);
		rmdir(prefix);
		return -1;
	}

	fd = open_detach_mount(prefix);
	if (fd < 0)
		return -1;

	return fd;
}

static int collect_cgroups(struct list_head *ctls)
{
	struct cg_ctl *cc;
	int ret = 0;
	int fd = -1;

	list_for_each_entry(cc, ctls, l) {
		char path[PATH_MAX], *root;
		struct cg_controller *cg;
		struct cg_root_opt *o;

		current_controller = NULL;

		/* We should get all the "real" (i.e. not name=systemd type)
		 * controller from parse_cgroups(), so find that controller if
		 * it exists. */
		list_for_each_entry(cg, &cgroups, l) {
			if (cgroup_contains(cg->controllers, cg->n_controllers, cc->name, NULL)) {
				current_controller = cg;
				break;
			}
		}

		if (!current_controller) {
			/* only allow "fake" controllers to be created this way */
			if (!strstartswith(cc->name, namestr)) {
				pr_err("controller %s not found\n", cc->name);
				return -1;
			} else {
				struct cg_controller *nc;

				nc = new_controller(cc->name);
				if (!nc)
					return -1;
				list_add_tail(&nc->l, &cg->l);
				n_cgroups++;
				current_controller = nc;
			}
		}

		if (!opts.manage_cgroups)
			continue;

		if (opts.cgroup_yard) {
			char dir_path[PATH_MAX];
			int off;

			off = snprintf(dir_path, PATH_MAX, "%s/", opts.cgroup_yard);
			if (strstartswith(cc->name, namestr))
				snprintf(dir_path + off, PATH_MAX - off, "%s", cc->name + strlen(namestr));
			else if (cc->name[0] == 0)
				snprintf(dir_path + off, PATH_MAX - off, "unified");
			else
				snprintf(dir_path + off, PATH_MAX - off, "%s", cc->name);

			fd = open(dir_path, O_RDONLY | O_DIRECTORY, 0);
			if (fd < 0) {
				pr_perror("couldn't open %s", dir_path);
				return -1;
			}
		} else {
			fd = open_cgroupfs(cc);
			if (fd < 0)
				return -1;
		}

		path_pref_len = snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);

		root = cc->path;
		if (opts.new_global_cg_root)
			root = opts.new_global_cg_root;

		list_for_each_entry(o, &opts.new_cgroup_roots, node) {
			if (!strcmp(cc->name, o->controller))
				root = o->newroot;
		}

		snprintf(path + path_pref_len, PATH_MAX - path_pref_len, "%s", root);

		ret = ftw(path, add_cgroup, 4);

		if (ret < 0)
			pr_perror("failed walking %s for empty cgroups", path);

		close_safe(&fd);

		if (ret < 0)
			return ret;

		if (opts.freeze_cgroup && !strcmp(cc->name, "freezer") && add_freezer_state(current_controller))
			return -1;
	}

	return 0;
}

int dump_thread_cgroup(const struct pstree_item *item, u32 *cg_id, struct parasite_dump_cgroup_args *args, int id)
{
	int pid, tid;
	LIST_HEAD(ctls);
	unsigned int n_ctls = 0;
	struct cg_set *cs;

	if (opts.unprivileged)
		return 0;

	if (item)
		pid = item->pid->real;
	else
		pid = getpid();

	if (id < 0)
		tid = pid;
	else
		tid = item->threads[id].real;

	pr_info("Dumping cgroups for thread %d\n", tid);
	if (parse_thread_cgroup(pid, tid, args, &ctls, &n_ctls))
		return -1;

	cs = get_cg_set(&ctls, n_ctls, item);
	if (!cs)
		return -1;

	if (!item) {
		BUG_ON(criu_cgset);
		criu_cgset = cs;
		pr_info("Set %d is criu one\n", cs->id);
	} else {
		if (item == root_item) {
			if (!root_cgset) {
				root_cgset = cs;
				pr_info("Set %d is root one\n", cs->id);
			}
		} else {
			struct cg_ctl *root, *stray;

			BUG_ON(!root_cgset);
			pr_info("Set %d is a stray\n", cs->id);

			/* Copy the cgns prefix from the root cgset for each
			 * controller. This is ok because we know that there is
			 * only one cgroup namespace.
			 */
			list_for_each_entry(root, &root_cgset->ctls, l) {
				list_for_each_entry(stray, &cs->ctls, l) {
					if (strcmp(root->name, stray->name))
						continue;

					if (strlen(stray->path) < root->cgns_prefix) {
						pr_err("cg %s shorter than path prefix %d?\n", stray->path,
						       root->cgns_prefix);
						return -1;
					}

					stray->cgns_prefix = root->cgns_prefix;
				}
			}
		}
	}

	*cg_id = cs->id;
	return 0;
}

static int dump_cg_dir_props(struct list_head *props, size_t n_props, CgroupPropEntry ***ents)
{
	struct cgroup_prop *prop_cur;
	CgroupPropEntry *cpe;
	void *m;
	int i = 0;

	m = xmalloc(n_props * (sizeof(CgroupPropEntry *) + sizeof(CgroupPropEntry)));
	*ents = m;
	if (!m)
		return -1;

	cpe = m + n_props * sizeof(CgroupPropEntry *);

	list_for_each_entry(prop_cur, props, list) {
		cgroup_prop_entry__init(cpe);

		cpe->perms = xmalloc(sizeof(*cpe->perms));
		if (!cpe->perms)
			goto error;
		cgroup_perms__init(cpe->perms);

		cpe->name = xstrdup(prop_cur->name);
		cpe->value = xstrdup(prop_cur->value);
		if (!cpe->name || !cpe->value)
			goto error;
		cpe->perms->mode = prop_cur->mode;
		cpe->perms->uid = prop_cur->uid;
		cpe->perms->gid = prop_cur->gid;

		(*ents)[i++] = cpe++;
	}

	return 0;

error:
	while (i >= 0) {
		xfree(cpe->name);
		xfree(cpe->value);
		--cpe;
		--i;
	}

	xfree(*ents);
	return -1;
}

static int dump_cg_dirs(struct list_head *dirs, size_t n_dirs, CgroupDirEntry ***ents, int poff)
{
	struct cgroup_dir *cur;
	CgroupDirEntry *cde;
	void *m;
	int i = 0;

	m = xmalloc(n_dirs * (sizeof(CgroupDirEntry *) + sizeof(CgroupDirEntry)));
	*ents = m;
	if (!m)
		return -1;

	cde = m + n_dirs * sizeof(CgroupDirEntry *);

	list_for_each_entry(cur, dirs, siblings) {
		cgroup_dir_entry__init(cde);

		cde->dir_perms = xmalloc(sizeof(*cde->dir_perms));
		if (!cde->dir_perms)
			return -1;
		cgroup_perms__init(cde->dir_perms);

		cde->dir_perms->mode = cur->mode;
		cde->dir_perms->uid = cur->uid;
		cde->dir_perms->gid = cur->gid;

		cde->dir_name = cur->path + poff;
		if (poff != 1)		 /* parent isn't "/" */
			cde->dir_name++; /* leading / */
		cde->n_children = cur->n_children;
		if (cur->n_children > 0)
			if (dump_cg_dirs(&cur->children, cur->n_children, &cde->children, strlen(cur->path)) < 0) {
				xfree(*ents);
				return -1;
			}

		cde->n_properties = cur->n_properties;
		if (cde->n_properties > 0) {
			if (dump_cg_dir_props(&cur->properties, cde->n_properties, &cde->properties) < 0) {
				xfree(*ents);
				return -1;
			}
		}

		(*ents)[i++] = cde++;
	}

	return 0;
}

static int dump_controllers(CgroupEntry *cg)
{
	struct cg_controller *cur;
	CgControllerEntry *ce;
	void *m;
	int i;

	cg->n_controllers = n_cgroups;
	m = xmalloc(n_cgroups * (sizeof(CgControllerEntry *) + sizeof(CgControllerEntry)));
	cg->controllers = m;
	ce = m + cg->n_controllers * sizeof(CgControllerEntry *);
	if (!m)
		return -1;

	i = 0;
	list_for_each_entry(cur, &cgroups, l) {
		cg_controller_entry__init(ce);

		ce->has_is_threaded = true;
		ce->is_threaded = cur->is_threaded;
		ce->cnames = cur->controllers;
		ce->n_cnames = cur->n_controllers;
		ce->n_dirs = cur->n_heads;
		if (ce->n_dirs > 0)
			if (dump_cg_dirs(&cur->heads, cur->n_heads, &ce->dirs, 0) < 0) {
				xfree(cg->controllers);
				cg->controllers = NULL;
				return -1;
			}
		cg->controllers[i++] = ce++;
	}

	return 0;
}

static void free_sets(CgroupEntry *cg, unsigned nr)
{
	unsigned i;

	for (i = 0; i < nr; i++)
		xfree(cg->sets[i]->ctls);
	xfree(cg->sets);
}

static int dump_sets(CgroupEntry *cg)
{
	struct cg_set *set;
	struct cg_ctl *ctl;
	unsigned s, c;
	void *m;
	CgSetEntry *se;
	CgMemberEntry *ce;

	pr_info("Dumping %d sets\n", n_sets - 1);

	cg->n_sets = n_sets - 1;
	m = xmalloc(cg->n_sets * (sizeof(CgSetEntry *) + sizeof(CgSetEntry)));
	cg->sets = m;
	se = m + cg->n_sets * sizeof(CgSetEntry *);
	if (!m)
		return -1;

	s = 0;
	list_for_each_entry(set, &cg_sets, l) {
		if (set == criu_cgset)
			continue;

		/*
		 * Now encode them onto the image entry
		 */

		cg_set_entry__init(se);
		se->id = set->id;

		se->n_ctls = set->n_ctls;
		m = xmalloc(se->n_ctls * (sizeof(CgMemberEntry *) + sizeof(CgMemberEntry)));
		se->ctls = m;
		ce = m + se->n_ctls * sizeof(CgMemberEntry *);
		if (!m) {
			free_sets(cg, s);
			return -1;
		}

		c = 0;
		list_for_each_entry(ctl, &set->ctls, l) {
			pr_info("   `- Dumping %s of %s\n", ctl->name, ctl->path);
			cg_member_entry__init(ce);
			ce->name = ctl->name;
			ce->path = ctl->path;
			if (ctl->cgns_prefix > 0) {
				ce->has_cgns_prefix = true;
				ce->cgns_prefix = ctl->cgns_prefix;
			}
			se->ctls[c++] = ce++;
		}

		cg->sets[s++] = se++;
	}

	return 0;
}

int dump_cgroups(void)
{
	CgroupEntry cg = CGROUP_ENTRY__INIT;
	int ret = -1;

	if (opts.unprivileged)
		return 0;

	BUG_ON(!criu_cgset || !root_cgset);

	/*
	 * Check whether root task lives in its own set as compared
	 * to criu. If yes, we should not dump anything. Note that
	 * list_is_singular() is slightly wrong here: if the criu cgset has
	 * empty cgroups, those will not be restored on the target host, since
	 * we're not dumping anything here.
	 */

	if (root_cgset == criu_cgset && list_is_singular(&cg_sets)) {
		pr_info("All tasks in criu's cgroups. Nothing to dump.\n");
		return 0;
	}

	if (dump_sets(&cg))
		return -1;
	if (dump_controllers(&cg)) {
		goto err;
	}

	pr_info("Writing CG image\n");
	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_CGROUP), &cg, PB_CGROUP);
err:
	free_sets(&cg, cg.n_sets);
	xfree(cg.controllers);
	return ret;
}

static int ctrl_dir_and_opt(CgControllerEntry *ctl, char *dir, int ds, char *opt, int os)
{
	int i, doff = 0, ooff = 0;
	bool none_opt = false;

	for (i = 0; i < ctl->n_cnames; i++) {
		char *n;

		n = ctl->cnames[i];
		if (strstartswith(n, "name=")) {
			n += 5;
			if (opt && !none_opt) {
				ooff += snprintf(opt + ooff, os - ooff, "none,");
				none_opt = true;
			}
		}

		if (n[0] == 0)
			doff += snprintf(dir + doff, ds - doff, "unified,");
		else
			doff += snprintf(dir + doff, ds - doff, "%s,", n);
		if (opt)
			ooff += snprintf(opt + ooff, os - ooff, "%s,", ctl->cnames[i]);
	}

	/* Chop the trailing ','-s */
	dir[--doff] = '\0';
	if (opt)
		opt[ooff - 1] = '\0';

	return doff;
}

/* Some properties cannot be restored after the cgroup has children or tasks in
 * it. We restore these properties as soon as the cgroup is created.
 */
static const char *special_props[] = {
	"cpuset.cpus",
	"cpuset.mems",
	"devices.list",
	"memory.kmem.limit_in_bytes",
	"memory.swappiness",
	"memory.oom_control",
	"memory.use_hierarchy",
	"cgroup.type",
	NULL,
};

bool is_special_property(const char *prop)
{
	size_t i = 0;

	for (i = 0; special_props[i]; i++)
		if (strcmp(prop, special_props[i]) == 0)
			return true;

	return false;
}

static int userns_move(void *arg, int fd, pid_t pid)
{
	char pidbuf[32];
	int cg, len, err;

	len = snprintf(pidbuf, sizeof(pidbuf), "%d", pid);

	if (len >= sizeof(pidbuf)) {
		pr_err("pid printing failed: %d\n", pid);
		return -1;
	}

	cg = get_service_fd(CGROUP_YARD);
	err = fd = openat(cg, arg, O_WRONLY);
	if (fd >= 0) {
		err = write(fd, pidbuf, len);
		close(fd);
	}

	if (err < 0) {
		pr_perror("Can't move %s into %s (%d/%d)", pidbuf, (char *)arg, err, fd);
		return -1;
	}

	return 0;
}

static int prepare_cgns(CgSetEntry *se)
{
	int i;
	bool do_unshare = false;

	for (i = 0; i < se->n_ctls; i++) {
		char aux[PATH_MAX];
		int j, aux_off;
		CgMemberEntry *ce = se->ctls[i];
		CgControllerEntry *ctrl = NULL;

		for (j = 0; j < n_controllers; j++) {
			CgControllerEntry *cur = controllers[j];
			if (cgroup_contains(cur->cnames, cur->n_cnames, ce->name, NULL)) {
				ctrl = cur;
				break;
			}
		}

		if (!ctrl) {
			pr_err("No cg_controller_entry found for %s/%s\n", ce->name, ce->path);
			return -1;
		}

		aux_off = ctrl_dir_and_opt(ctrl, aux, sizeof(aux), NULL, 0);

		/* We need to do an unshare() here as unshare() pins the root
		 * of the cgroup namespace to whatever the current cgroups are.
		 * For example, consider a task in a cgroup (according to the
		 * host):
		 *
		 * /unsprefix/insidecontainer
		 *
		 * If the task first moved itself into /unsprefix, then did unshare(),
		 * when the task examines its own /proc/self/cgroup file it will see /,
		 * but to the host it is really in /unsprefix. Then if it further enters
		 * /insidecontainer here, the full host path will be
		 * /unsprefix/insidecontianer. There is no way to say "set the cgroup
		 * namespace boundary at /unsprefix" without first entering that, doing
		 * the unshare, and then entering the rest of the path.
		 */
		if (ce->has_cgns_prefix) {
			char tmp = ce->path[ce->cgns_prefix];
			ce->path[ce->cgns_prefix] = '\0';

			pr_info("setting cgns prefix to %s\n", ce->path);
			snprintf(aux + aux_off, sizeof(aux) - aux_off, "/%s/cgroup.procs", ce->path);
			ce->path[ce->cgns_prefix] = tmp;
			if (userns_call(userns_move, 0, aux, strlen(aux) + 1, -1) < 0) {
				pr_perror("couldn't set cgns prefix %s", aux);
				return -1;
			}

			do_unshare = true;
		}
	}

	if (do_unshare && unshare(CLONE_NEWCGROUP) < 0) {
		pr_perror("couldn't unshare cgns");
		return -1;
	}

	return 0;
}

static int move_in_cgroup(CgSetEntry *se)
{
	int i;

	pr_info("Move into %d\n", se->id);

	for (i = 0; i < se->n_ctls; i++) {
		char aux[PATH_MAX];
		int fd = -1, err, j, aux_off;
		CgMemberEntry *ce = se->ctls[i];
		CgControllerEntry *ctrl = NULL;

		for (j = 0; j < n_controllers; j++) {
			CgControllerEntry *cur = controllers[j];
			if (cgroup_contains(cur->cnames, cur->n_cnames, ce->name, NULL)) {
				ctrl = cur;
				break;
			}
		}

		if (!ctrl) {
			pr_err("No cg_controller_entry found for %s/%s\n", ce->name, ce->path);
			return -1;
		}

		aux_off = ctrl_dir_and_opt(ctrl, aux, sizeof(aux), NULL, 0);

		/* Note that unshare(CLONE_NEWCGROUP) doesn't change the view
		 * of previously mounted cgroupfses; since we're restoring via
		 * a dirfd pointing to the cg yard set up by when criu was in
		 * the root cgns, we still want to use the full path here when
		 * we move into the cgroup.
		 */
		snprintf(aux + aux_off, sizeof(aux) - aux_off, "/%s/cgroup.procs", ce->path);
		pr_debug("  `-> %s\n", aux);
		err = userns_call(userns_move, 0, aux, strlen(aux) + 1, -1);
		if (err < 0) {
			pr_perror("Can't move into %s (%d/%d)", aux, err, fd);
			return -1;
		}
	}

	return 0;
}

int prepare_cgroup_namespace(struct pstree_item *root_task)
{
	CgSetEntry *se;

	if (opts.manage_cgroups == CG_MODE_IGNORE)
		return 0;

	if (root_task->parent) {
		pr_err("Expecting root_task to restore cgroup namespace\n");
		return -1;
	}

	/*
	 * If on dump all dumped tasks are in same cgset with criu we don't
	 * dump cgsets and thus cgroup namespaces and rely that on restore
	 * criu caller would prepare proper cgset/cgns for us. Also in case
	 * of --unprivileged we don't even have the root cgset here.
	 */
	if (!rsti(root_task)->cg_set || rsti(root_task)->cg_set == root_cg_set) {
		pr_info("Cgroup namespace inherited from parent\n");
		return 0;
	}

	se = find_rst_set_by_id(rsti(root_task)->cg_set);
	if (!se) {
		pr_err("No set %d found\n", rsti(root_task)->cg_set);
		return -1;
	}

	if (prepare_cgns(se) < 0) {
		pr_err("failed preparing cgns\n");
		return -1;
	}

	return 0;
}

int restore_task_cgroup(struct pstree_item *me)
{
	struct pstree_item *parent = me->parent;
	CgSetEntry *se;
	u32 current_cgset;

	if (opts.manage_cgroups == CG_MODE_IGNORE)
		return 0;

	if (!rsti(me)->cg_set)
		return 0;

	/* Zombies and helpers can have cg_set == 0 so we skip them */
	while (parent && !rsti(parent)->cg_set)
		parent = parent->parent;

	if (parent)
		current_cgset = rsti(parent)->cg_set;
	else
		current_cgset = root_cg_set;

	if (rsti(me)->cg_set == current_cgset) {
		pr_info("Cgroups %d inherited from parent\n", current_cgset);
		return 0;
	}

	se = find_rst_set_by_id(rsti(me)->cg_set);
	if (!se) {
		pr_err("No set %d found\n", rsti(me)->cg_set);
		return -1;
	}

	return move_in_cgroup(se);
}

void fini_cgroup(void)
{
	if (!cg_yard)
		return;

	close_service_fd(CGROUP_YARD);
	if (!opts.cgroup_yard) {
		if (umount2(cg_yard, MNT_DETACH))
			pr_perror("Unable to umount %s", cg_yard);
		if (rmdir(cg_yard))
			pr_perror("Unable to remove %s", cg_yard);
	}
	xfree(cg_yard);
	cg_yard = NULL;
}

static int add_subtree_control_prop_prefix(char *input, char *output, char prefix)
{
	char *current, *next;
	size_t len, off = 0;

	current = input;
	do {
		next = strchrnul(current, ' ');
		len = next - current;

		output[off] = prefix;
		off++;
		memcpy(output + off, current, len);
		off += len;
		output[off] = ' ';
		off++;

		current = next + 1;
	} while (*next != '\0');

	return off;
}

static int restore_cgroup_subtree_control(const CgroupPropEntry *cg_prop_entry_p, int fd)
{
	char buf[1024];
	char line[1024];
	int ret, off = 0;

	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret < 0) {
		pr_perror("read from cgroup.subtree_control");
		return ret;
	}
	/* Remove the trailing newline */
	buf[ret] = '\0';

	/* Remove all current subsys in subtree_control */
	if (buf[0] != '\0')
		off = add_subtree_control_prop_prefix(buf, line, '-');

	/* Add subsys need to be restored in subtree_control */
	if (cg_prop_entry_p->value[0] != '\0')
		off += add_subtree_control_prop_prefix(cg_prop_entry_p->value, line + off, '+');

	/* Remove the trailing space */
	if (off != 0) {
		off--;
		line[off] = '\0';
	}

	if (write(fd, line, off) != off) {
		pr_perror("write to cgroup.subtree_control");
		return -1;
	}

	return 0;
}

/*
 * Note: The path string can be modified in this function,
 * the length of path string should be at least PATH_MAX.
 */
static int restore_cgroup_prop(const CgroupPropEntry *cg_prop_entry_p, char *path, int off, bool split_lines,
			       bool skip_fails)
{
	int cg, fd, exit_code = -1, flag;
	CgroupPerms *perms = cg_prop_entry_p->perms;
	int is_subtree_control = !strcmp(cg_prop_entry_p->name, "cgroup.subtree_control");

	if (opts.manage_cgroups == CG_MODE_IGNORE)
		return 0;

	if (!cg_prop_entry_p->value) {
		pr_err("cg_prop_entry->value was empty when should have had a value\n");
		return -1;
	}

	if (snprintf(path + off, PATH_MAX - off, "/%s", cg_prop_entry_p->name) >= PATH_MAX) {
		pr_err("snprintf output was truncated for %s\n", cg_prop_entry_p->name);
		return -1;
	}

	pr_info("Restoring cgroup property value [%s] to [%s]\n", cg_prop_entry_p->value, path);

	if (is_subtree_control)
		flag = O_RDWR;
	else
		flag = O_WRONLY;

	cg = get_service_fd(CGROUP_YARD);
	fd = openat(cg, path, flag);
	if (fd < 0) {
		pr_perror("bad cgroup path: %s", path);
		return -1;
	}

	if (perms && cr_fchperm(fd, perms->uid, perms->gid, perms->mode) < 0)
		goto out;

	/* skip these two since restoring their values doesn't make sense */
	if (!strcmp(cg_prop_entry_p->name, "cgroup.procs") || !strcmp(cg_prop_entry_p->name, "tasks")) {
		exit_code = 0;
		goto out;
	}

	if (is_subtree_control) {
		exit_code = restore_cgroup_subtree_control(cg_prop_entry_p, fd);
		goto out;
	}

	/* skip restoring cgroup.type if its value is not "threaded" */
	if (!strcmp(cg_prop_entry_p->name, "cgroup.type") && strcmp(cg_prop_entry_p->value, "threaded")) {
		exit_code = 0;
		goto out;
	}

	if (split_lines) {
		char *line = cg_prop_entry_p->value;
		char *next_line;
		size_t len;

		do {
			next_line = strchrnul(line, '\n');
			len = next_line - line;

			if (write(fd, line, len) != len) {
				pr_perror("Failed writing %s to %s", line, path);
				if (!skip_fails)
					goto out;
			}
			line = next_line + 1;
		} while (*next_line != '\0');
	} else {
		size_t len = strlen(cg_prop_entry_p->value);
		int ret;

		ret = write(fd, cg_prop_entry_p->value, len);
		/* memory.kmem.limit_in_bytes has been deprecated. Look at
		 * 58056f77502f3 ("memcg, kmem: further deprecate
		 * kmem.limit_in_bytes") for more details. */
		if (ret == -1 && errno == EOPNOTSUPP &&
		    !strcmp(cg_prop_entry_p->name, "memory.kmem.limit_in_bytes"))
			ret = len;
		if (ret != len) {
			pr_perror("Failed writing %s to %s", cg_prop_entry_p->value, path);
			if (!skip_fails)
				goto out;
		}
	}

	exit_code = 0;
out:
	if (close(fd) != 0)
		pr_perror("Failed closing %s", path);

	return exit_code;
}

static CgroupPropEntry *freezer_state_entry;
static char freezer_path[PATH_MAX];

int restore_freezer_state(void)
{
	size_t freezer_path_len;

	if (!freezer_state_entry)
		return 0;

	freezer_path_len = strlen(freezer_path);
	return restore_cgroup_prop(freezer_state_entry, freezer_path, freezer_path_len, false, false);
}

static void add_freezer_state_for_restore(CgroupPropEntry *entry, char *path, size_t path_len)
{
	BUG_ON(path_len >= sizeof(freezer_path));

	if (freezer_state_entry) {
		int max_len, i;

		max_len = strlen(freezer_path);
		if (max_len > path_len)
			max_len = path_len;

		/* If there are multiple freezer.state properties, that means they had
		 * one common path prefix with no tasks in it. Let's find that common
		 * prefix.
		 */
		for (i = 0; i < max_len; i++) {
			if (freezer_path[i] != path[i]) {
				freezer_path[i] = 0;
				return;
			}
		}
	}

	freezer_state_entry = entry;
	/* Path is not null terminated at path_len */
	strncpy(freezer_path, path, path_len);
	freezer_path[path_len] = 0;
}

/*
 * Filter out ifpriomap interfaces which have 0 as priority.
 * As by default new ifpriomap has 0 as a priority for each
 * interface, this will save up some write()'s.
 * As this property is used rarely, this may save a whole bunch
 * of syscalls, skipping all ifpriomap restore.
 */
static int filter_ifpriomap(char *out, char *line)
{
	char *next_line, *space;
	bool written = false;
	size_t len;

	if (*line == '\0')
		return 0;

	do {
		next_line = strchrnul(line, '\n');
		len = next_line - line;

		space = strchr(line, ' ');
		if (!space) {
			pr_err("Invalid value for ifpriomap: `%s'\n", line);
			return -1;
		}

		if (!strtol(space, NULL, 10))
			goto next;

		/* Copying with last \n or \0 */
		strncpy(out, line, len + 1);
		out += len + 1;
		written = true;
	next:
		line = next_line + 1;
	} while (*next_line != '\0');

	if (written)
		*(out - 1) = '\0';

	return 0;
}

static int restore_cgroup_ifpriomap(CgroupPropEntry *cpe, char *path, int off)
{
	CgroupPropEntry priomap = *cpe;
	int ret = -1;

	priomap.value = xmalloc(strlen(cpe->value) + 1);
	priomap.value[0] = '\0';

	if (filter_ifpriomap(priomap.value, cpe->value))
		goto out;

	if (strlen(priomap.value))
		ret = restore_cgroup_prop(&priomap, path, off, true, true);
	else
		ret = 0;

out:
	xfree(priomap.value);
	return ret;
}

static int prepare_cgroup_dir_properties(char *path, int off, CgroupDirEntry **ents, unsigned int n_ents)
{
	unsigned int i, j;

	for (i = 0; i < n_ents; i++) {
		CgroupDirEntry *e = ents[i];
		size_t off2 = off;

		if (strcmp(e->dir_name, "") == 0)
			goto skip; /* skip root cgroups */

		off2 += sprintf(path + off, "/%s", e->dir_name);
		for (j = 0; j < e->n_properties; ++j) {
			CgroupPropEntry *p = e->properties[j];

			if (!strcmp(p->name, "freezer.state")) {
				add_freezer_state_for_restore(p, path, off2);
				continue; /* skip restore now */
			}

			/* Skip restoring special cpuset props now.
			 * They were restored earlier, and can cause
			 * the restore to fail if some other task has
			 * entered the cgroup.
			 */
			if (is_special_property(p->name))
				continue;

			/*
			 * The kernel can't handle it in one write()
			 * Number of network interfaces on host may differ.
			 */
			if (strcmp(p->name, "net_prio.ifpriomap") == 0) {
				if (restore_cgroup_ifpriomap(p, path, off2))
					return -1;
				continue;
			}

			if (restore_cgroup_prop(p, path, off2, false, false) < 0)
				return -1;
		}
	skip:
		if (prepare_cgroup_dir_properties(path, off2, e->children, e->n_children) < 0)
			return -1;
	}

	return 0;
}

int prepare_cgroup_properties(void)
{
	char cname_path[PATH_MAX];
	unsigned int i, off;

	for (i = 0; i < n_controllers; i++) {
		CgControllerEntry *c = controllers[i];

		if (c->n_cnames < 1) {
			pr_err("Each CgControllerEntry should have at least 1 cname\n");
			return -1;
		}

		off = ctrl_dir_and_opt(c, cname_path, sizeof(cname_path), NULL, 0);
		if (prepare_cgroup_dir_properties(cname_path, off, c->dirs, c->n_dirs) < 0)
			return -1;
	}

	return 0;
}

/*
 * The devices cgroup must be restored in a special way:
 * only the contents of devices.list can be read, and it is a whitelist
 * of all the devices the cgroup is allowed to create. To re-create
 * this whitelist, we firstly deny everything via devices.deny,
 * and then write the list back into devices.allow.
 *
 * Further, we must have a write() call for each line, because the kernel
 * only parses the first line of any write().
 */
static int restore_devices_list(char *paux, size_t off, CgroupPropEntry *pr)
{
	CgroupPropEntry dev_allow = *pr;
	CgroupPropEntry dev_deny = *pr;
	int ret;

	dev_allow.name = "devices.allow";
	dev_deny.name = "devices.deny";
	dev_deny.value = "a";

	ret = restore_cgroup_prop(&dev_deny, paux, off, false, false);

	/*
	 * An empty string here means nothing is allowed,
	 * and the kernel disallows writing an "" to devices.allow,
	 * so let's just keep going.
	 */
	if (!strcmp(dev_allow.value, ""))
		return 0;

	if (ret < 0)
		return -1;

	return restore_cgroup_prop(&dev_allow, paux, off, true, false);
}

static int restore_special_property(char *paux, size_t off, CgroupPropEntry *pr)
{
	/*
	 * XXX: we can drop this hack and make memory.swappiness and
	 * memory.oom_control regular properties when we drop support for
	 * kernels < 3.16. See 3dae7fec5.
	 */
	if (!strcmp(pr->name, "memory.swappiness") && !strcmp(pr->value, "60"))
		return 0;
	if (!strcmp(pr->name, "memory.oom_control") && !strcmp(pr->value, "0"))
		return 0;

	if (!strcmp(pr->name, "devices.list")) {
		/*
		 * A bit of a fudge here. These are write only by owner
		 * by default, but the container engine could have changed
		 * the perms. We should come up with a better way to
		 * restore all of this stuff.
		 */
		pr->perms->mode = 0200;
		return restore_devices_list(paux, off, pr);
	}

	return restore_cgroup_prop(pr, paux, off, false, false);
}

static int restore_special_props(char *paux, size_t off, CgroupDirEntry *e)
{
	unsigned int j;

	pr_info("Restore special props\n");

	for (j = 0; j < e->n_properties; j++) {
		CgroupPropEntry *prop = e->properties[j];

		if (!is_special_property(prop->name))
			continue;

		if (restore_special_property(paux, off, prop) < 0) {
			pr_err("Restoring %s special property failed\n", prop->name);
			return -1;
		}
	}

	return 0;
}

static int prepare_dir_perms(int cg, char *path, CgroupPerms *perms)
{
	int fd, ret = 0;

	fd = openat(cg, path, O_DIRECTORY);
	if (fd < 0) {
		pr_perror("failed to open cg dir fd (%s) for chowning", path);
		return -1;
	}

	if (perms)
		ret = cr_fchperm(fd, perms->uid, perms->gid, perms->mode);
	close(fd);
	return ret;
}

static int prepare_cgroup_dirs(char **controllers, int n_controllers, char *paux, size_t off, CgroupDirEntry **ents,
			       size_t n_ents)
{
	size_t i, j;
	CgroupDirEntry *e;
	int cg = get_service_fd(CGROUP_YARD);

	for (i = 0; i < n_ents; i++) {
		size_t off2 = off;
		e = ents[i];

		off2 += sprintf(paux + off, "/%s", e->dir_name);

		if (faccessat(cg, paux, F_OK, 0) < 0) {
			if (errno != ENOENT) {
				pr_perror("Failed accessing cgroup dir %s", paux);
				return -1;
			}

			if (opts.manage_cgroups & (CG_MODE_NONE | CG_MODE_PROPS)) {
				pr_err("Cgroup dir %s doesn't exist\n", paux);
				return -1;
			}

			if (mkdirpat(cg, paux, 0755)) {
				pr_perror("Can't make cgroup dir %s", paux);
				return -1;
			}
			pr_info("Created cgroup dir %s\n", paux);

			if (prepare_dir_perms(cg, paux, e->dir_perms) < 0)
				return -1;

			for (j = 0; j < n_controllers; j++) {
				if (restore_special_props(paux, off2, e) < 0) {
					pr_err("Restoring special cpuset props failed!\n");
					return -1;
				}
			}
		} else {
			pr_info("Determined cgroup dir %s already exist\n", paux);

			if (opts.manage_cgroups & CG_MODE_STRICT) {
				pr_err("Abort restore of existing cgroups\n");
				return -1;
			}

			if (opts.manage_cgroups & (CG_MODE_SOFT | CG_MODE_NONE)) {
				pr_info("Skip restoring properties on cgroup dir %s\n", paux);
				if (e->n_properties > 0) {
					xfree(e->properties);
					e->properties = NULL;
					e->n_properties = 0;
				}
			}

			if (!(opts.manage_cgroups & CG_MODE_NONE) && prepare_dir_perms(cg, paux, e->dir_perms) < 0)
				return -1;
		}

		if (prepare_cgroup_dirs(controllers, n_controllers, paux, off2, e->children, e->n_children) < 0)
			return -1;
	}

	return 0;
}

/*
 * Prepare the CGROUP_YARD service descriptor. This guy is
 * tmpfs mount with the set of ctl->name directories each
 * one having the respective cgroup mounted.
 *
 * It's required for two reasons.
 *
 * First, if we move more than one task into cgroups it's
 * faster to have cgroup tree visible by them all in sime
 * single place. Searching for this thing existing in the
 * criu's space is not nice, as parsing /proc/mounts is not
 * very fast, other than this not all cgroups may be mounted.
 *
 * Second, when we have user-namespaces support we will
 * loose the ability to mount cgroups on-demand, so prepare
 * them in advance.
 */

static int prepare_cgroup_sfd(CgroupEntry *ce)
{
	int off, i, ret;
	char paux[PATH_MAX];

	if (!opts.manage_cgroups)
		return 0;

	pr_info("Preparing cgroups yard (cgroups restore mode %#x)\n", opts.manage_cgroups);

	if (opts.cgroup_yard) {
		off = sprintf(paux, "%s", opts.cgroup_yard);

		cg_yard = xstrdup(paux);
		if (!cg_yard)
			return -1;
	} else {
		off = sprintf(paux, ".criu.cgyard.XXXXXX");
		if (mkdtemp(paux) == NULL) {
			pr_perror("Can't make temp cgyard dir");
			return -1;
		}

		cg_yard = xstrdup(paux);
		if (!cg_yard) {
			rmdir(paux);
			return -1;
		}

		if (make_yard(cg_yard))
			return -1;
	}

	pr_debug("Opening %s as cg yard\n", cg_yard);
	i = open(cg_yard, O_DIRECTORY);
	if (i < 0) {
		pr_perror("Can't open cgyard");
		return -1;
	}

	ret = install_service_fd(CGROUP_YARD, i);
	if (ret < 0)
		return -1;

	paux[off++] = '/';

	for (i = 0; i < ce->n_controllers; i++) {
		int ctl_off = off, yard_off;
		char opt[128], *yard;
		CgControllerEntry *ctrl = ce->controllers[i];

		if (ctrl->n_cnames < 1) {
			pr_err("Each cg_controller_entry must have at least 1 controller\n");
			return -1;
		}

		ctl_off += ctrl_dir_and_opt(ctrl, paux + ctl_off, sizeof(paux) - ctl_off, opt, sizeof(opt));

		/* Create controller if not yet present */
		if (access(paux, F_OK)) {
			char *fstype = "cgroup";

			if (ctrl->cnames[0][0] == 0)
				fstype = "cgroup2";

			pr_debug("\tMaking controller dir %s (%s), type %s\n", paux, opt, fstype);
			if (mkdir(paux, 0700)) {
				pr_perror("\tCan't make controller dir %s", paux);
				return -1;
			}
			if (mount("none", paux, fstype, 0, opt) < 0) {
				pr_perror("\tCan't mount controller dir %s", paux);
				return -1;
			}
		}

		/*
		 * Finally handle all cgroups for this controller.
		 */
		yard = paux + strlen(cg_yard) + 1;
		yard_off = ctl_off - (strlen(cg_yard) + 1);
		if (opts.manage_cgroups &&
		    prepare_cgroup_dirs(ctrl->cnames, ctrl->n_cnames, yard, yard_off, ctrl->dirs, ctrl->n_dirs))
			return -1;
	}

	return 0;
}

static int cgroupd_unblock_sigterm(void)
{
	sigset_t unblockmask;

	sigemptyset(&unblockmask);
	sigaddset(&unblockmask, SIGTERM);

	if (sigprocmask(SIG_UNBLOCK, &unblockmask, NULL)) {
		pr_perror("cgroupd: can't unblock SIGTERM");
		return -1;
	}

	return 0;
}

/*
 * If a thread is a different cgroup set than the main thread in process,
 * it means it is in a threaded controller. This daemon receives the cg_set
 * number from the restored thread and move this thread to the correct
 * cgroup controllers
 */
static int cgroupd(int sk)
{
	/*
	 * This pairs with SIGTERM in stop_cgroupd(), and ensures that cgroupd
	 * will receive termination signal, regardless of which signal block
	 * mask was inherited.
	 */
	if (cgroupd_unblock_sigterm())
		return -1;

	pr_info("cgroud: Daemon started\n");

	while (1) {
		struct unsc_msg um;
		uns_call_t call;
		pid_t tid;
		int fd, cg_set, i;
		CgSetEntry *cg_set_entry;
		int ret;

		unsc_msg_init(&um, &call, &cg_set, NULL, 0, 0, NULL);
		ret = recvmsg(sk, &um.h, 0);
		if (ret <= 0) {
			pr_perror("cgroupd: recv req error");
			return -1;
		}

		unsc_msg_pid_fd(&um, &tid, &fd);
		pr_debug("cgroupd: move process %d into cg_set %d\n", tid, cg_set);

		cg_set_entry = find_rst_set_by_id(cg_set);
		if (!cg_set_entry) {
			pr_err("cgroupd: No set found %d\n", cg_set);
			return -1;
		}

		for (i = 0; i < cg_set_entry->n_ctls; i++) {
			int j, aux_off;
			CgMemberEntry *ce = cg_set_entry->ctls[i];
			char aux[PATH_MAX];
			CgControllerEntry *ctrl = NULL;
			const char *format;

			for (j = 0; j < n_controllers; j++) {
				CgControllerEntry *cur = controllers[j];
				if (cgroup_contains(cur->cnames, cur->n_cnames, ce->name, NULL)) {
					ctrl = cur;
					break;
				}
			}

			if (!ctrl) {
				pr_err("cgroupd: No cg_controller_entry found for %s/%s\n", ce->name, ce->path);
				return -1;
			}

			/*
			 * This is not a threaded controller, all threads in this
			 * process must be in this controller. Main thread has been
			 * restored, so this thread is in this controller already.
			 */
			if (!ctrl->has_is_threaded || !ctrl->is_threaded)
				continue;

			aux_off = ctrl_dir_and_opt(ctrl, aux, sizeof(aux), NULL, 0);
			format = ctrl->cnames[0][0] ? "/%s/tasks" : "/%s/cgroup.threads";
			snprintf(aux + aux_off, sizeof(aux) - aux_off, format, ce->path);

			/*
			 * Cgroupd runs outside of the namespaces so we don't
			 * need to use userns_call here
			 */
			if (userns_move(aux, 0, tid)) {
				pr_err("cgroupd: Can't move thread %d into %s/%s\n", tid, ce->name, ce->path);
				return -1;
			}
		}

		/*
		 * We only want to send the cred which contains thread id back.
		 * The restored thread recvmsg(MSG_PEEK) until it gets its own
		 * thread id.
		 */
		unsc_msg_init(&um, &call, &cg_set, NULL, 0, 0, &tid);
		if (sendmsg(sk, &um.h, 0) <= 0) {
			pr_perror("cgroupd: send req error");
			return -1;
		}
	}

	return 0;
}

int stop_cgroupd(void)
{
	if (cgroupd_pid) {
		sigset_t blockmask, oldmask;

		/*
		 * Block the SIGCHLD signal to avoid triggering
		 * sigchld_handler()
		 */
		sigemptyset(&blockmask);
		sigaddset(&blockmask, SIGCHLD);
		sigprocmask(SIG_BLOCK, &blockmask, &oldmask);

		kill(cgroupd_pid, SIGTERM);
		waitpid(cgroupd_pid, NULL, 0);

		sigprocmask(SIG_SETMASK, &oldmask, NULL);
	}

	return 0;
}

static int prepare_cgroup_thread_sfd(void)
{
	int sk;

	sk = start_unix_cred_daemon(&cgroupd_pid, cgroupd);
	if (sk < 0) {
		pr_err("failed to start cgroupd\n");
		return -1;
	}

	if (install_service_fd(CGROUPD_SK, sk) < 0) {
		kill(cgroupd_pid, SIGKILL);
		waitpid(cgroupd_pid, NULL, 0);
		return -1;
	}

	return 0;
}

static int rewrite_cgsets(CgroupEntry *cge, char **controllers, int n_controllers, char **dir_name, char *newroot)
{
	size_t dirlen = strlen(*dir_name);
	char *dir = *dir_name;
	char *dirnew = NULL;
	size_t i, j;

	/*
	 * For example we may have the following in the image:
	 *
	 * set
	 * 	name "hugetlb"
	 * 	path "/300"
	 *
	 * controller
	 * 	cnames hugetlb
	 * 	dirs
	 * 		dirname "300"
	 * 		properties ...
	 *
	 * when we're switching to a new root we need to change
	 * @path and don't forget to update the @dirname into
	 * new state.
	 */

	for (i = 0; i < cge->n_sets; i++) {
		CgSetEntry *set = cge->sets[i];

		for (j = 0; j < set->n_ctls; j++) {
			CgMemberEntry *cg = set->ctls[j];

			/*
			 * Make sure if it's same controller
			 * and its path with stripping leading
			 * "/" is matching to be renamed.
			 */
			if (!(cgroup_contains(controllers, n_controllers, cg->name, NULL) &&
			      strstartswith(cg->path + 1, dir)))
				continue;

			if (cg->has_cgns_prefix && cg->cgns_prefix) {
				char *prev = cg->path;

				cg->path = xsprintf("%s%s", newroot, cg->path + cg->cgns_prefix);
				if (!cg->path) {
					cg->path = prev;
					xfree(dirnew);
					return -ENOMEM;
				}
				xfree(prev);

				if (!dirnew) {
					/* -1 because cgns_prefix includes leading "/" */
					dirnew = xsprintf("%s%s", newroot, dir + cg->cgns_prefix - 1);
					if (!dirnew)
						return -ENOMEM;
				}
				cg->cgns_prefix = strlen(newroot);
			} else {
				char *prev = cg->path;
				/*
				 * If no prefix present simply rename the
				 * root but make sure the rest of path is
				 * untouched.
				 */
				cg->path = xsprintf("%s%s", newroot, cg->path + dirlen + 1);
				if (!cg->path) {
					cg->path = prev;
					xfree(dirnew);
					return -ENOMEM;
				}
				xfree(prev);
				if (!dirnew) {
					dirnew = xstrdup(newroot);
					if (!dirnew)
						return -ENOMEM;
				}
			}
		}
	}

	if (dirnew) {
		xfree(dir);
		*dir_name = dirnew;
	}
	return 0;
}

static int rewrite_cgroup_roots(CgroupEntry *cge)
{
	int i, j;
	struct cg_root_opt *o;

	for (i = 0; i < cge->n_controllers; i++) {
		CgControllerEntry *ctrl = cge->controllers[i];
		u64 ctrl_mask = (1ULL << ctrl->n_cnames) - 1;
		char *newroot = NULL;

		list_for_each_entry(o, &opts.new_cgroup_roots, node) {
			unsigned old_mask = ctrl_mask;

			/* coverity[check_return] */
			cgroup_contains(ctrl->cnames, ctrl->n_cnames, o->controller, &ctrl_mask);
			if (old_mask != ctrl_mask) {
				if (newroot && strcmp(newroot, o->newroot)) {
					pr_err("CG paths mismatch: %s %s\n", newroot, o->newroot);
					return -1;
				}
				newroot = o->newroot;
			}
			if (!ctrl_mask)
				break;
		}

		if (!newroot)
			newroot = opts.new_global_cg_root;

		if (newroot) {
			for (j = 0; j < ctrl->n_dirs; j++) {
				CgroupDirEntry *cgde = ctrl->dirs[j];

				pr_info("rewriting %s to %s\n", cgde->dir_name, newroot);
				if (rewrite_cgsets(cge, ctrl->cnames, ctrl->n_cnames, &cgde->dir_name, newroot))
					return -1;
			}
		}
	}

	return 0;
}

int prepare_cgroup(void)
{
	int ret;
	struct cr_img *img;
	CgroupEntry *ce;

	img = open_image(CR_FD_CGROUP, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &ce, PB_CGROUP);
	close_image(img);
	if (ret <= 0) /* Zero is OK -- no sets there. */
		return ret;

	if (rewrite_cgroup_roots(ce))
		return -1;

	n_sets = ce->n_sets;
	rst_sets = ce->sets;
	n_controllers = ce->n_controllers;
	controllers = ce->controllers;

	if (n_sets) {
		/*
		 * We rely on the fact that all sets contain the same
		 * set of controllers. This is checked during dump
		 * with cg_set_compare(CGCMP_ISSUB) call.
		 */
		ret = prepare_cgroup_sfd(ce);
		if (ret < 0)
			return ret;
		ret = prepare_cgroup_thread_sfd();
	} else {
		ret = 0;
	}

	return ret;
}

int new_cg_root_add(char *controller, char *newroot)
{
	struct cg_root_opt *o;

	if (!controller) {
		SET_CHAR_OPTS(new_global_cg_root, newroot);
		return 0;
	}

	o = xmalloc(sizeof(*o));
	if (!o)
		return -1;

	o->controller = xstrdup(controller);
	if (!o->controller)
		goto err_ctrl;
	o->newroot = xstrdup(newroot);
	if (!o->newroot)
		goto err_newroot;
	list_add(&o->node, &opts.new_cgroup_roots);

	return 0;
err_newroot:
	xfree(o->controller);
err_ctrl:
	xfree(o);
	return -1;
}

struct ns_desc cgroup_ns_desc = NS_DESC_ENTRY(CLONE_NEWCGROUP, "cgroup");
