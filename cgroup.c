#define LOG_PREFIX	"cg: "
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
#include "list.h"
#include "xmalloc.h"
#include "cgroup.h"
#include "cr_options.h"
#include "pstree.h"
#include "proc_parse.h"
#include "util.h"
#include "imgset.h"
#include "util-pie.h"
#include "protobuf.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/cgroup.pb-c.h"

/*
 * These string arrays have the names of all the properties that will be
 * restored. To add a property for a cgroup type, add it to the
 * corresponding char array above the NULL terminator. If you are adding
 * a new cgroup family all together, you must also edit get_known_properties()
 * Currently the code only supports properties with 1 value
 */

static const char *cpu_props[] = {
	"cpu.shares",
	"cpu.cfs_period_us",
	"cpu.cfs_quota_us",
	"cpu.rt_period_us",
	"cpu.rt_runtime_us",
	"notify_on_release",
	NULL
};

static const char *memory_props[] = {
	/* limit_in_bytes and memsw.limit_in_bytes must be set in this order */
	"memory.limit_in_bytes",
	"memory.memsw.limit_in_bytes",
	"memory.use_hierarchy",
	"notify_on_release",
	NULL
};

static const char *cpuset_props[] = {
	/*
	 * cpuset.cpus and cpuset.mems must be set before the process moves
	 * into its cgroup; they are "initialized" below to whatever the root
	 * values are in copy_special_cg_props so as not to cause ENOSPC when
	 * values are restored via this code.
	 */
	"cpuset.cpus",
	"cpuset.mems",
	"cpuset.memory_migrate",
	"cpuset.cpu_exclusive",
	"cpuset.mem_exclusive",
	"cpuset.mem_hardwall",
	"cpuset.memory_spread_page",
	"cpuset.memory_spread_slab",
	"cpuset.sched_load_balance",
	"cpuset.sched_relax_domain_level",
	"notify_on_release",
	NULL
};

static const char *blkio_props[] = {
	"blkio.weight",
	"notify_on_release",
	NULL
};

static const char *freezer_props[] = {
	"notify_on_release",
	NULL
};

/*
 * This structure describes set of controller groups
 * a task lives in. The cg_ctl entries are stored in
 * the @ctls list sorted by the .name field and then
 * by the .path field.
 */

struct cg_set {
	u32			id;
	struct list_head	l;
	unsigned int 		n_ctls;
	struct list_head	ctls;
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

static CgSetEntry *find_rst_set_by_id(u32 id)
{
	int i;

	for (i = 0; i < n_sets; i++)
		if (rst_sets[i]->id == id)
			return rst_sets[i];

	return NULL;
}

#define CGCMP_MATCH	1	/* check for exact match */
#define CGCMP_ISSUB	2	/* check set is subset of ctls */

static bool cg_set_compare(struct cg_set *set, struct list_head *ctls, int what)
{
	struct list_head *l1 = &set->ctls, *l2 = ctls;

	while (1) {
		struct cg_ctl *c1 = NULL, *c2 = NULL;

		if (l1->next != &set->ctls)
			c1 = list_first_entry(l1, struct cg_ctl, l);
		if (l2->next != ctls)
			c2 = list_first_entry(l2, struct cg_ctl, l);

		if (!c1 || !c2) /* Nowhere to move next */
			return !c1 && !c2; /* Both lists scanned -- match */

		if (strcmp(c1->name, c2->name))
			return false;

		switch (what) {
		case CGCMP_MATCH:
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

static struct cg_set *get_cg_set(struct list_head *ctls, unsigned int n_ctls)
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
		list_splice(ctls, &cs->ctls);
		cs->n_ctls = n_ctls;
		list_add_tail(&cs->l, &cg_sets);
		n_sets++;

		if (!pr_quelled(LOG_DEBUG)) {
			struct cg_ctl *ctl;

			list_for_each_entry(ctl, &cs->ctls, l)
				pr_debug("    `- [%s] -> [%s]\n", ctl->name, ctl->path);
		}
	}

	return cs;
}

struct cg_controller *new_controller(const char *name, int heirarchy)
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
	nc->heirarchy = heirarchy;

	nc->n_heads = 0;
	INIT_LIST_HEAD(&nc->heads);

	return nc;
}

int parse_cg_info(void)
{
	if (parse_cgroups(&cgroups, &n_cgroups) < 0)
		return -1;

	return 0;
}

/* Check that co-mounted controllers from /proc/cgroups (e.g. cpu and cpuacct)
 * are contained in a comma separated string (e.g. from /proc/self/cgroup or
 * mount options). */
static bool cgroup_contains(char **controllers, unsigned int n_controllers, char *name)
{
	unsigned int i;
	bool all_match = true;
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
static struct cg_controller	*current_controller;
static unsigned int		path_pref_len;

#define EXACT_MATCH	0
#define PARENT_MATCH	1
#define NO_MATCH	2

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

	fd = open(fullpath, O_RDONLY);
	if (fd == -1) {
		property->value = NULL;
		pr_perror("Failed opening %s", fullpath);
		return -1;
	}

	ret = read(fd, buf, sizeof(buf) - 1);
	if (ret == -1) {
		pr_err("Failed scanning %s\n", fullpath);
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

static const char **get_known_properties(char *controller)
{
	const char **prop_arr = NULL;

	if (!strcmp(controller, "cpu"))
		prop_arr = cpu_props;
	else if (!strcmp(controller, "memory"))
		prop_arr = memory_props;
	else if (!strcmp(controller, "cpuset"))
		prop_arr = cpuset_props;
	else if (!strcmp(controller, "blkio"))
		prop_arr = blkio_props;
	else if (!strcmp(controller, "freezer"))
		prop_arr = freezer_props;

	return prop_arr;
}

static int add_cgroup_properties(const char *fpath, struct cgroup_dir *ncd,
				 struct cg_controller *controller)
{
	int i, j;
	char buf[PATH_MAX];
	struct cgroup_prop *prop;

	for (i = 0; i < controller->n_controllers; ++i) {

		const char **prop_arr = get_known_properties(controller->controllers[i]);

		for (j = 0; prop_arr != NULL && prop_arr[j] != NULL; ++j) {
			if (snprintf(buf, PATH_MAX, "%s/%s", fpath, prop_arr[j]) >= PATH_MAX) {
				pr_err("snprintf output was truncated");
				return -1;
			}

			if (access(buf, F_OK) < 0 && errno == ENOENT) {
				pr_info("Couldn't open %s. This cgroup property may not exist on this kernel\n", buf);
				continue;
			}

			prop = create_cgroup_prop(prop_arr[j]);
			if (!prop) {
				free_all_cgroup_props(ncd);
				return -1;
			}

			if (read_cgroup_prop(prop, buf) < 0) {
				free_cgroup_prop(prop);
				free_all_cgroup_props(ncd);
				return -1;
			}

			pr_info("Dumping value %s from %s/%s\n", prop->value, fpath, prop->name);
			list_add_tail(&prop->list, &ncd->properties);
			ncd->n_properties++;
		}
	}

	return 0;
}

static int add_cgroup(const char *fpath, const struct stat *sb, int typeflag)
{
	struct cgroup_dir *ncd = NULL, *match;
	int ret = 0;

	if (typeflag == FTW_D) {
		int mtype;

		pr_info("adding cgroup %s\n", fpath);

		ncd = xmalloc(sizeof(*ncd));
		if (!ncd)
			goto out;

		/* chop off the first "/proc/self/fd/N" str */
		if (fpath[path_pref_len] == '\0')
			ncd->path = xstrdup("/");
		else
			ncd->path = xstrdup(fpath + path_pref_len);

		if (!ncd->path)
			goto out;

		mtype = find_dir(ncd->path, &current_controller->heads, &match);

		switch (mtype) {
		/* ignore co-mounted cgroups */
		case EXACT_MATCH:
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
			ret = -1;
			goto out;
		}

		return 0;
	} else
		return 0;

out:
	if (ncd)
		xfree(ncd->path);
	xfree(ncd);
	return ret;
}

static int collect_cgroups(struct list_head *ctls)
{
	struct cg_ctl *cc;
	int ret = 0;
	int fd = -1;

	list_for_each_entry(cc, ctls, l) {
		char path[PATH_MAX], mopts[1024];
		char *name, prefix[] = ".criu.cgmounts.XXXXXX";
		struct cg_controller *cg;

		current_controller = NULL;

		/* We should get all the "real" (i.e. not name=systemd type)
		 * controller from parse_cgroups(), so find that controller if
		 * it exists. */
		list_for_each_entry(cg, &cgroups, l) {
			if (cgroup_contains(cg->controllers, cg->n_controllers, cc->name)) {
				current_controller = cg;
				break;
			}
		}

		if (!current_controller) {
			/* only allow "fake" controllers to be created this way */
			if (!strstartswith(cc->name, "name=")) {
				pr_err("controller %s not found\n", cc->name);
				ret = -1;
				goto out;
			} else {
				struct cg_controller *nc = new_controller(cc->name, -1);
				list_add_tail(&nc->l, &cg->l);
				n_cgroups++;
				current_controller = nc;
			}
		}

		if (!opts.manage_cgroups)
			continue;

		if (strstartswith(cc->name, "name=")) {
			name = cc->name + 5;
			snprintf(mopts, sizeof(mopts), "none,%s", cc->name);
		} else {
			name = cc->name;
			snprintf(mopts, sizeof(mopts), "%s", name);
		}

		if (mkdtemp(prefix) == NULL) {
			pr_perror("can't make dir for cg mounts");
			return -1;
		}

		if (mount("none", prefix, "cgroup", 0, mopts) < 0) {
			pr_perror("couldn't mount %s", mopts);
			rmdir(prefix);
			return -1;
		}

		fd = open_detach_mount(prefix);
		if (fd < 0)
			return -1;

		path_pref_len = snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
		snprintf(path + path_pref_len, PATH_MAX - path_pref_len, "%s", cc->path);

		ret = ftw(path, add_cgroup, 4);
		if (ret < 0) {
			pr_perror("failed walking %s for empty cgroups", path);
			goto out;
		}

out:
		close_safe(&fd);

		if (ret < 0)
			return ret;
	}

	return 0;
}

int dump_task_cgroup(struct pstree_item *item, u32 *cg_id)
{
	int pid;
	LIST_HEAD(ctls);
	unsigned int n_ctls = 0;
	struct cg_set *cs;

	if (item)
		pid = item->pid.real;
	else
		pid = getpid();

	pr_info("Dumping cgroups for %d\n", pid);
	if (parse_task_cgroup(pid, &ctls, &n_ctls))
		return -1;

	cs = get_cg_set(&ctls, n_ctls);
	if (!cs)
		return -1;

	if (!item) {
		BUG_ON(criu_cgset);
		criu_cgset = cs;
		pr_info("Set %d is criu one\n", cs->id);
	} else if (item == root_item) {
		BUG_ON(root_cgset);
		root_cgset = cs;
		pr_info("Set %d is root one\n", cs->id);

		/*
		 * The on-stack ctls is moved into cs inside
		 * the get_cg_set routine.
		 */
		if (cs != criu_cgset && collect_cgroups(&cs->ctls))
			return -1;
	}

	*cg_id = cs->id;
	return 0;
}

static int dump_cg_dir_props(struct list_head *props, size_t n_props,
			     CgroupPropEntry ***ents)
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
		cpe->name = xstrdup(prop_cur->name);
		cpe->value = xstrdup(prop_cur->value);
		if (!cpe->name || !cpe->value)
			goto error;
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
		cde->dir_name = cur->path + poff;
		if (poff != 1) /* parent isn't "/" */
			cde->dir_name++; /* leading / */
		cde->n_children = cur->n_children;
		if (cur->n_children > 0)
			if (dump_cg_dirs(&cur->children, cur->n_children, &cde->children, strlen(cur->path)) < 0) {
				xfree(*ents);
				return -1;
			}

		cde->n_properties = cur->n_properties;
		if (cde->n_properties > 0) {
			if (dump_cg_dir_props(&cur->properties,
					      cde->n_properties, &cde->properties) < 0) {
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

		ce->cnames = cur->controllers;
		ce->n_cnames = cur->n_controllers;
		ce->n_dirs = cur->n_heads;
		if (ce->n_dirs > 0)
			if (dump_cg_dirs(&cur->heads, cur->n_heads, &ce->dirs, 0) < 0) {
				xfree(cg->controllers);
				return -1;
			}
		cg->controllers[i++] = ce++;
	}

	return 0;
}


static int dump_sets(CgroupEntry *cg)
{
	struct cg_set *set;
	struct cg_ctl *ctl;
	int s, c;
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
		 * Check that all sets we've found that tasks live in are
		 * subsets of the one root task lives in
		 */

		pr_info(" `- Dumping %d set (%d ctls)\n", set->id, set->n_ctls);
		if (!cg_set_compare(set, &root_cgset->ctls, CGCMP_ISSUB)) {
			pr_err("Set %d is not subset of %d\n",
					set->id, root_cgset->id);
			return -1;
		}

		/*
		 * Now encode them onto the image entry
		 */

		cg_set_entry__init(se);
		se->id = set->id;

		se->n_ctls = set->n_ctls;
		m = xmalloc(se->n_ctls * (sizeof(CgMemberEntry *) + sizeof(CgMemberEntry)));
		se->ctls = m;
		ce = m + se->n_ctls * sizeof(CgMemberEntry *);
		if (!m)
			return -1;

		c = 0;
		list_for_each_entry(ctl, &set->ctls, l) {
			pr_info("   `- Dumping %s of %s\n", ctl->name, ctl->path);
			cg_member_entry__init(ce);
			ce->name = ctl->name;
			ce->path = ctl->path;
			se->ctls[c++] = ce++;
		}

		cg->sets[s++] = se++;
	}

	return 0;
}

int dump_cgroups(void)
{
	CgroupEntry cg = CGROUP_ENTRY__INIT;

	BUG_ON(!criu_cgset || !root_cgset);

	/*
	 * Check whether root task lives in its own set as compared
	 * to criu. If yes, we should not dump anything, but make
	 * sure no other sets exist. The latter case can be supported,
	 * but requires some trickery and is hardly needed at the
	 * moment.
	 */

	if (root_cgset == criu_cgset) {
		if (!list_is_singular(&cg_sets)) {
			pr_err("Non supported sub-cgroups found\n");
			return -1;
		}

		pr_info("All tasks in criu's cgroups. Nothing to dump.\n");
		return 0;
	}

	if (dump_sets(&cg))
		return -1;
	if (dump_controllers(&cg))
		return -1;

	pr_info("Writing CG image\n");
	return pb_write_one(img_from_set(glob_imgset, CR_FD_CGROUP), &cg, PB_CGROUP);
}

static int ctrl_dir_and_opt(CgControllerEntry *ctl, char *dir, int ds,
		char *opt, int os)
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

static const char *special_cpuset_props[] = {
	"cpuset.cpus",
	"cpuset.mems",
	NULL,
};

static int move_in_cgroup(CgSetEntry *se)
{
	int cg, i;

	pr_info("Move into %d\n", se->id);
	cg = get_service_fd(CGROUP_YARD);
	for (i = 0; i < se->n_ctls; i++) {
		char aux[PATH_MAX];
		int fd, err, j, aux_off;
		CgMemberEntry *ce = se->ctls[i];
		CgControllerEntry *ctrl = NULL;

		for (j = 0; j < n_controllers; j++) {
			CgControllerEntry *cur = controllers[j];
			if (cgroup_contains(cur->cnames, cur->n_cnames, ce->name)) {
				ctrl = cur;
				break;
			}
		}

		if (!ctrl) {
			pr_err("No cg_controller_entry found for %s/%s\n", ce->name, ce->path);
			return -1;
		}

		aux_off = ctrl_dir_and_opt(ctrl, aux, sizeof(aux), NULL, 0);

		snprintf(aux + aux_off, sizeof(aux) - aux_off, "/%s/tasks", ce->path);
		pr_debug("  `-> %s\n", aux);
		err = fd = openat(cg, aux, O_WRONLY);
		if (fd >= 0) {
			/*
			 * Writing zero into this file moves current
			 * task w/o any permissions checks :)
			 */
			err = write(fd, "0", 1);
			close(fd);
		}

		if (err < 0) {
			pr_perror("Can't move into %s (%d/%d)", aux, err, fd);
			return -1;
		}
	}

	return 0;
}

int prepare_task_cgroup(struct pstree_item *me)
{
	CgSetEntry *se;
	u32 current_cgset;

	if (!rsti(me)->cg_set)
		return 0;

	if (me->parent)
		current_cgset = rsti(me->parent)->cg_set;
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
	umount2(cg_yard, MNT_DETACH);
	rmdir(cg_yard);
	xfree(cg_yard);
	cg_yard = NULL;
}

static int restore_cgroup_prop(const CgroupPropEntry * cg_prop_entry_p,
			       char *path, int off)
{
	FILE *f;
	int cg;

	if (!cg_prop_entry_p->value) {
		pr_err("cg_prop_entry->value was empty when should have had a value");
		return -1;
	}

	if (snprintf(path + off, PATH_MAX - off, "/%s", cg_prop_entry_p->name) >= PATH_MAX) {
		pr_err("snprintf output was truncated for %s\n", cg_prop_entry_p->name);
		return -1;
	}

	cg = get_service_fd(CGROUP_YARD);
	f = fopenat(cg, path, "w+");
	if (!f) {
		pr_perror("Failed opening %s for writing", path);
		return -1;
	}

	if (fprintf(f, "%s", cg_prop_entry_p->value) < 0) {
		fclose(f);
		pr_err("Failed writing %s to %s\n", cg_prop_entry_p->value, path);
		return -1;
	}

	if (fclose(f) != 0) {
		pr_perror("Failed closing %s", path);
		return -1;
	}

	pr_info("Restored cgroup property value %s to %s\n", cg_prop_entry_p->value, path);
	return 0;
}

static int prepare_cgroup_dir_properties(char *path, int off, CgroupDirEntry **ents,
					 unsigned int n_ents)
{
	unsigned int i, j;

	for (i = 0; i < n_ents; i++) {
		CgroupDirEntry *e = ents[i];
		size_t off2 = off;

		off2 += sprintf(path + off, "/%s", e->dir_name);
		if (e->n_properties > 0) {
			for (j = 0; j < e->n_properties; ++j) {
				if (restore_cgroup_prop(e->properties[j], path, off2) < 0)
					return -1;
			}
		}

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

static int restore_special_cpuset_props(char *paux, size_t off, CgroupDirEntry *e)
{
	int i, j;

	for (i = 0; special_cpuset_props[i]; i++) {
		const char *name = special_cpuset_props[i];

		for (j = 0; j < e->n_properties; j++) {
			CgroupPropEntry *prop = e->properties[j];

			if (strcmp(name, prop->name) == 0)
				if (restore_cgroup_prop(prop, paux, off) < 0)
					return -1;
		}
	}

	return 0;
}

static int prepare_cgroup_dirs(char **controllers, int n_controllers, char *paux, size_t off,
				CgroupDirEntry **ents, size_t n_ents)
{
	size_t i, j;
	CgroupDirEntry *e;
	int cg = get_service_fd(CGROUP_YARD);

	for (i = 0; i < n_ents; i++) {
		size_t off2 = off;
		e = ents[i];
		struct stat st;

		off2 += sprintf(paux + off, "/%s", e->dir_name);

		/*
		 * Checking to see if file already exists. If not, create it. If
		 * it does exist, prevent us from overwriting the properties
		 * later by removing the CgroupDirEntry's properties.
		 */
		if (fstatat(cg, paux, &st, 0) < 0) {
			if (errno != ENOENT) {
				pr_perror("Failed accessing file %s", paux);
				return -1;
			}

			if (mkdirpat(cg, paux)) {
				pr_perror("Can't make cgroup dir %s", paux);
				return -1;
			}
			pr_info("Created dir %s\n", paux);

			for (j = 0; j < n_controllers; j++) {
				if (strcmp(controllers[j], "cpuset") == 0) {
					if (restore_special_cpuset_props(paux, off2, e) < 0) {
						pr_err("Restoring special cpuset props failed!\n");
						return -1;
					}
				}
			}
		} else {
			if (e->n_properties > 0) {
				xfree(e->properties);
				e->properties = NULL;
				e->n_properties = 0;
			}
			pr_info("Determined dir %s already existed\n", paux);
		}

		if (prepare_cgroup_dirs(controllers, n_controllers, paux, off2,
				e->children, e->n_children) < 0)
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

	pr_info("Preparing cgroups yard\n");

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

	if (mount("none", cg_yard, "tmpfs", 0, NULL)) {
		pr_perror("Can't mount tmpfs in cgyard");
		goto err;
	}

	if (mount("none", cg_yard, NULL, MS_PRIVATE, NULL)) {
		pr_perror("Can't make cgyard private");
		goto err;
	}

	pr_debug("Opening %s as cg yard\n", cg_yard);
	i = open(cg_yard, O_DIRECTORY);
	if (i < 0) {
		pr_perror("Can't open cgyard");
		goto err;
	}

	ret = install_service_fd(CGROUP_YARD, i);
	close(i);
	if (ret < 0)
		goto err;


	paux[off++] = '/';

	for (i = 0; i < ce->n_controllers; i++) {
		int ctl_off = off, yard_off;
		char opt[128], *yard;
		CgControllerEntry *ctrl = ce->controllers[i];

		if (ctrl->n_cnames < 1) {
			pr_err("Each cg_controller_entry must have at least 1 controller");
			goto err;
		}

		ctl_off += ctrl_dir_and_opt(ctrl,
				paux + ctl_off, sizeof(paux) - ctl_off,
				opt, sizeof(opt));

		pr_debug("\tMaking subdir %s (%s)\n", paux, opt);
		if (mkdir(paux, 0700)) {
			pr_perror("Can't make cgyard subdir %s", paux);
			goto err;
		}

		if (mount("none", paux, "cgroup", 0, opt) < 0) {
			pr_perror("Can't mount %s cgyard", paux);
			goto err;
		}

		/* We skip over the .criu.cgyard.XXXXXX/, since those will be
		 * referred to by the cg yard service fd. */
		yard = paux + strlen(cg_yard) + 1;
		yard_off = ctl_off - (strlen(cg_yard) + 1);
		if (opts.manage_cgroups &&
		    prepare_cgroup_dirs(ctrl->cnames, ctrl->n_cnames, yard, yard_off,
				ctrl->dirs, ctrl->n_dirs))
			goto err;

	}

	return 0;

err:
	fini_cgroup();
	return -1;
}

static int rewrite_cgsets(CgroupEntry *cge, char **controllers, int n_controllers,
			  char *from, char *to)
{
	int i, j;
	for (i = 0; i < cge->n_sets; i++) {
		CgSetEntry *set = cge->sets[i];
		for (j = 0; j < set->n_ctls; j++) {
			CgMemberEntry *cg = set->ctls[j];
			if (cgroup_contains(controllers, n_controllers, cg->name) &&
					/* +1 to get rid of leading / */
					strstartswith(cg->path + 1, from)) {

				/* +1 to get rid of leading /, again */
				int off = strlen(from) + 1;

				/* +1 for trailing NULL */
				int newlen = strlen(to) + strlen(cg->path + off) + 1;
				char *m = xmalloc(newlen * sizeof(char*));
				if (!m)
					return -1;

				sprintf(m, "%s%s", to, cg->path + off);
				free(cg->path);
				cg->path = m;
			}
		}

	}
	return 0;
}

static int rewrite_cgroup_roots(CgroupEntry *cge)
{
	int i, j;
	struct cg_root_opt *o;
	char *newroot = NULL;

	for (i = 0; i < cge->n_controllers; i++) {
		CgControllerEntry *ctrl = cge->controllers[i];
		newroot = opts.new_global_cg_root;

		list_for_each_entry(o, &opts.new_cgroup_roots, node) {
			if (cgroup_contains(ctrl->cnames, ctrl->n_cnames, o->controller)) {
				newroot = o->newroot;
				break;
			}

		}

		if (newroot) {
			for (j = 0; j < ctrl->n_dirs; j++) {
				CgroupDirEntry *cgde = ctrl->dirs[j];
				char *m;

				pr_info("rewriting %s to %s\n", cgde->dir_name, newroot);
				if (rewrite_cgsets(cge, ctrl->cnames, ctrl->n_cnames, cgde->dir_name, newroot))
					return -1;

				m = xstrdup(newroot);
				if (!m)
					return -1;

				free(cgde->dir_name);
				cgde->dir_name = m;
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

	img = open_image(CR_FD_CGROUP, O_RSTR | O_OPT);
	if (!img) {
		if (errno == ENOENT) /* backward compatibility */
			return 0;
		else
			return -1;
	}

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

	if (n_sets)
		/*
		 * We rely on the fact that all sets contain the same
		 * set of controllers. This is checked during dump
		 * with cg_set_compare(CGCMP_ISSUB) call.
		 */
		ret = prepare_cgroup_sfd(ce);
	else
		ret = 0;

	return ret;
}

int new_cg_root_add(char *controller, char *newroot)
{
	struct cg_root_opt *o;

	if (!controller) {
		opts.new_global_cg_root = newroot;
		return 0;
	}

	o = xmalloc(sizeof(*o));
	if (!o)
		return -1;

	o->controller = controller;
	o->newroot = newroot;
	list_add(&o->node, &opts.new_cgroup_roots);
	return 0;
}
