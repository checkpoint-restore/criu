#define LOG_PREFIX	"cg: "
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include "xmalloc.h"
#include "cgroup.h"
#include "pstree.h"
#include "proc_parse.h"
#include "util.h"
#include "fdset.h"
#include "protobuf.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/cgroup.pb-c.h"

/*
 * This structure describes set of controller groups
 * a task lives in. The cg_ctl entries are stored in
 * the @ctls list sorted by the .name field.
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
static char *cg_yard;
static struct cg_set *root_cgset; /* Set root item lives in */
static struct cg_set *criu_cgset; /* Set criu process lives in */
static u32 cg_set_ids = 1;

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

		if (log_get_loglevel() >= LOG_DEBUG) {
			struct cg_ctl *ctl;

			list_for_each_entry(ctl, &cs->ctls, l)
				pr_debug("    `- [%s] -> [%s]\n", ctl->name, ctl->path);
		}
	}

	return cs;
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
	}

	*cg_id = cs->id;
	return 0;
}

static int dump_sets(CgroupEntry *cg)
{
	struct cg_set *set;
	struct cg_ctl *ctl;
	int s, c;
	void *m;
	CgSetEntry *se;
	ControllerEntry *ce;

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
		m = xmalloc(se->n_ctls * (sizeof(ControllerEntry *) + sizeof(ControllerEntry)));
		se->ctls = m;
		ce = m + se->n_ctls * sizeof(ControllerEntry *);
		if (!m)
			return -1;

		c = 0;
		list_for_each_entry(ctl, &set->ctls, l) {
			pr_info("   `- Dumping %s of %s\n", ctl->name, ctl->path);
			controller_entry__init(ce);
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

	pr_info("Writing CG image\n");
	return pb_write_one(fdset_fd(glob_fdset, CR_FD_CGROUP), &cg, PB_CGROUP);
}

static int move_in_cgroup(CgSetEntry *se)
{
	int cg, i;

	pr_info("Move into %d\n", se->id);
	cg = get_service_fd(CGROUP_YARD);
	for (i = 0; i < se->n_ctls; i++) {
		char aux[1024];
		int fd, err;
		ControllerEntry *ce = se->ctls[i];

		sprintf(aux, "%s/%s/tasks", ce->name, ce->path);
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
			pr_perror("Can't move into %s (%d/%d)\n",
					aux, err, fd);
			return -1;
		}
	}

	close_service_fd(CGROUP_YARD);
	return 0;
}

int prepare_task_cgroup(struct pstree_item *me)
{
	CgSetEntry *se;
	u32 current_cgset;

	if (!me->rst->cg_set)
		return 0;

	if (me->parent)
		current_cgset = me->parent->rst->cg_set;
	else
		current_cgset = root_cg_set;

	if (me->rst->cg_set == current_cgset) {
		pr_info("Cgroups %d inherited from parent\n", current_cgset);
		close_service_fd(CGROUP_YARD);
		return 0;
	}

	se = find_rst_set_by_id(me->rst->cg_set);
	if (!se) {
		pr_err("No set %d found\n", me->rst->cg_set);
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

static int prepare_cgroup_sfd(CgSetEntry *root_set)
{
	int off, i;
	char paux[PATH_MAX], aux[128];

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

	for (i = 0; i < root_set->n_ctls; i++) {
		ControllerEntry *ce = root_set->ctls[i];
		char *opt = ce->name;

		sprintf(paux + off, "/%s", ce->name);
		if (strstartswith(ce->name, "name=")) {
			sprintf(aux, "none,%s", ce->name);
			opt = aux;
		}

		if (mkdir(paux, 0700)) {
			pr_perror("Can't make cgyard subdir");
			goto err;
		}

		if (mount("none", paux, "cgroup", 0, opt) < 0) {
			pr_perror("Can't mount %s cgyard", ce->name);
			goto err;
		}
	}

	pr_debug("Opening %s as cg yard\n", cg_yard);
	i = open(cg_yard, O_DIRECTORY);
	if (i < 0) {
		pr_perror("Can't open cgyard");
		goto err;
	}

	off = install_service_fd(CGROUP_YARD, i);
	close(i);
	if (off < 0)
		goto err;

	return 0;

err:
	fini_cgroup();
	return -1;
}

int prepare_cgroup(void)
{
	int fd, ret;
	CgroupEntry *ce;

	fd = open_image(CR_FD_CGROUP, O_RSTR | O_OPT);
	if (fd < 0) {
		if (errno == ENOENT) /* backward compatibility */
			return 0;
		else
			return fd;
	}

	ret = pb_read_one_eof(fd, &ce, PB_CGROUP);
	close(fd);
	if (ret <= 0) /* Zero is OK -- no sets there. */
		return ret;

	n_sets = ce->n_sets;
	rst_sets = ce->sets;
	if (n_sets)
		/*
		 * We rely on the fact that all sets contain the same
		 * set of controllers. This is checked during dump
		 * with cg_set_compare(CGCMP_ISSUB) call.
		 */
		ret = prepare_cgroup_sfd(rst_sets[0]);
	else
		ret = 0;

	return ret;
}
