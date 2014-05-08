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
static struct cg_set *root_cgset; /* Set root item lives in */
static struct cg_set *criu_cgset; /* Set criu process lives in */
static u32 cg_set_ids = 1;

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
