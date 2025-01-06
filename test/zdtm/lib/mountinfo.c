#include <stdio.h>
#include <string.h>

#include "mountinfo.h"
#include "fs.h"
#include "xmalloc.h"

/*
 * mountinfo contains mangled paths. space, tab and back slash were replaced
 * with usual octal escape. This function replaces these symbols back.
 */
static void cure_path(char *path)
{
	int i, len, off = 0;

	if (strchr(path, '\\') == NULL) /* fast path */
		return;

	len = strlen(path);
	for (i = 0; i < len; i++) {
		if (!strncmp(path + i, "\\040", 4)) {
			path[i - off] = ' ';
			goto replace;
		} else if (!strncmp(path + i, "\\011", 4)) {
			path[i - off] = '\t';
			goto replace;
		} else if (!strncmp(path + i, "\\134", 4)) {
			path[i - off] = '\\';
			goto replace;
		}
		if (off)
			path[i - off] = path[i];
		continue;
	replace:
		off += 3;
		i += 3;
	}
	path[len - off] = 0;
}

static struct mountinfo_zdtm *mountinfo_zdtm_alloc(struct mntns_zdtm *mntns)
{
	struct mountinfo_zdtm *new;

	new = xzalloc(sizeof(struct mountinfo_zdtm));
	if (new)
		list_add_tail(&new->list, &mntns->mountinfo_list);
	return new;
}

static void mountinfo_zdtm_free(struct mountinfo_zdtm *mountinfo)
{
	list_del(&mountinfo->list);
	xfree(mountinfo->mountpoint);
	xfree(mountinfo->root);
	xfree(mountinfo->fstype);
	xfree(mountinfo);
}

static void mountinfo_zdtm_free_all(struct mntns_zdtm *mntns)
{
	struct mountinfo_zdtm *mountinfo, *tmp;

	list_for_each_entry_safe(mountinfo, tmp, &mntns->mountinfo_list, list)
		mountinfo_zdtm_free(mountinfo);
}

#define BUF_SIZE 4096
char buf[BUF_SIZE];

int mntns_parse_mountinfo(struct mntns_zdtm *mntns)
{
	FILE *f;
	int ret;

	INIT_LIST_HEAD(&mntns->mountinfo_list);

	f = fopen("/proc/self/mountinfo", "r");
	if (!f) {
		pr_perror("Failed to open mountinfo");
		return -1;
	}

	while (fgets(buf, BUF_SIZE, f)) {
		struct mountinfo_zdtm *new;
		unsigned int kmaj, kmin;
		char *str, *hyphen, *shared, *master;
		int n;

		new = mountinfo_zdtm_alloc(mntns);
		if (!new) {
			pr_perror("Failed to alloc mountinfo_zdtm");
			goto free;
		}

		ret = sscanf(buf, "%i %i %u:%u %ms %ms %*s %n", &new->mnt_id, &new->parent_mnt_id, &kmaj, &kmin,
			     &new->root, &new->mountpoint, &n);
		if (ret != 6) {
			pr_perror("Failed to parse mountinfo line \"%s\"", buf);
			goto free;
		}
		cure_path(new->root);
		cure_path(new->mountpoint);
		new->s_dev = MKKDEV(kmaj, kmin);

		str = buf + n;
		hyphen = strstr(buf, " - ");
		if (!hyphen) {
			pr_perror("Failed to find \" - \" in mountinfo line \"%s\"", buf);
			goto free;
		}
		*hyphen++ = '\0';

		shared = strstr(str, "shared:");
		if (shared)
			new->shared_id = atoi(shared + 7);
		master = strstr(str, "master:");
		if (master)
			new->master_id = atoi(master + 7);

		ret = sscanf(hyphen, "- %ms", &new->fstype);
		if (ret != 1) {
			pr_perror("Failed to parse fstype in mountinfo tail \"%s\"", hyphen);
			goto free;
		}
	}

	fclose(f);
	return 0;
free:
	mountinfo_zdtm_free_all(mntns);
	fclose(f);
	return -1;
}

static struct mountinfo_topology *mountinfo_topology_alloc(struct mntns_zdtm *mntns, struct mountinfo_zdtm *mountinfo)
{
	struct mountinfo_topology *new;

	new = xzalloc(sizeof(struct mountinfo_topology));
	if (new) {
		new->mountinfo = mountinfo;
		new->topology_id = -1;
		INIT_LIST_HEAD(&new->children);
		INIT_LIST_HEAD(&new->siblings);
		list_add_tail(&new->list, &mntns->topology_list);
		INIT_LIST_HEAD(&new->sharing_list);
	}
	return new;
}

static void mountinfo_topology_free(struct mountinfo_topology *topology)
{
	list_del(&topology->list);
	xfree(topology);
}

static void mountinfo_topology_free_all(struct mntns_zdtm *mntns)
{
	struct mountinfo_topology *topology, *tmp;

	list_for_each_entry_safe(topology, tmp, &mntns->topology_list, list)
		mountinfo_topology_free(topology);
}

static struct mountinfo_topology *mountinfo_topology_lookup_parent(struct mntns_zdtm *mntns,
								   struct mountinfo_topology *topology)
{
	struct mountinfo_topology *parent;

	list_for_each_entry(parent, &mntns->topology_list, list) {
		if (parent->mountinfo->mnt_id == topology->mountinfo->parent_mnt_id)
			return parent;
	}

	return NULL;
}

static struct mountinfo_topology *mt_subtree_next(struct mountinfo_topology *mt, struct mountinfo_topology *root)
{
	if (!list_empty(&mt->children))
		return list_entry(mt->children.next, struct mountinfo_topology, siblings);

	while (mt->parent && mt != root) {
		if (mt->siblings.next == &mt->parent->children)
			mt = mt->parent;
		else
			return list_entry(mt->siblings.next, struct mountinfo_topology, siblings);
	}

	return NULL;
}

static void __mt_resort_siblings(struct mountinfo_topology *parent)
{
	LIST_HEAD(list);

	while (!list_empty(&parent->children)) {
		struct mountinfo_topology *m, *p;

		m = list_first_entry(&parent->children, struct mountinfo_topology, siblings);
		list_del(&m->siblings);

		list_for_each_entry(p, &list, siblings)
			if (strcmp(p->mountinfo->mountpoint, m->mountinfo->mountpoint) < 0)
				break;

		list_add_tail(&m->siblings, &p->siblings);
	}

	list_splice(&list, &parent->children);
}

static void mntns_mt_resort_siblings(struct mntns_zdtm *mntns)
{
	struct mountinfo_topology *mt = mntns->tree;
	LIST_HEAD(mtlist);
	int i = 0;

	while (1) {
		/* Assign topology id to mt in dfs order */
		mt->topology_id = i++;
		list_move_tail(&mt->list, &mtlist);
		__mt_resort_siblings(mt);
		mt = mt_subtree_next(mt, mntns->tree);
		if (!mt)
			break;
	}

	/* Update mntns->topology_list in dfs order */
	list_splice(&mtlist, &mntns->topology_list);
}

static struct sharing_group *sharing_group_find_or_alloc(struct mntns_zdtm *mntns, int shared_id, int master_id,
							 unsigned int s_dev)
{
	struct sharing_group *sg;

	list_for_each_entry(sg, &mntns->sharing_groups_list, list) {
		if ((sg->shared_id == shared_id) && (sg->master_id == master_id)) {
			if (sg->s_dev != s_dev) {
				pr_err("Sharing/devid inconsistency\n");
				return NULL;
			}
			return sg;
		}
	}

	sg = xzalloc(sizeof(struct sharing_group));
	if (!sg)
		return NULL;

	sg->shared_id = shared_id;
	sg->master_id = master_id;
	sg->s_dev = s_dev;
	sg->topology_id = -1;

	INIT_LIST_HEAD(&sg->children);
	INIT_LIST_HEAD(&sg->siblings);
	INIT_LIST_HEAD(&sg->mounts_list);

	list_add_tail(&sg->list, &mntns->sharing_groups_list);

	return sg;
}

static void sharing_group_free(struct sharing_group *sg)
{
	list_del(&sg->list);
	xfree(sg);
}

static void sharing_group_free_all(struct mntns_zdtm *mntns)
{
	struct sharing_group *sg, *tmp;

	list_for_each_entry_safe(sg, tmp, &mntns->sharing_groups_list, list)
		sharing_group_free(sg);
}

static struct sharing_group *sharing_group_lookup_parent(struct mntns_zdtm *mntns, struct sharing_group *sg)
{
	struct sharing_group *parent;

	list_for_each_entry(parent, &mntns->sharing_groups_list, list) {
		if (parent->shared_id == sg->master_id)
			return parent;
	}

	/* Create "external" sharing */
	parent = sharing_group_find_or_alloc(mntns, sg->master_id, 0, sg->s_dev);
	if (parent)
		return parent;

	return NULL;
}

static int mntns_build_tree(struct mntns_zdtm *mntns)
{
	struct mountinfo_topology *topology, *parent, *tree = NULL;
	struct mountinfo_zdtm *mountinfo;
	struct sharing_group *sg, *sg_parent;

	INIT_LIST_HEAD(&mntns->topology_list);

	/* Prealloc mount tree */
	list_for_each_entry(mountinfo, &mntns->mountinfo_list, list) {
		topology = mountinfo_topology_alloc(mntns, mountinfo);
		if (!topology)
			goto err;
	}

	/* Build mount tree */
	list_for_each_entry(topology, &mntns->topology_list, list) {
		parent = mountinfo_topology_lookup_parent(mntns, topology);
		if (!parent) {
			if (tree) {
				pr_err("Bad mount tree with too roots %d and %d\n", tree->mountinfo->mnt_id,
				       parent->mountinfo->mnt_id);
				goto err;
			}
			tree = topology;
		} else {
			topology->parent = parent;
			list_add_tail(&topology->siblings, &parent->children);
		}
	}
	mntns->tree = tree;

	/* Sort mounts by mountpoint */
	mntns_mt_resort_siblings(mntns);

	INIT_LIST_HEAD(&mntns->sharing_groups_list);

	/* Prealloc sharing groups */
	list_for_each_entry(topology, &mntns->topology_list, list) {
		if (!topology->mountinfo->shared_id && !topology->mountinfo->master_id)
			continue;

		/*
		 * Due to mntns->topology_list is sorted in dfs order
		 * sharing groups are also sorted the same
		 */
		sg = sharing_group_find_or_alloc(mntns, topology->mountinfo->shared_id, topology->mountinfo->master_id,
						 topology->mountinfo->s_dev);
		if (!sg)
			goto err;

		list_add_tail(&topology->sharing_list, &sg->mounts_list);
		topology->sharing = sg;

		/* Set sharing group topology id to minimal topology id of it's mounts */
		if (sg->topology_id == -1 || topology->topology_id < sg->topology_id)
			sg->topology_id = topology->topology_id;
	}

	/* Build sharing group trees */
	list_for_each_entry(sg, &mntns->sharing_groups_list, list) {
		if (sg->master_id) {
			sg_parent = sharing_group_lookup_parent(mntns, sg);
			sg->parent = sg_parent;
			list_add(&sg->siblings, &sg_parent->children);
		}
	}

	return 0;
err:
	mountinfo_topology_free_all(mntns);
	sharing_group_free_all(mntns);
	return -1;
}

static int mountinfo_topology_list_compare(struct mntns_zdtm *mntns_a, struct mntns_zdtm *mntns_b)
{
	struct mountinfo_topology *topology_a, *topology_b;

	topology_a = list_first_entry(&mntns_a->topology_list, struct mountinfo_topology, list);
	topology_b = list_first_entry(&mntns_b->topology_list, struct mountinfo_topology, list);

	while (&topology_a->list != &mntns_a->topology_list && &topology_b->list != &mntns_b->topology_list) {
		if (topology_a->topology_id != topology_b->topology_id) {
			pr_err("Mounts %d and %d have different topology id %d and %d\n", topology_a->mountinfo->mnt_id,
			       topology_b->mountinfo->mnt_id, topology_a->topology_id, topology_b->topology_id);
			return -1;
		}

		if (topology_a->parent && topology_b->parent) {
			if (topology_a->parent->topology_id != topology_b->parent->topology_id) {
				pr_err("Mounts %d and %d have different parent topology id %d and %d\n",
				       topology_a->mountinfo->mnt_id, topology_b->mountinfo->mnt_id,
				       topology_a->parent->topology_id, topology_b->parent->topology_id);
				return -1;
			}
		} else if (topology_a->parent || topology_b->parent) {
			pr_err("One of mounts %d and %d has parent and other doesn't\n", topology_a->mountinfo->mnt_id,
			       topology_b->mountinfo->mnt_id);
			return -1;
		}

		if (topology_a->sharing && topology_b->sharing) {
			if (topology_a->sharing->topology_id != topology_b->sharing->topology_id) {
				pr_err("Mounts %d and %d have different sharing topology id %d and %d\n",
				       topology_a->mountinfo->mnt_id, topology_b->mountinfo->mnt_id,
				       topology_a->sharing->topology_id, topology_b->sharing->topology_id);
				return -1;
			}
		} else if (topology_a->sharing || topology_b->sharing) {
			pr_err("One of mounts %d and %d has sharing and other doesn't\n", topology_a->mountinfo->mnt_id,
			       topology_b->mountinfo->mnt_id);
			return -1;
		}

		topology_a = list_entry(topology_a->list.next, struct mountinfo_topology, list);
		topology_b = list_entry(topology_b->list.next, struct mountinfo_topology, list);
	}
	if (&topology_a->list != &mntns_a->topology_list || &topology_b->list != &mntns_b->topology_list) {
		pr_err("Mount tree topology length mismatch\n");
		return -1;
	}

	return 0;
}

static int sharing_group_list_compare(struct mntns_zdtm *mntns_a, struct mntns_zdtm *mntns_b)
{
	struct sharing_group *sg_a, *sg_b;

	sg_a = list_first_entry(&mntns_a->sharing_groups_list, struct sharing_group, list);
	sg_b = list_first_entry(&mntns_b->sharing_groups_list, struct sharing_group, list);

	while (&sg_a->list != &mntns_a->sharing_groups_list && &sg_b->list != &mntns_b->sharing_groups_list) {
		if (sg_a->topology_id != sg_b->topology_id) {
			pr_err("Sharings (%d,%d) and (%d,%d) have different sharing topology id %d and %d\n",
			       sg_a->shared_id, sg_a->master_id, sg_b->shared_id, sg_b->master_id, sg_a->topology_id,
			       sg_b->topology_id);
			return -1;
		}

		if (sg_a->parent && sg_b->parent) {
			if (sg_a->parent->topology_id != sg_b->parent->topology_id) {
				pr_err("Sharings (%d,%d) and (%d,%d) have different parent topology id %d and %d\n",
				       sg_a->shared_id, sg_a->master_id, sg_b->shared_id, sg_b->master_id,
				       sg_a->parent->topology_id, sg_b->parent->topology_id);
				return -1;
			}
		} else if (sg_a->parent || sg_b->parent) {
			pr_err("One of sharings (%d,%d) and (%d,%d) has parent and other doesn't\n", sg_a->shared_id,
			       sg_a->master_id, sg_b->shared_id, sg_b->master_id);
			return -1;
		}

		sg_a = list_entry(sg_a->list.next, struct sharing_group, list);
		sg_b = list_entry(sg_b->list.next, struct sharing_group, list);
	}

	if (&sg_a->list != &mntns_a->sharing_groups_list || &sg_b->list != &mntns_b->sharing_groups_list) {
		pr_err("Mount tree sharing topology length mismatch\n");
		return -1;
	}

	return 0;
}

int mntns_compare(struct mntns_zdtm *mntns_a, struct mntns_zdtm *mntns_b)
{
	if (mntns_build_tree(mntns_a)) {
		pr_err("Failed to build first mountinfo topology tree\n");
		return -1;
	}

	if (mntns_build_tree(mntns_b)) {
		pr_err("Failed to build second mountinfo topology tree\n");
		return -1;
	}

	if (mountinfo_topology_list_compare(mntns_a, mntns_b))
		return -1;

	if (sharing_group_list_compare(mntns_a, mntns_b))
		return -1;

	return 0;
}

void mntns_free_all(struct mntns_zdtm *mntns)
{
	mountinfo_zdtm_free_all(mntns);
	mountinfo_topology_free_all(mntns);
	sharing_group_free_all(mntns);
}
