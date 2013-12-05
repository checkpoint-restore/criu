#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "asm/int.h"

#include "mount-btrfs.h"
#include "proc_parse.h"
#include "xmalloc.h"
#include "string.h"
#include "mount.h"
#include "util.h"
#include "log.h"

/*
 * All subvolumes are bound to a mountpoint as rbtree.
 *
 *    mountpoint     mountpoint     mountpoint
 *       |               |              |
 *    private         private        private
 *       |               |              |
 *     root             root           root
 *      / \             / \            / \
 * subvol subvol   subvol subvol  subvol subvol
 *   ...   ...       ...   ...       ...   ...
 *
 * For convenient interface and fast lookup we also
 * bind all roots to a global forest.
 *
 * WARNING: We assume that we're running on LE machine!
 *
 * Also we are NOT freeing memory allocated for all this
 * structures, the kernel will free them for us.
 *
 * FIXME: We're not handling overmounted paths.
 */

#undef	LOG_PREFIX
#define LOG_PREFIX "btrfs: "

struct btrfs_subvol_root {
	struct rb_root			rb_root;
	struct rb_node			rb_node;

	struct mount_info const         *m;

	u64				tree_id;
	dev_t				st_dev;
};

struct btrfs_subvol_node {
	struct rb_node			rb_node;

	u64				root_id;
	u64				ref_tree;
	u64				dir_id;

	struct rb_node			rb_dev;
	dev_t				st_dev;

	char				*name;		/* name from ioctl */
	char				*path;		/* path to subvolume, may be partial */
	char				*full;		/* full path to subvolume */
	int				deleted;	/* if deleted */
};

static struct rb_root btrfs_forest = RB_ROOT;

static struct btrfs_subvol_node *btrfs_node_lookup_dev(struct btrfs_subvol_root *r, dev_t dev)
{
	struct rb_node *e = r->rb_root.rb_node;
	struct btrfs_subvol_node *n;

	while (e) {
		n = rb_entry(e, struct btrfs_subvol_node, rb_node);
		if (n->st_dev > dev)
			e = e->rb_left;
		else if (n->st_dev < dev)
			e = e->rb_right;
		else
			return n;
	}
	return NULL;
}

static int btrfs_insert_node(struct btrfs_subvol_root *r, struct btrfs_subvol_node *n)
{
	struct rb_node **p = &r->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct btrfs_subvol_node *cur;

	while(*p) {
		parent = *p;
		cur = rb_entry(parent, struct btrfs_subvol_node, rb_node);
		if (cur->root_id > n->root_id)
			p = &(*p)->rb_left;
		else if (cur->root_id < n->root_id)
			p = &(*p)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&n->rb_node, parent, p);
	rb_insert_color(&n->rb_node, &r->rb_root);
	return 0;
}

static struct btrfs_subvol_root *btrfs_vol_lookup_dev(dev_t dev)
{
	struct rb_node *e = btrfs_forest.rb_node;
	struct btrfs_subvol_root *n;

	while (e) {
		n = rb_entry(e, struct btrfs_subvol_root, rb_node);
		if (n->m->s_dev > dev)
			e = e->rb_left;
		else if (n->m->s_dev < dev)
			e = e->rb_right;
		else
			return n;
	}
	return NULL;
}

static int btrfs_insert_vol(struct btrfs_subvol_root *r)
{
	struct rb_node **p = &btrfs_forest.rb_node;
	struct rb_node *parent = NULL;
	struct btrfs_subvol_root *cur;

	while(*p) {
		parent = *p;
		cur = rb_entry(parent, struct btrfs_subvol_root, rb_node);
		if (cur->m->s_dev > r->m->s_dev)
			p = &(*p)->rb_left;
		else if (cur->m->s_dev < r->m->s_dev)
			p = &(*p)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&r->rb_node, parent, p);
	rb_insert_color(&r->rb_node, &btrfs_forest);
	return 0;
}

static struct btrfs_subvol_node *btrfs_lookup_node(struct btrfs_subvol_root *r, u64 root_id)
{
	struct btrfs_subvol_node *n;
	struct rb_node *e = r->rb_root.rb_node;

	while (e) {
		n = rb_entry(e, struct btrfs_subvol_node, rb_node);
		if (n->root_id > root_id)
			e = e->rb_left;
		else if (n->root_id < root_id)
			e = e->rb_right;
		else
			return n;
	}
	return NULL;
}

static struct btrfs_subvol_node *btrfs_create_node(void)
{
	struct btrfs_subvol_node *n;

	n = xzalloc(sizeof(*n));
	if (!n)
		return NULL;

	rb_init_node(&n->rb_node);
	rb_init_node(&n->rb_dev);
	return n;
}

static struct btrfs_subvol_root *btrfs_create_root(int fd, struct mount_info *m, struct stat *st)
{
	struct btrfs_ioctl_ino_lookup_args args = { };
	struct btrfs_subvol_root *r;

	r = xzalloc(sizeof(*r));
	if (!r)
		return NULL;
	r->rb_root = RB_ROOT;
	rb_init_node(&r->rb_node);

	args.objectid = BTRFS_FIRST_FREE_OBJECTID;
	if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args) < 0) {
		pr_perror("Can't find mount point tree-id");
		xfree(r);
		return NULL;
	}

	r->st_dev = st->st_dev;
	r->tree_id = args.treeid;
	r->m = m;
	return r;
}

static int btrfs_resolve_stat(struct btrfs_subvol_root *r, struct btrfs_subvol_node *n)
{
	char path[PATH_MAX];
	struct stat st;

	if (n->deleted || !n->ref_tree)
		return 0;

	strlcpy(path, r->m->mountpoint, sizeof(path));
	strlcat(path, "/", sizeof(path));
	strlcat(path, n->full, sizeof(path));

	if (stat(path, &st)) {
		pr_perror("Can't get stat on `%s'", path);
		return -1;
	}

	n->st_dev = st.st_dev;
	return 0;
}

static int btrfs_resolve_full(struct btrfs_subvol_root *r, struct btrfs_subvol_node *n)
{
	struct btrfs_subvol_node *found = n;
	char *full_path = NULL;
	size_t len = 0;

	while (1) {
		size_t add_len;
		char *tmp;
		u64 next;

		if (!found->ref_tree) {
			xfree(full_path);
			return -ENOENT;
		}

		add_len = strlen(found->path);

		if (full_path) {
			tmp = xmalloc(add_len + 2 + len);
			if (!tmp)
				return -ENOMEM;
			memcpy(tmp + add_len + 1, full_path, len);
			tmp[add_len] = '/';
			memcpy(tmp, found->path, add_len);
			tmp[add_len + len + 1] = '\0';
			xfree(full_path);
			full_path = tmp;
			len += add_len + 1;
		} else {
			full_path = xstrdup(found->path);
			if (!full_path)
				return -ENOMEM;
			len = add_len;
		}

		next = found->ref_tree;
		if (next == r->tree_id)
			break;
		else if (next == BTRFS_FS_TREE_OBJECTID)
			break;

		found = btrfs_lookup_node(r, next);
		if (!found) {
			xfree(full_path);
			return -ENOENT;
		}
	}

	n->full = full_path;
	return 0;
}

static int btrfs_add_update_node(struct btrfs_subvol_root *r,
				 struct btrfs_ioctl_search_header *sh,
				 struct btrfs_root_ref *ref)
{
	struct btrfs_subvol_node *n;

	n = btrfs_lookup_node(r, sh->objectid);
	if (!n) {
		n = btrfs_create_node();
		if  (!n) {
			pr_err("Can't create node for %s\n", r->m->mountpoint);
			return -1;
		}

		n->root_id = sh->objectid;

		if (btrfs_insert_node(r, n)) {
			pr_err("Can't insert node for %s\n", r->m->mountpoint);
			return -1;
		}
	}

	if (sh->type == BTRFS_ROOT_BACKREF_KEY) {
		char *name = (char *)(ref + 1);

		if (name && ref->name_len) {
			char *new = xrealloc(n->name, ref->name_len + 1);
			if (!new) {
				pr_err("Failed to update node name for %s\n", r->m->mountpoint);
				return -1;
			}
			n->name = new;
			memcpy(n->name, name, ref->name_len);
			n->name[ref->name_len] = '\0';
		}
		n->ref_tree	= sh->offset;
		n->dir_id	= ref->dirid;
	} else if (sh->type == BTRFS_ROOT_ITEM_KEY) {
		n->ref_tree	= 0;
		n->dir_id	= 0;
	}

	return 0;
}

static int btrfs_resolve_all(int fd, struct btrfs_subvol_root *r)
{
	struct btrfs_ioctl_ino_lookup_args args;
	struct btrfs_subvol_node *node;
	struct rb_node *nd;
	int ret;

	for (nd = rb_first(&r->rb_root); nd; nd = rb_next(nd)) {
		node = rb_entry(nd, struct btrfs_subvol_node, rb_node);

		if (!node->ref_tree)
			continue;

		memzero(&args, sizeof(args));
		args.treeid	= node->ref_tree;
		args.objectid	= node->dir_id;

		if (ioctl(fd, BTRFS_IOC_INO_LOOKUP, &args) < 0) {
			pr_perror("Failed to lookup inode");
			return -1;
		}

		if (args.name[0]) {
			node->path = xmalloc(strlen(node->name) + strlen(args.name) + 1);
			if (!node->path) {
				pr_err("Can't resolve path\n");
				return -1;
			}
			strcpy(node->path, args.name);
			strcat(node->path, node->name);
		} else {
			node->path = strdup(node->name);
			if (!node->path) {
				pr_err("Can't duplicate path\n");
				return -1;
			}
		}
	}

	for (nd = rb_first(&r->rb_root); nd; nd = rb_next(nd)) {
		node = rb_entry(nd, struct btrfs_subvol_node, rb_node);

		ret = btrfs_resolve_full(r, node);
		if (ret == -ENOENT)
			node->deleted = 1;
		else if (ret != 0)
			return -1;

		if (btrfs_resolve_stat(r, node))
			return -1;
	}

	return 0;
}

static void btrfs_show_subvolumes(struct btrfs_subvol_root *r)
{
	struct btrfs_subvol_node *node;
	struct rb_node *nd;

	if (log_get_loglevel() < LOG_DEBUG)
		return;

	pr_debug("\tmountpoint %s tree_id %llx\n",
		 r->m->mountpoint, (long long)r->tree_id);

	for (nd = rb_first(&r->rb_root); nd; nd = rb_next(nd)) {
		node = rb_entry(nd, struct btrfs_subvol_node, rb_node);

		pr_debug("\t\troot_id %llx ref_tree %llx dir_id %llx "
			 "dev %lx full %s\n",
			 (long long)node->root_id, (long long)node->ref_tree,
			 (long long)node->dir_id, (long)node->st_dev, node->full);
	}
}

static void *btrfs_parse_volume(struct mount_info *m)
{
	struct btrfs_ioctl_search_args tree_args;
	struct btrfs_ioctl_search_header sh;
	struct btrfs_ioctl_search_key *sk = &tree_args.key;

	struct btrfs_subvol_root *r, *result = NULL;

	unsigned long off, i;
	int ret = -1, fd = -1;
	struct stat st;

	memzero(&tree_args, sizeof(tree_args));

	sk->tree_id		= 1;
	sk->max_type		= BTRFS_ROOT_BACKREF_KEY;
	sk->min_type		= BTRFS_ROOT_ITEM_KEY;
	sk->min_objectid	= BTRFS_FIRST_FREE_OBJECTID;
	sk->max_objectid	= BTRFS_LAST_FREE_OBJECTID;
	sk->max_offset		= (u64)-1;
	sk->max_transid		= (u64)-1;
	sk->nr_items		= 4096;

	fd = open(m->mountpoint, O_RDONLY);
	if (fd < 0) {
		pr_perror("Can't open %s", m->mountpoint);
		goto err;
	}

	if (stat(m->mountpoint, &st)) {
		pr_perror("Can't get stat on %s", m->mountpoint);
		goto err;
	}

	r = btrfs_create_root(fd, m, &st);
	if (!r) {
		pr_err("Can't create btrfs root for %s\n", m->mountpoint);
		goto err;
	}

	while(1) {
		ret = ioctl(fd, BTRFS_IOC_TREE_SEARCH, &tree_args);
		if (ret < 0) {
			pr_perror("Failed to search tree for %s", m->mountpoint);
			goto err;
		} else if (sk->nr_items == 0)
			break;

		for (off = 0, i = 0; i < sk->nr_items; i++) {
			memcpy(&sh, tree_args.buf + off, sizeof(sh));
			off += sizeof(sh);

			if (sh.type == BTRFS_ROOT_BACKREF_KEY || sh.type == BTRFS_ROOT_ITEM_KEY) {
				ret = btrfs_add_update_node(r, &sh, (void *)(tree_args.buf + off));
				if (ret)
					goto err;
			}

			off += sh.len;
			sk->min_objectid = sh.objectid;
			sk->min_type = sh.type;
			sk->min_offset = sh.offset;
		}

		sk->nr_items = 4096;
		sk->min_offset++;
		if (!sk->min_offset)
			sk->min_type++;
		else
			continue;

		if (sk->min_type > BTRFS_ROOT_BACKREF_KEY) {
			sk->min_type = BTRFS_ROOT_ITEM_KEY;
			sk->min_objectid++;
		} else
			continue;

		if (sk->min_objectid > sk->max_objectid)
			break;
	}

	ret = btrfs_resolve_all(fd, r);
	if (ret)
		goto err;
	if (btrfs_insert_vol(r))
		goto err;

	BUG_ON(m->private);
	m->private = (void *)result;
	btrfs_show_subvolumes(r);
	result = r;
err:
	close_safe(&fd);
	return (void *)result;
}

int btrfs_parse_mountinfo(struct mount_info *m)
{
	return btrfs_parse_volume(m) ? 0 : -1;
}

bool is_btrfs_subvol(dev_t vol_id, dev_t dev_id)
{
	struct btrfs_subvol_root *r;

	r = btrfs_vol_lookup_dev(vol_id);
	if (r) {
		if (r->st_dev == dev_id)
			return true;
		else
			return btrfs_node_lookup_dev(r, dev_id) != NULL;
	}

	return false;
}
