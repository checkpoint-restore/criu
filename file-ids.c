#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#include "types.h"
#include "file-ids.h"
#include "rbtree.h"

#include "compiler.h"
#include "syscall.h"
#include "image.h"
#include "util.h"

/*
 * We track shared files by global rbtree, where each node might
 * be a root for subtree. The reason for that is the nature of data
 * we obtain from operating system.
 *
 * Basically OS provides us two ways to distinguish files
 *
 *  - information obtained from fstat call
 *  - shiny new sys_kcmp system call (which may compare the file descriptor
 *    pointers inside the kernel and provide us order info)
 *
 * So, to speedup procedure of searching for shared file descriptors
 * we use both techniques. From fstat call we get that named general file
 * IDs (genid) which are carried in the main rbtree.
 *
 * In case if two genid are the same -- we need to use a second way and
 * call for sys_kcmp. Thus, if kernel tells us that files have identical
 * genid but in real they are different from kernel point of view -- we assign
 * a second unique key (subid) to such file descriptor and put it into a subtree.
 *
 * So the tree will look like
 *
 *               (root)
 *               genid-1
 *              /    \
 *         genid-2  genid-3
 *            / \    / \
 *
 * Where each genid node might be a sub-rbtree as well
 *
 *               (genid-N)
 *               /      \
 *           subid-1   subid-2
 *            / \       / \
 *
 * Carrying two rbtree at once allow us to minimize the number
 * of sys_kcmp syscalls, also to collect and dump file descriptors
 * in one pass.
 */

struct fd_id_entry {
	struct rb_node	node;

	struct rb_root	subtree_root;
	struct rb_node	subtree_node;

	u32		genid;	/* generic id, may have duplicates */
	u32		subid;	/* subid is always unique */

	pid_t		pid;
	int		fd;
} __aligned(sizeof(long));

static void show_subnode(struct rb_node *node, int self)
{
	struct fd_id_entry *this = rb_entry(node, struct fd_id_entry, subtree_node);

	pr_info("\t\t| %x.%x %s\n", this->genid, this->subid,
			self ? "(self)" : "");
	if (node->rb_left) {
		pr_info("\t\t| left:\n");
		show_subnode(node->rb_left, 0);
		pr_info("\t\t| --l\n");
	}
	if (node->rb_right) {
		pr_info("\t\t| right:\n");
		show_subnode(node->rb_right, 0);
		pr_info("\t\t| --r\n");
	}
}

static void show_subtree(struct rb_root *root)
{
	pr_info("\t\t| SubTree\n");
	show_subnode(root->rb_node, 1);
}

static void show_node(struct rb_node *node)
{
	struct fd_id_entry *this = rb_entry(node, struct fd_id_entry, node);

	pr_info("\t%x.%x\n", this->genid, this->subid);
	if (node->rb_left) {
		pr_info("\tleft:\n");
		show_node(node->rb_left);
		pr_info("\t--l\n");
	}
	if (node->rb_right) {
		pr_info("\tright:\n");
		show_node(node->rb_right);
		pr_info("\t--r\n");
	}

	show_subtree(&this->subtree_root);
	pr_info("\t--s\n");
}

static struct rb_root fd_id_root = RB_ROOT;

void fd_id_show_tree(void)
{
	struct rb_root *root = &fd_id_root;

	pr_info("\tTree of file IDs\n");
	if (root->rb_node)
		show_node(root->rb_node);
}

static unsigned long fd_id_entries_subid = 1;

static struct fd_id_entry *alloc_fd_id_entry(pid_t pid, struct fdinfo_entry *fe)
{
	struct fd_id_entry *e;

	e = xmalloc(sizeof(*e));
	if (!e)
		goto err;

	e->subid	= fd_id_entries_subid++;
	e->genid	= fe->id;
	e->pid		= pid;
	e->fd		= (int)fe->addr;

	/* Make sure no overflow here */
	BUG_ON(!e->subid);

	rb_init_node(&e->node);
	rb_init_node(&e->subtree_node);
	e->subtree_root = RB_ROOT;
	rb_link_and_balance(&e->subtree_root, &e->subtree_node,
			NULL, &e->subtree_root.rb_node);
err:
	return e;
}

static struct fd_id_entry *fd_id_generate_sub(struct fd_id_entry *e,
		pid_t pid, struct fdinfo_entry *fe, int *new_id)
{
	struct rb_node *node = e->subtree_root.rb_node;
	struct fd_id_entry *sub = NULL;

	struct rb_node **new = &e->subtree_root.rb_node;
	struct rb_node *parent = NULL;

	BUG_ON(!node);

	while (node) {
		struct fd_id_entry *this = rb_entry(node, struct fd_id_entry, subtree_node);
		int ret = sys_kcmp(this->pid, pid, KCMP_FILE, this->fd, (int)fe->addr);

		parent = *new;
		if (ret < 0)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (ret > 0)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}

	sub = alloc_fd_id_entry(pid, fe);
	if (!sub)
		return NULL;

	rb_link_and_balance(&e->subtree_root, &sub->subtree_node, parent, new);
	*new_id = 1;
	return sub;
}

static struct fd_id_entry *fd_id_generate_gen(pid_t pid,
		struct fdinfo_entry *fe, int *new_id)
{
	struct rb_node *node = fd_id_root.rb_node;
	struct fd_id_entry *e = NULL;

	struct rb_node **new = &fd_id_root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct fd_id_entry *this = rb_entry(node, struct fd_id_entry, node);

		parent = *new;
		if (fe->id < this->genid)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (fe->id > this->genid)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return fd_id_generate_sub(this, pid, fe, new_id);
	}

	e = alloc_fd_id_entry(pid, fe);
	if (!e)
		return NULL;

	rb_link_and_balance(&fd_id_root, &e->node, parent, new);
	*new_id = 1;
	return e;

}

u32 fd_id_generate_special(void)
{
	return fd_id_entries_subid++;
}

int fd_id_generate(pid_t pid, struct fdinfo_entry *fe)
{
	struct fd_id_entry *fid;
	int new_id = 0;

	if (fd_is_special(fe)) {
		fe->id = fd_id_generate_special();
		return 1;
	}

	fid = fd_id_generate_gen(pid, fe, &new_id);
	if (!fid)
		return -ENOMEM;

	fe->id = fid->subid;
	return new_id;
}
