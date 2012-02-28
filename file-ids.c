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

struct rb_root fd_id_root = RB_ROOT;
static unsigned long fd_id_entries_subid = 1;

static struct fd_id_entry *alloc_fd_id_entry(u32 genid, pid_t pid, int fd)
{
	struct fd_id_entry *e;

	e = xmalloc(sizeof(*e));
	if (!e)
		goto err;

	e->u.key.subid	= fd_id_entries_subid++;
	e->u.key.genid	= genid;
	e->pid		= pid;
	e->fd		= fd;

	/* Make sure no overflow here */
	BUG_ON(!e->u.key.subid);

	rb_init_node(&e->node);
	rb_init_node(&e->subtree_node);
	rb_attach_node(&e->subtree_root, &e->subtree_node);
err:
	return e;
}

static struct fd_id_entry *
lookup_alloc_subtree(struct fd_id_entry *e, u32 genid, pid_t pid, int fd)
{
	struct rb_node *node = e->subtree_root.rb_node;
	struct fd_id_entry *sub = NULL;

	struct rb_node **new = &e->subtree_root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct fd_id_entry *this = rb_entry(node, struct fd_id_entry, subtree_node);
		int ret = sys_kcmp(this->pid, pid, KCMP_FILE, this->fd, fd);

		parent = *new;
		if (ret < 0)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (ret > 0)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}

	sub = alloc_fd_id_entry(genid, pid, fd);
	if (!sub)
		goto err;

	rb_link_and_balance(&e->subtree_root, &sub->subtree_node, parent, new);
err:
	return sub;
}

struct fd_id_entry *fd_id_entry_collect(u32 genid, pid_t pid, int fd)
{
	struct rb_node *node = fd_id_root.rb_node;
	struct fd_id_entry *e = NULL;

	struct rb_node **new = &fd_id_root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct fd_id_entry *this = rb_entry(node, struct fd_id_entry, node);

		parent = *new;
		if (genid < this->u.key.genid)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (genid > this->u.key.genid)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return lookup_alloc_subtree(this, genid, pid, fd);
	}

	e = alloc_fd_id_entry(genid, pid, fd);
	if (!e)
		goto err;

	rb_link_and_balance(&fd_id_root, &e->node, parent, new);
err:
	return e;
}
