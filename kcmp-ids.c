#include <unistd.h>
#include <stdlib.h>
#include "types.h"
#include "rbtree.h"
#include "util.h"
#include "syscall.h"
#include "kcmp-ids.h"

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

struct kid_entry {
	struct rb_node	node;

	struct rb_root	subtree_root;
	struct rb_node	subtree_node;

	u32		subid;	/* subid is always unique */
	struct kid_elem	elem;
} __aligned(sizeof(long));

static void show_subnode(struct rb_node *node, int self)
{
	struct kid_entry *this = rb_entry(node, struct kid_entry, subtree_node);

	pr_info("\t\t| %#x.%#x %s\n", this->elem.genid, this->subid,
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
	struct kid_entry *this = rb_entry(node, struct kid_entry, node);

	pr_info("\t%#x.%#x\n", this->elem.genid, this->subid);
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

void kid_show_tree(struct kid_tree *tree)
{
	struct rb_root *root = &tree->root;

	pr_info("\tTree of %d objects\n", tree->kcmp_type);
	if (root->rb_node)
		show_node(root->rb_node);
}

static struct kid_entry *alloc_kid_entry(struct kid_tree *tree, struct kid_elem *elem)
{
	struct kid_entry *e;

	e = xmalloc(sizeof(*e));
	if (!e)
		goto err;

	e->subid	= tree->subid++;
	e->elem		= *elem;

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

static u32 kid_generate_sub(struct kid_tree *tree, struct kid_entry *e,
		struct kid_elem *elem, int *new_id)
{
	struct rb_node *node = e->subtree_root.rb_node;
	struct kid_entry *sub = NULL;

	struct rb_node **new = &e->subtree_root.rb_node;
	struct rb_node *parent = NULL;

	BUG_ON(!node);

	while (node) {
		struct kid_entry *this = rb_entry(node, struct kid_entry, subtree_node);
		int ret = sys_kcmp(this->elem.pid, elem->pid, tree->kcmp_type,
				this->elem.idx, elem->idx);

		parent = *new;
		if (ret < 0)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (ret > 0)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this->subid;
	}

	sub = alloc_kid_entry(tree, elem);
	if (!sub)
		return 0;

	rb_link_and_balance(&e->subtree_root, &sub->subtree_node, parent, new);
	*new_id = 1;
	return sub->subid;
}

u32 kid_generate_gen(struct kid_tree *tree,
		struct kid_elem *elem, int *new_id)
{
	struct rb_node *node = tree->root.rb_node;
	struct kid_entry *e = NULL;

	struct rb_node **new = &tree->root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct kid_entry *this = rb_entry(node, struct kid_entry, node);

		parent = *new;
		if (elem->genid < this->elem.genid)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (elem->genid > this->elem.genid)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return kid_generate_sub(tree, this, elem, new_id);
	}

	e = alloc_kid_entry(tree, elem);
	if (!e)
		return 0;

	rb_link_and_balance(&tree->root, &e->node, parent, new);
	*new_id = 1;
	return e->subid;

}

