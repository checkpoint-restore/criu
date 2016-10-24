/*
 * RBtree implementation adopted from the Linux kernel sources.
 */

#ifndef __CR_RBTREE_H__
#define __CR_RBTREE_H__

#include <stddef.h>

#include "common/compiler.h"

#define	RB_RED		0
#define	RB_BLACK	1
#define RB_MASK		3

struct rb_node {
	unsigned long	rb_parent_color; /* Keeps both parent anc color */
	struct rb_node	*rb_right;
	struct rb_node	*rb_left;
} __aligned(sizeof(long));

struct rb_root {
	struct rb_node	*rb_node;
};

#define rb_parent(r)	((struct rb_node *)((r)->rb_parent_color & ~RB_MASK))
#define rb_color(r)	((r)->rb_parent_color & RB_BLACK)
#define rb_is_red(r)	(!rb_color(r))
#define rb_is_black(r)	(rb_color(r))
#define rb_set_red(r)	do { (r)->rb_parent_color &= ~RB_BLACK; } while (0)
#define rb_set_black(r)	do { (r)->rb_parent_color |= RB_BLACK; } while (0)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->rb_parent_color = (rb->rb_parent_color & RB_MASK) | (unsigned long)p;
}

static inline void rb_set_color(struct rb_node *rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~RB_BLACK) | color;
}

#define RB_ROOT				(struct rb_root){ NULL, }
#define	rb_entry(ptr, type, member)	container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)		((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node)		(rb_parent(node) == node)
#define RB_CLEAR_NODE(node)		(rb_set_parent(node, node))

static inline void rb_init_node(struct rb_node *node)
{
	*node = (struct rb_node){ };

	RB_CLEAR_NODE(node);
}

extern void rb_insert_color(struct rb_node *node, struct rb_root *root);
extern void rb_erase(struct rb_node *node, struct rb_root *root);

/* Find logical next and previous nodes in a tree */
extern struct rb_node *rb_first(const struct rb_root *root);
extern struct rb_node *rb_last(const struct rb_root *root);
extern struct rb_node *rb_next(const struct rb_node *node);
extern struct rb_node *rb_prev(const struct rb_node *node);

/* Fast replacement of a single node without remove/rebalance/add/rebalance */
extern void rb_replace_node(struct rb_node *victim, struct rb_node *new,
			    struct rb_root *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
			 struct rb_node **rb_link)
{
	node->rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

static inline void rb_link_and_balance(struct rb_root *root,
				struct rb_node *node,
				struct rb_node *parent,
				struct rb_node **rb_link)
{
	rb_link_node(node, parent, rb_link);
	rb_insert_color(node, root);
}

#endif /* __CR_RBTREE_H__ */
