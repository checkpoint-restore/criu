/*
 * RBtree implementation adopted from the Linux
 * kernel sources.
 */

#ifndef	_LINUX_RBTREE_H
#define	_LINUX_RBTREE_H

#include <stddef.h>

#define	RB_RED		0
#define	RB_BLACK	1
#define RB_COLOR_MASK	3

struct rb_node {
	unsigned long	rb_parent_color;
	struct rb_node	*rb_right;
	struct rb_node	*rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
	struct rb_node *rb_node;
};


#define rb_parent(r)	((struct rb_node *)((r)->rb_parent_color & ~RB_COLOR_MASK))
#define rb_color(r)	((r)->rb_parent_color & RB_BLACK)
#define rb_is_red(r)	(!rb_color(r))
#define rb_is_black(r)	rb_color(r)
#define rb_set_red(r)	do { (r)->rb_parent_color &= ~RB_BLACK; } while (0)
#define rb_set_black(r)	do { (r)->rb_parent_color |= RB_BLACK; } while (0)

static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
	rb->rb_parent_color = (rb->rb_parent_color & RB_COLOR_MASK) |(unsigned long)p;
}

static inline void rb_set_color(struct rb_node *rb, int color)
{
	rb->rb_parent_color = (rb->rb_parent_color & ~RB_BLACK) | color;
}

#define RB_ROOT (struct rb_root)	{ NULL, }
#define	rb_entry(ptr, type, member)	\
	container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)		((root)->rb_node == NULL)
#define RB_EMPTY_NODE(node)		(rb_parent(node) == node)
#define RB_CLEAR_NODE(node)		(rb_set_parent(node, node))

static inline void rb_init_node(struct rb_node *rb)
{
	rb->rb_parent_color = 0;
	rb->rb_right = NULL;
	rb->rb_left = NULL;
	RB_CLEAR_NODE(rb);
}

void rb_insert_color(struct rb_node *, struct rb_root *);
void rb_erase(struct rb_node *, struct rb_root *);

struct rb_node *rb_next(const struct rb_node *node);
struct rb_node *rb_prev(const struct rb_node *node);
struct rb_node *rb_first(const struct rb_root *node);
struct rb_node *rb_last(const struct rb_root *node);

void rb_replace_node(struct rb_node *victim, struct rb_node *new, 
			    struct rb_root *root);

static inline void rb_link_node(struct rb_node *node, struct rb_node *parent,
				struct rb_node **rb_link)
{
	node->rb_parent_color = (unsigned long )parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#endif	/* _LINUX_RBTREE_H */
