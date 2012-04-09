#ifndef __KCMP_IDS_H__
#define __KCMP_IDS_H__

struct kid_tree {
	struct rb_root root;
	unsigned kcmp_type;
	unsigned long subid;

};

#define DECLARE_KCMP_TREE(name, type)	\
	struct kid_tree name = {	\
		.root = RB_ROOT,	\
		.kcmp_type = type,	\
		.subid = 1,		\
	}

struct kid_elem {
	int pid;
	unsigned genid;
	unsigned idx;
};

u32 kid_generate_gen(struct kid_tree *tree,
		struct kid_elem *elem, int *new_id);
void kid_show_tree(struct kid_tree *tree);

#endif
