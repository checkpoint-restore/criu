#ifndef __CR_KCMP_IDS_H__
#define __CR_KCMP_IDS_H__

#include "kcmp.h"

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

extern u32 kid_generate_gen(struct kid_tree *tree,
			    struct kid_elem *elem, int *new_id);

#endif /* __CR_KCMP_IDS_H__ */
