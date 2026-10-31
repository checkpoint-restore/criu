#ifndef __CR_EXTERNAL_H__
#define __CR_EXTERNAL_H__
struct external {
	struct list_head node;
	char *id;
	char *val;
	void *data;
};

extern int add_external(char *key);
extern int add_external_val(char *id, char *val);
extern bool external_lookup_id(char *id);
extern char *external_lookup_by_key(char *id);
extern void *external_lookup_data(char *id);
extern int external_for_each_type(char *type, int (*cb)(struct external *, void *), void *arg);

static inline char *external_val(struct external *e)
{
	return e->val;
}
#endif
