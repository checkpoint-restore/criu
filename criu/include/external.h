#ifndef __CR_EXTERNAL_H__
#define __CR_EXTERNAL_H__
struct external {
	struct list_head node;
	char *id;
};

extern int add_external(char *key);
extern bool external_lookup_id(char *id);
extern char *external_lookup_by_key(char *id);
#endif
