#ifndef __CR_EXTERNAL_H__
#define __CR_EXTERNAL_H__
struct external {
	struct list_head node;
	char *id;
	void *data;
};

extern int add_external(char *key);
extern bool external_lookup_id(char *id);
extern char *external_lookup_by_key(char *id);
extern void *external_lookup_data(char *id);
extern int external_for_each_type(char *type, int (*cb)(struct external *, void *), void *arg);

static inline char *external_val(struct external *e)
{
	char *aux;

	aux = strchr(e->id, '[');
	if (aux) {
		aux = strchr(aux + 1, ']');
		if (aux && aux[1] == ':')
			return aux + 2;
	}

	return NULL;
}
#endif
