#include "list.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "external.h"

int add_external(char *key)
{
	struct external *ext;

	ext = xmalloc(sizeof(*ext));
	if (!ext)
		return -1;
	ext->id = key;
	list_add(&ext->node, &opts.external);

	return 0;
}

bool external_lookup_id(char *id)
{
	struct external *ext;

	list_for_each_entry(ext, &opts.external, node)
		if (!strcmp(ext->id, id))
			return true;
	return false;
}

char *external_lookup_by_key(char *key)
{
	struct external *ext;
	int len = strlen(key);

	list_for_each_entry(ext, &opts.external, node) {
		if (strncmp(ext->id, key, len))
			continue;
		if (ext->id[len] == ':')
			return ext->id + len + 1;
	}
	return NULL;
}

