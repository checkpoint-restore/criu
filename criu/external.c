#include "common/err.h"
#include "common/list.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "mount.h"
#include "external.h"
#include "util.h"

#include "net.h"

int add_external(char *key)
{
	struct external *ext;

	if (strstartswith(key, "mnt[]"))
		return ext_mount_parse_auto(key + 5);

	ext = xmalloc(sizeof(*ext));
	if (!ext)
		return -1;

	ext->id = xstrdup(key);
	if (!ext->id)
		goto err_id;

	if (strstartswith(key, "macvlan") && macvlan_ext_add(ext) < 0)
		goto err;

	list_add(&ext->node, &opts.external);

	return 0;
err:
	xfree(ext->id);
err_id:
	xfree(ext);
	return -1;
}

bool external_lookup_id(char *id)
{
	struct external *ext;

	list_for_each_entry(ext, &opts.external, node)
		if (!strcmp(ext->id, id))
			return true;
	return false;
}

void *external_lookup_data(char *key)
{
	struct external *ext;
	int len = strlen(key);

	list_for_each_entry(ext, &opts.external, node) {
		if (strncmp(ext->id, key, len))
			continue;

		return ext->data;
	}

	return ERR_PTR(-ENOENT);
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
		else if (ext->id[len] == '\0')
			return NULL;
	}
	return ERR_PTR(-ENOENT);
}

int external_for_each_type(char *type, int (*cb)(struct external *, void *), void *arg)
{
	struct external *ext;
	int ln = strlen(type);
	int ret = 0;

	list_for_each_entry(ext, &opts.external, node) {
		if (strncmp(ext->id, type, ln))
			continue;
		if (ext->id[ln] != '[')
			continue;

		ret = cb(ext, arg);
		if (ret)
			break;
	}

	return ret;
}
