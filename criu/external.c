#include "common/err.h"
#include "common/list.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "mount.h"
#include "external.h"
#include "util.h"

#include "net.h"

int add_external_val(char *id, char *val)
{
	struct external *ext;

	if (val && val[0] == '\0') {
		pr_err("Empty value for external resource %s\n", id);
		return -1;
	}

	ext = xmalloc(sizeof(*ext));
	if (!ext)
		return -1;

	ext->id = xstrdup(id);
	if (!ext->id)
		goto err_id;

	if (val) {
		ext->val = xstrdup(val);
		if (!ext->val)
			goto err_val;
	} else {
		ext->val = NULL;
	}

	if (strstartswith(id, "macvlan[") && macvlan_ext_add(ext) < 0)
		goto err;

	list_add(&ext->node, &opts.external);

	return 0;
err:
	xfree(ext->val);
err_val:
	xfree(ext->id);
err_id:
	xfree(ext);
	return -1;
}

int add_external(char *key)
{
	cleanup_free char *id = NULL;
	char *br, *val;
	size_t len;

	if (strstartswith(key, "mnt[]") && (key[5] == '\0' || key[5] == ':'))
		return ext_mount_parse_auto(key + 5);

	br = strchr(key, '[');
	if (!br) {
		pr_err("Malformed external resource %s: expected TYPE[KEY] or TYPE[KEY]:VAL\n", key);
		return -1;
	}

	val = strstr(br + 1, "]:");
	if (val) {
		if (val == br + 1) {
			pr_err("Empty key in external resource %s\n", key);
			return -1;
		}
		/*
		 * There is no escaping, so a second "]:" makes it impossible
		 * to tell where the key ends. Keys or values containing "]:"
		 * can be passed via the ext_mnt RPC field instead.
		 */
		if (strstr(val + 2, "]:")) {
			pr_err("Ambiguous external resource %s: more than one \"]:\"\n", key);
			return -1;
		}
		id = xstrndup(key, val - key + 1);
		if (!id)
			return -1;
		return add_external_val(id, val + 2);
	}

	if (!strstartswith(key, "file[") && !strstartswith(key, "tty[") && !strstartswith(key, "unix[")) {
		pr_err("Malformed external resource %s: expected TYPE[KEY]:VAL\n", key);
		return -1;
	}

	len = strlen(key);
	if (key[len - 1] != ']') {
		pr_err("Malformed external resource %s: expected TYPE[KEY]\n", key);
		return -1;
	}
	if (key + len - 1 == br + 1) {
		pr_err("Empty key in external resource %s\n", key);
		return -1;
	}

	return add_external_val(key, NULL);
}

bool external_lookup_id(char *id)
{
	struct external *ext;

	list_for_each_entry(ext, &opts.external, node)
		if (!strcmp(ext->id, id) && !ext->val)
			return true;
	return false;
}

void *external_lookup_data(char *key)
{
	struct external *ext;

	list_for_each_entry(ext, &opts.external, node) {
		if (!strcmp(ext->id, key))
			return ext->data;
	}

	return ERR_PTR(-ENOENT);
}

char *external_lookup_by_key(char *key)
{
	struct external *ext;

	list_for_each_entry(ext, &opts.external, node) {
		if (!strcmp(ext->id, key))
			return ext->val;
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
