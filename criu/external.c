#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "common/err.h"
#include "common/list.h"
#include "cr_options.h"
#include "xmalloc.h"
#include "mount.h"
#include "external.h"
#include "util.h"

#include "net.h"

static bool
token_has_hex_letters(const char *start, const char *end)
{
	const char *p;

	for (p = start; p < end; p++) {
		if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))
			return true;
	}

	return false;
}

static bool
token_has_hex_prefix(const char *start, const char *end)
{
	return (end - start) > 2 && start[0] == '0' &&
		(start[1] == 'x' || start[1] == 'X');
}

static bool
parse_external_id_component(const char *id, char delim, char **end,
			     unsigned long long *val, bool *unambiguous)
{
	char *tmp;

	/*
	 * First try decimal. If it fully consumes the component, this token is
	 * ambiguous (digits-only can be decimal or hex).
	 */
	errno = 0;
	*val = strtoull(id, &tmp, 10);
	if (!errno && tmp != id && *tmp == delim) {
		*end = tmp;
		*unambiguous = false;
		return true;
	}

	/*
	 * Fallback to hex for forms decimal parser can't consume up to delim.
	 * This covers 0x-prefixed values and bare-hex values with a-f/A-F.
	 */
	errno = 0;
	*val = strtoull(id, &tmp, 16);
	if (errno || tmp == id || *tmp != delim)
		return false;

	*end = tmp;
	*unambiguous = token_has_hex_prefix(id, tmp) ||
		       token_has_hex_letters(id, tmp);
	return true;
}

static bool
parse_external_file_id(const char *id, unsigned int *mnt_id, uint64_t *inode,
		       bool *unambiguous)
{
	char *end = NULL;
	unsigned long long val;
	bool mnt_unambiguous, inode_unambiguous;

	if (!strstartswith(id, "file["))
		return false;
	id += strlen("file[");

	if (!parse_external_id_component(id, ':', &end, &val, &mnt_unambiguous))
		return false;
	if (val > UINT_MAX)
		return false;
	*mnt_id = (unsigned int)val;

	id = end + 1;
	if (!parse_external_id_component(id, ']', &end, &val, &inode_unambiguous))
		return false;
	end++;
	if (*end != '\0')
		return false;

	*inode = val;
	*unambiguous = mnt_unambiguous && inode_unambiguous;
	return true;
}

int
add_external(char *key)
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
	unsigned int id_mnt_id, ext_mnt_id;
	uint64_t id_inode, ext_inode;
	bool id_unambiguous, ext_unambiguous;

	if (!parse_external_file_id(id, &id_mnt_id, &id_inode, &id_unambiguous))
		id_unambiguous = false;

	list_for_each_entry(ext, &opts.external, node) {
		if (!strcmp(ext->id, id))
			return true;

		/*
		 * Only normalize when BOTH the queried ID and the stored ID
		 * are unambiguous (explicit 0x prefix or explicit hex digits).
		 * Ambiguous IDs (digit-only like 11) retain their literal semantics
		 * and are not matched by normalization to avoid silent miscorrection.
		 * This preserves backward compatibility with existing checkpoint
		 * images while enabling proper matching for unambiguous forms.
		 */
		if (id_unambiguous &&
		    parse_external_file_id(ext->id, &ext_mnt_id, &ext_inode, &ext_unambiguous) &&
		    ext_unambiguous &&
		    ext_mnt_id == id_mnt_id && ext_inode == id_inode)
			return true;
	}
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
