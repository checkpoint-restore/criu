#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that extended attributes of a ghost file survive checkpoint/restore";
const char *test_author = "Mallika Suri <whoismallika@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define USER_XATTR "user.zdtm"
#define ACL_XATTR  "system.posix_acl_access"
#define CAP_XATTR  "security.capability"

/*
 * A minimal POSIX ACL: version 2 followed by 8 byte entries of
 * tag, perm and id. The named user entry is the one that cannot be
 * reconstructed from st_mode alone.
 */
#define ACL_EA_VERSION 0x0002
#define ACL_USER_OBJ   0x01
#define ACL_USER       0x02
#define ACL_GROUP_OBJ  0x04
#define ACL_MASK       0x10
#define ACL_OTHER      0x20

static size_t build_acl(uint8_t *buf)
{
	static const struct {
		uint16_t tag;
		uint16_t perm;
		uint32_t id;
	} ents[] = {
		{ ACL_USER_OBJ, 0x6, 0xffffffff },
		{ ACL_USER, 0x7, 1234 },
		{ ACL_GROUP_OBJ, 0x4, 0xffffffff },
		{ ACL_MASK, 0x7, 0xffffffff },
		{ ACL_OTHER, 0x4, 0xffffffff },
	};
	uint32_t ver = ACL_EA_VERSION;
	size_t off = 0;
	unsigned i;

	memcpy(buf, &ver, sizeof(ver));
	off += sizeof(ver);

	for (i = 0; i < sizeof(ents) / sizeof(ents[0]); i++) {
		memcpy(buf + off, &ents[i].tag, 2);
		memcpy(buf + off + 2, &ents[i].perm, 2);
		memcpy(buf + off + 4, &ents[i].id, 4);
		off += 8;
	}
	return off;
}

/* VFS_CAP_REVISION_2, one effective capability set. */
static size_t build_cap(uint8_t *buf)
{
	uint32_t magic = 0x02000000 | 0x000001; /* revision 2 | effective */
	uint32_t zero = 0;

	memset(buf, 0, 20);
	memcpy(buf, &magic, 4);
	memcpy(buf + 4, &zero, 4);
	return 20;
}

/* 0 set, 1 unsupported, -1 hard error */
static int set_attr(int fd, const char *name, const uint8_t *val, size_t len)
{
	if (fsetxattr(fd, name, val, len, 0)) {
		if (errno == EOPNOTSUPP || errno == ENOTSUP)
			return 1;
		pr_perror("Can't set %s", name);
		return -1;
	}
	return 0;
}

static int check_attr(int fd, const char *name, const uint8_t *want, size_t wlen)
{
	uint8_t got[256];
	ssize_t len;

	len = fgetxattr(fd, name, got, sizeof(got));
	if (len < 0) {
		fail("%s is gone from the ghost file", name);
		return -1;
	}
	if ((size_t)len != wlen || memcmp(got, want, wlen)) {
		fail("%s on the ghost file changed", name);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t acl[64], cap[32];
	const char *uval = "zdtm-ghost";
	size_t alen, clen, ulen;
	int fd, exit_code = 1;
	int user_sup, acl_sup, cap_sup;

	test_init(argc, argv);

	alen = build_acl(acl);
	clen = build_cap(cap);
	ulen = strlen(uval) + 1;

	fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't open %s", filename);
		return 1;
	}

	if (unlink(filename) < 0) {
		pr_perror("Can't unlink %s", filename);
		goto err;
	}

	/*
	 * Each attribute is supported independently, so record them
	 * separately and check back whichever the filesystem accepted.
	 */
	user_sup = set_attr(fd, USER_XATTR, (const uint8_t *)uval, ulen);
	if (user_sup < 0)
		goto err;

	acl_sup = set_attr(fd, ACL_XATTR, acl, alen);
	if (acl_sup < 0)
		goto err;

	cap_sup = set_attr(fd, CAP_XATTR, cap, clen);
	if (cap_sup < 0)
		goto err;

	test_daemon();
	test_waitsig();

	if (user_sup > 0 && acl_sup > 0 && cap_sup > 0) {
		skip("extended attributes are not supported here");
		pass();
		exit_code = 0;
		goto err;
	}

	if (user_sup == 0 && check_attr(fd, USER_XATTR, (const uint8_t *)uval, ulen))
		goto err;

	if (acl_sup == 0 && check_attr(fd, ACL_XATTR, acl, alen))
		goto err;

	if (cap_sup == 0 && check_attr(fd, CAP_XATTR, cap, clen))
		goto err;

	pass();
	exit_code = 0;
err:
	close(fd);
	return exit_code;
}
