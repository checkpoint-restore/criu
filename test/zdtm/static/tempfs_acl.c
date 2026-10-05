#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/limits.h>

#include "zdtmtst.h"

const char *test_doc = "Check that POSIX ACLs and file capabilities on tmpfs survive checkpoint/restore";
const char *test_author = "Mallika <whoismallika@gmail.com>";

char *dirname;
TEST_OPTION(dirname, string, "directory name", 1);

/*
 * A POSIX ACL is stored in the system.posix_acl_access attribute as a
 * version header followed by 8 byte entries of {tag, perm, id}. A valid
 * ACL that names a user needs the three base entries, the named user and
 * a mask.
 */
#define ACL_XATTR	 "system.posix_acl_access"
#define ACL_EA_VERSION	 0x0002
#define ACL_USER_OBJ	 0x01
#define ACL_USER	 0x02
#define ACL_GROUP_OBJ	 0x04
#define ACL_MASK	 0x10
#define ACL_OTHER	 0x20
#define ACL_UNDEFINED_ID (~0U)
#define ACL_UID		 1234

/* security.capability, VFS_CAP_REVISION_2 layout. */
#define CAP_XATTR	     "security.capability"
#define VFS_CAP_REVISION_2   0x02000000
#define VFS_CAP_FLAGS_EFFECT 0x000001
#define CAP_NET_RAW	     13

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

static void put_le16(uint8_t *p, uint16_t v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static size_t build_acl(uint8_t *buf)
{
	static const struct {
		uint16_t tag, perm;
		uint32_t id;
	} ents[] = {
		{ ACL_USER_OBJ, 6, ACL_UNDEFINED_ID },
		{ ACL_USER, 7, ACL_UID },
		{ ACL_GROUP_OBJ, 4, ACL_UNDEFINED_ID },
		{ ACL_MASK, 7, ACL_UNDEFINED_ID },
		{ ACL_OTHER, 4, ACL_UNDEFINED_ID },
	};
	size_t i, off = 4;

	put_le32(buf, ACL_EA_VERSION);
	for (i = 0; i < sizeof(ents) / sizeof(ents[0]); i++) {
		put_le16(buf + off, ents[i].tag);
		put_le16(buf + off + 2, ents[i].perm);
		put_le32(buf + off + 4, ents[i].id);
		off += 8;
	}
	return off;
}

static size_t build_cap(uint8_t *buf)
{
	put_le32(buf, VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECT);
	put_le32(buf + 4, 1U << CAP_NET_RAW); /* permitted, low word */
	put_le32(buf + 8, 0);		      /* inheritable, low word */
	put_le32(buf + 12, 0);		      /* permitted, high word */
	put_le32(buf + 16, 0);		      /* inheritable, high word */
	return 20;
}

static int set_and_record(const char *path, const char *name, const uint8_t *val, size_t len)
{
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		pr_perror("Can't create %s", path);
		return -1;
	}
	close(fd);

	if (setxattr(path, name, val, len, 0)) {
		if (errno == EOPNOTSUPP)
			return 1;
		pr_perror("Can't set %s on %s", name, path);
		return -1;
	}
	return 0;
}

static int check(const char *path, const char *name, const uint8_t *want, size_t wlen)
{
	uint8_t got[256];
	ssize_t len;

	len = getxattr(path, name, got, sizeof(got));
	if (len < 0) {
		fail("%s is gone from %s", name, path);
		return -1;
	}
	if ((size_t)len != wlen || memcmp(got, want, wlen)) {
		fail("%s on %s changed", name, path);
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t acl[64], cap[32];
	char apath[PATH_MAX], cpath[PATH_MAX];
	size_t alen, clen;
	int ret = 1, r;

	test_init(argc, argv);

	alen = build_acl(acl);
	clen = build_cap(cap);

	mkdir(dirname, 0700);
	if (mount("none", dirname, "tmpfs", 0, "") < 0) {
		pr_perror("Can't mount tmpfs");
		return 1;
	}

	ssprintf(apath, "%s/acl.file", dirname);
	ssprintf(cpath, "%s/cap.file", dirname);

	r = set_and_record(apath, ACL_XATTR, acl, alen);
	if (r == 0)
		r = set_and_record(cpath, CAP_XATTR, cap, clen);
	if (r < 0)
		goto err;
	if (r > 0) {
		/*
		 * Either attribute being unsupported means there is nothing
		 * to check, so skip rather than fail.
		 */
		test_daemon();
		test_waitsig();
		skip("extended attributes are not supported here");
		pass();
		ret = 0;
		goto err;
	}

	test_daemon();
	test_waitsig();

	if (check(apath, ACL_XATTR, acl, alen) || check(cpath, CAP_XATTR, cap, clen))
		goto err;

	pass();
	ret = 0;
err:
	umount2(dirname, MNT_DETACH);
	rmdir(dirname);
	return ret;
}
