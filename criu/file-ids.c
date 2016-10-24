#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "int.h"
#include "file-ids.h"
#include "rbtree.h"
#include "kcmp-ids.h"
#include "common/compiler.h"
#include "image.h"
#include "util.h"
#include "irmap.h"
#include "files.h"

static DECLARE_KCMP_TREE(fd_tree, KCMP_FILE);

#define FDID_BITS	5
#define FDID_SIZE	(1 << FDID_BITS)
#define FDID_MASK	(FDID_SIZE - 1)

static inline int fdid_hashfn(unsigned int s_dev, unsigned long i_ino)
{
	return (s_dev + i_ino) & FDID_MASK;
}

struct fd_id {
	int mnt_id;
	unsigned int dev;
	unsigned long ino;
	u32 id;
	struct fd_id *n;
};

static struct fd_id *fd_id_cache[FDID_SIZE];

static void fd_id_cache_one(u32 id, struct fd_parms *p)
{
	struct fd_id *fi;
	unsigned hv;

	fi = xmalloc(sizeof(*fi));
	if (fi) {
		fi->dev = p->stat.st_dev;
		fi->ino = p->stat.st_ino;
		fi->mnt_id = p->mnt_id;
		fi->id = id;

		hv = fdid_hashfn(p->stat.st_dev, p->stat.st_ino);
		fi->n = fd_id_cache[hv];
		fd_id_cache[hv] = fi;
	}
}

static struct fd_id *fd_id_cache_lookup(struct fd_parms *p)
{
	struct stat *st = &p->stat;
	struct fd_id *fi;

	for (fi = fd_id_cache[fdid_hashfn(st->st_dev, st->st_ino)];
			fi; fi = fi->n)
		if (fi->dev == st->st_dev &&
		    fi->ino == st->st_ino &&
		    fi->mnt_id == p->mnt_id)
			return fi;

	return NULL;
}

int fd_id_generate_special(struct fd_parms *p, u32 *id)
{
	if (p) {
		struct fd_id *fi;

		fi = fd_id_cache_lookup(p);
		if (fi) {
			*id = fi->id;
			return 0;
		}
	}

	*id = fd_tree.subid++;
	if (p)
		fd_id_cache_one(*id, p);
	return 1;
}

int fd_id_generate(pid_t pid, FdinfoEntry *fe, struct fd_parms *p)
{
	u32 id;
	struct kid_elem e;
	int new_id = 0;

	e.pid = pid;
	e.genid = fe->id;
	e.idx = fe->fd;

	id = kid_generate_gen(&fd_tree, &e, &new_id);
	if (!id)
		return -ENOMEM;

	if (new_id)
		fd_id_cache_one(id, p);

	fe->id = id;
	return new_id;
}
