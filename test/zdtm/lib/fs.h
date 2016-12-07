#ifndef ZDTM_FS_H_
#define ZDTM_FS_H_

#ifndef _BSD_SOURCE
# define _BSD_SOURCE
#endif

#include <sys/types.h>
#include <sys/sysmacros.h>

#include <limits.h>

#define KDEV_MINORBITS	20
#define KDEV_MINORMASK	((1UL << KDEV_MINORBITS) - 1)
#define MKKDEV(ma, mi)	(((ma) << KDEV_MINORBITS) | (mi))

static inline unsigned int kdev_major(unsigned int kdev)
{
	return kdev >> KDEV_MINORBITS;
}

static inline unsigned int kdev_minor(unsigned int kdev)
{
	return kdev & KDEV_MINORMASK;
}

static inline dev_t kdev_to_odev(unsigned int kdev)
{
	/*
	 * New kernels encode devices in a new form.
	 * See kernel's fs/stat.c for details, there
	 * choose_32_64 helpers which are the key.
	 */
	unsigned major = kdev_major(kdev);
	unsigned minor = kdev_minor(kdev);

	return makedev(major, minor);
}

typedef struct {
	int			mnt_id;
	int			parent_mnt_id;
	unsigned int		s_dev;
	char			root[PATH_MAX];
	char			mountpoint[PATH_MAX];
	char			fsname[64];
} mnt_info_t;

extern mnt_info_t *mnt_info_alloc(void);
extern void mnt_info_free(mnt_info_t **m);
extern mnt_info_t *get_cwd_mnt_info(void);

#endif /* ZDTM_FS_H_ */
