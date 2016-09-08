#include <sys/uio.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <unistd.h>

#include "int.h"
#include "crtools.h"
#include "pagemap.h"
#include "restorer.h"

static int cr_dedup_one_pagemap(int id, int flags);

int cr_dedup(void)
{
	int close_ret, ret = 0;
	int id;
	DIR * dirp;
	struct dirent *ent;

	dirp = opendir(CR_PARENT_LINK);
	if (dirp == NULL) {
		pr_perror("Can't enter previous snapshot folder, error=%d", errno);
		ret = -1;
		goto err;
	}

	while (1) {
		errno = 0;
		ent = readdir(dirp);
		if (ent == NULL) {
			if (errno) {
				pr_perror("Failed readdir, error=%d", errno);
				ret = -1;
				goto err;
			}
			break;
		}

		ret = sscanf(ent->d_name, "pagemap-%d.img", &id);
		if (ret == 1) {
			pr_info("pid=%d\n", id);
			ret = cr_dedup_one_pagemap(id, PR_TASK);
			if (ret < 0)
				break;
		}

		ret = sscanf(ent->d_name, "pagemap-shmem-%d.img", &id);
		if (ret == 1) {
			pr_info("shmid=%d\n", id);
			ret = cr_dedup_one_pagemap(id, PR_SHMEM);
			if (ret < 0)
				break;
		}
	}

err:
	if (dirp) {
		close_ret = closedir(dirp);
		if (close_ret == -1)
			return close_ret;
	}

	if (ret < 0)
		return ret;

	pr_info("Deduplicated\n");
	return 0;
}

static int cr_dedup_one_pagemap(int id, int flags)
{
	int ret;
	struct page_read pr;
	struct page_read * prp;
	struct iovec iov;

	flags |= PR_MOD;
	ret = open_page_read(id, &pr, flags);
	if (ret <= 0)
		return -1;

	prp = pr.parent;
	if (!prp)
		goto exit;

	while (1) {
		ret = pr.get_pagemap(&pr, &iov);
		if (ret <= 0)
			goto exit;

		pr_debug("dedup iovec base=%p, len=%zu\n", iov.iov_base, iov.iov_len);
		if (!pr.pe->in_parent) {
			ret = dedup_one_iovec(prp, &iov);
			if (ret)
				goto exit;
		}
	}
exit:
	pr.close(&pr);

	if (ret < 0)
		return ret;

	return 0;
}
