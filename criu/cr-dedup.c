#include <sys/uio.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <unistd.h>

#include "int.h"
#include "crtools.h"
#include "pagemap.h"
#include "restorer.h"

static int cr_dedup_one_pagemap(unsigned long img_id, int flags);

int cr_dedup(void)
{
	int close_ret, ret = 0;
	unsigned long img_id;
	DIR *dirp;
	struct dirent *ent;

	dirp = opendir(CR_PARENT_LINK);
	if (dirp == NULL) {
		pr_perror("Can't enter previous snapshot folder");
		ret = -1;
		goto err;
	}

	while (1) {
		errno = 0;
		ent = readdir(dirp);
		if (ent == NULL) {
			if (errno) {
				pr_perror("Failed readdir");
				ret = -1;
				goto err;
			}
			break;
		}

		ret = sscanf(ent->d_name, "pagemap-%lu.img", &img_id);
		if (ret == 1) {
			pr_info("pid=%lu\n", img_id);
			ret = cr_dedup_one_pagemap(img_id, PR_TASK);
			if (ret < 0)
				break;
		}

		ret = sscanf(ent->d_name, "pagemap-shmem-%lu.img", &img_id);
		if (ret == 1) {
			pr_info("shmid=%lu\n", img_id);
			ret = cr_dedup_one_pagemap(img_id, PR_SHMEM);
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

static int cr_dedup_one_pagemap(unsigned long img_id, int flags)
{
	int ret;
	struct page_read pr;
	struct page_read *prp;

	flags |= PR_MOD;
	ret = open_page_read(img_id, &pr, flags);
	if (ret <= 0)
		return -1;

	prp = pr.parent;
	if (!prp)
		goto exit;

	while (1) {
		ret = pr.advance(&pr);
		if (ret <= 0)
			goto exit;

		pr_debug("dedup iovec base=%" PRIx64 ", len=%lu\n", pr.pe->vaddr, pagemap_len(pr.pe));
		if (!pagemap_in_parent(pr.pe)) {
			ret = dedup_one_iovec(prp, pr.pe->vaddr, pagemap_len(pr.pe));
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
