#include <sys/uio.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <unistd.h>

#include "crtools.h"
#include "pagemap.h"
#include "restorer.h"

static int cr_dedup_one_pagemap(int pid);

int cr_dedup(void)
{
	int close_ret, ret = 0;
	int pid;
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

		ret = sscanf(ent->d_name, "pagemap-%d.img", &pid);
		if (ret == 1) {
			pr_info("pid=%d\n", pid);
			ret = cr_dedup_one_pagemap(pid);
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

static int cr_dedup_one_pagemap(int pid)
{
	int ret;
	struct page_read pr;
	struct page_read * prp;
	struct iovec iov;

	ret = open_page_read(pid, &pr, PR_TASK | PR_MOD);
	if (ret <= 0) {
		ret = -1;
		goto exit;
	}

	prp = pr.parent;
	if (!prp)
		goto exit;

	ret = pr.get_pagemap(&pr, &iov);
	if (ret <= 0)
		goto exit;

	while (1) {
		pr_debug("dedup iovec base=%p, len=%zu\n", iov.iov_base, iov.iov_len);
		if (!pr.pe->in_parent) {
			ret = dedup_one_iovec(prp, &iov);
			if (ret)
				goto exit;
		}

		pr.put_pagemap(&pr);
		ret = pr.get_pagemap(&pr, &iov);
		if (ret <= 0)
			goto exit;
	}
exit:
	pr.close(&pr);

	if (ret < 0)
		return ret;

	return 0;
}
