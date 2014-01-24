#include <sys/uio.h>
#include <fcntl.h>
#include <linux/falloc.h>
#include <unistd.h>

#include "crtools.h"
#include "page-read.h"
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

	ret = open_page_rw(pid, &pr);
	if (ret) {
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
		pr_debug("dedup iovec base=%lu, len=%zu\n", (unsigned long)iov.iov_base, iov.iov_len);
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

int dedup_one_iovec(struct page_read *pr, struct iovec *iov)
{
	unsigned long off;
	unsigned long off_real;
	unsigned long iov_end;

	iov_end = (unsigned long)iov->iov_base + iov->iov_len;
	off = (unsigned long)iov->iov_base;
	while (1) {
		int ret;
		struct iovec piov;
		unsigned long  piov_end;
		ret = seek_pagemap_page(pr, off, false);
		if (ret == -1)
			return -1;

		if (ret == 0) {
			if (off < pr->cvaddr && pr->cvaddr < iov_end)
				off = pr->cvaddr;
			else
				return 0;
		}

		if (!pr->pe)
			return -1;
		pagemap2iovec(pr->pe, &piov);
		piov_end = (unsigned long)piov.iov_base + piov.iov_len;
		off_real = lseek(pr->fd_pg, 0, SEEK_CUR);
		if (!pr->pe->in_parent) {
			pr_debug("Punch!/%lu/%lu/\n", off_real, min(piov_end, iov_end) - off);
			ret = fallocate(pr->fd_pg, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					off_real, min(piov_end, iov_end) - off);
			if (ret != 0) {
				pr_perror("Error punching hole : %d", errno);
				return -1;
			}
		}

		if (piov_end < iov_end) {
			off = piov_end;
			continue;
		} else
			return 0;
	}
	return 0;
}
