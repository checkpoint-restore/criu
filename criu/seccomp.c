#include <linux/filter.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common/config.h"
#include "imgset.h"
#include "kcmp.h"
#include "pstree.h"
#include <compel/ptrace.h>
#include "proc_parse.h"
#include "restorer.h"
#include "seccomp.h"
#include "servicefd.h"
#include "util.h"
#include "rst-malloc.h"

#include "protobuf.h"
#include "images/seccomp.pb-c.h"

#undef	LOG_PREFIX
#define LOG_PREFIX "seccomp: "

static SeccompEntry *seccomp_img_entry;

/* populated on dump during collect_seccomp_filters() */
static int next_filter_id = 0;
static struct seccomp_info **filters = NULL;

static struct seccomp_info *find_inherited(struct pstree_item *parent,
					   struct sock_filter *filter,
					   int len, struct seccomp_metadata *meta)
{
	struct seccomp_info *info;

	/* if we have no filters yet, this one has no parent */
	if (!filters)
		return NULL;

	for (info = filters[dmpi(parent)->pi_creds->last_filter]; info; info = info->prev) {

		if (len != info->filter.filter.len)
			continue;
		if (!!meta ^ !!info->filter.has_flags)
			continue;
		if (info->filter.has_flags && meta) {
			if (info->filter.flags != meta->flags)
				continue;
		}
		if (!memcmp(filter, info->filter.filter.data, len))
			return info;
	}

	return NULL;
}

static int collect_filter_for_pstree(struct pstree_item *item)
{
	struct seccomp_metadata meta_buf, *meta = &meta_buf;
	struct seccomp_info *infos = NULL, *cursor;
	int info_count, i, ret = -1;
	struct sock_filter buf[BPF_MAXINSNS];
	void *m;

	if (item->pid->state == TASK_DEAD ||
	    dmpi(item)->pi_creds->s.seccomp_mode != SECCOMP_MODE_FILTER)
		return 0;

	for (i = 0; true; i++) {
		int len;
		struct seccomp_info *info, *inherited = NULL;

		len = ptrace(PTRACE_SECCOMP_GET_FILTER, item->pid->real, i, buf);
		if (len < 0) {
			if (errno == ENOENT) {
				/* end of the search */
				BUG_ON(i == 0);
				goto save_infos;
			} else if (errno == EINVAL) {
				pr_err("dumping seccomp infos not supported\n");
				goto out;
			} else {
				pr_perror("couldn't dump seccomp filter");
				goto out;
			}
		}

		if (!meta)
			meta = &meta_buf;

		meta->flags = 0;
		meta->filter_off = i;

		if (ptrace(PTRACE_SECCOMP_GET_METADATA, item->pid->real, sizeof(meta), meta) < 0) {
			if (errno == EIO) {
				/*
				 * No PTRACE_SECCOMP_GET_METADATA support in
				 * kernel detected, thus simply ignore. Moving
				 * it into kerndat is preferred but not
				 * required.
				 */
				meta = NULL;
			} else {
				pr_perror("couldn't fetch seccomp metadata: pid %d pos %d",
					  item->pid->real, i);
				goto out;
			}
		}

		inherited = find_inherited(item->parent, buf, len, meta);
		if (inherited) {
			bool found = false;

			/* Small sanity check: if infos is already populated,
			 * we should have inherited that filter too. */
			for (cursor = infos; cursor; cursor = cursor->prev) {
				if (inherited->prev== cursor) {
					found = true;
					break;
				}
			}

			BUG_ON(!found);

			infos = inherited;
			continue;
		}

		info = xmalloc(sizeof(*info));
		if (!info)
			goto out;
		seccomp_filter__init(&info->filter);

		if (meta) {
			info->filter.has_flags = true;
			info->filter.flags = meta->flags;
		}

		info->filter.filter.len = len * sizeof(struct sock_filter);
		info->filter.filter.data = xmalloc(info->filter.filter.len);
		if (!info->filter.filter.data) {
			xfree(info);
			goto out;
		}

		memcpy(info->filter.filter.data, buf, info->filter.filter.len);

		info->prev = infos;
		infos = info;
	}

save_infos:
	info_count = i;

	m = xrealloc(filters, sizeof(*filters) * (next_filter_id + info_count));
	if (!m)
		goto out;
	filters = m;

	for (cursor = infos, i = info_count + next_filter_id - 1;
	     i >= next_filter_id; i--) {
		BUG_ON(!cursor);
		cursor->id = i;
		filters[i] = cursor;
		cursor = cursor->prev;
	}

	next_filter_id += info_count;

	dmpi(item)->pi_creds->last_filter = infos->id;

	/* Don't free the part of the tree we just successfully acquired */
	infos = NULL;
	ret = 0;
out:
	while (infos) {
		struct seccomp_info *freeme = infos;
		infos = infos->prev;
		xfree(freeme->filter.filter.data);
		xfree(freeme);
	}

	return ret;
}

static int dump_seccomp_filters(void)
{
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	int ret = -1, i;

	/* If we didn't collect any filters, don't create a seccomp image at all. */
	if (next_filter_id == 0)
		return 0;

	se.seccomp_filters = xzalloc(sizeof(*se.seccomp_filters) * next_filter_id);
	if (!se.seccomp_filters)
		return -1;

	se.n_seccomp_filters = next_filter_id;

	for (i = 0; i < next_filter_id; i++) {
		SeccompFilter *sf;
		struct seccomp_info *cur = filters[i];

		sf = se.seccomp_filters[cur->id] = &cur->filter;
		if (cur->prev) {
			sf->has_prev = true;
			sf->prev = cur->prev->id;
		}
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SECCOMP), &se, PB_SECCOMP);

	xfree(se.seccomp_filters);

	for (i = 0; i < next_filter_id; i++) {
		struct seccomp_info *freeme = filters[i];

		xfree(freeme->filter.filter.data);
		xfree(freeme);
	}
	xfree(filters);

	return ret;
}

int collect_seccomp_filters(void)
{
	if (preorder_pstree_traversal(root_item, collect_filter_for_pstree) < 0)
		return -1;

	if (dump_seccomp_filters())
		return -1;

	return 0;
}

/* The seccomp_img_entry will be shared between all children */
int seccomp_read_image(void)
{
	struct cr_img *img;
	int ret;

	img = open_image(CR_FD_SECCOMP, O_RSTR);
	if (!img)
		return -1;

	ret = pb_read_one_eof(img, &seccomp_img_entry, PB_SECCOMP);
	close_image(img);
	if (ret <= 0)
		return 0; /* there were no filters */

	BUG_ON(!seccomp_img_entry);

	return 0;
}

/* seccomp_img_entry will be freed per-children after forking */
static void free_seccomp_filters(void)
{
	if (seccomp_img_entry) {
		seccomp_entry__free_unpacked(seccomp_img_entry, NULL);
		seccomp_img_entry = NULL;
	}
}

void seccomp_rst_reloc(struct thread_restore_args *args)
{
	size_t j, off;

	if (!args->seccomp_filters_n)
		return;

	args->seccomp_filters = rst_mem_remap_ptr(args->seccomp_filters_pos, RM_PRIVATE);
	args->seccomp_filters_data = (void *)args->seccomp_filters +
			args->seccomp_filters_n * sizeof(struct thread_seccomp_filter);

	for (j = off = 0; j < args->seccomp_filters_n; j++) {
		struct thread_seccomp_filter *f = &args->seccomp_filters[j];

		f->sock_fprog.filter = args->seccomp_filters_data + off;
		off += f->sock_fprog.len * sizeof(struct sock_filter);
	}
}

int seccomp_prepare_threads(struct pstree_item *item, struct task_restore_args *ta)
{
	struct thread_restore_args *args_array = (struct thread_restore_args *)(&ta[1]);
	size_t i, j, nr_filters, filters_size, rst_size, off;

	for (i = 0; i < item->nr_threads; i++) {
		ThreadCoreEntry *thread_core = item->core[i]->thread_core;
		struct thread_restore_args *args = &args_array[i];
		SeccompFilter *sf;

		args->seccomp_mode		= SECCOMP_MODE_DISABLED;
		args->seccomp_filters_pos	= 0;
		args->seccomp_filters_n		= 0;
		args->seccomp_filters		= NULL;
		args->seccomp_filters_data	= NULL;

		if (thread_core->has_seccomp_mode)
			args->seccomp_mode = thread_core->seccomp_mode;

		if (args->seccomp_mode != SECCOMP_MODE_FILTER)
			continue;

		if (thread_core->seccomp_filter >= seccomp_img_entry->n_seccomp_filters) {
			pr_err("Corrupted filter index on tid %d (%u > %zu)\n",
			       item->threads[i]->ns[0].virt, thread_core->seccomp_filter,
			       seccomp_img_entry->n_seccomp_filters);
			return -1;
		}

		sf = seccomp_img_entry->seccomp_filters[thread_core->seccomp_filter];
		if (sf->filter.len % (sizeof(struct sock_filter))) {
			pr_err("Corrupted filter len on tid %d (index %u)\n",
			       item->threads[i]->ns[0].virt,
			       thread_core->seccomp_filter);
			return -1;
		}
		filters_size = sf->filter.len;
		nr_filters = 1;

		while (sf->has_prev) {
			if (sf->prev >= seccomp_img_entry->n_seccomp_filters) {
				pr_err("Corrupted filter index on tid %d (%u > %zu)\n",
				       item->threads[i]->ns[0].virt, sf->prev,
				       seccomp_img_entry->n_seccomp_filters);
				return -1;
			}

			sf = seccomp_img_entry->seccomp_filters[sf->prev];
			if (sf->filter.len % (sizeof(struct sock_filter))) {
				pr_err("Corrupted filter len on tid %d (index %u)\n",
				       item->threads[i]->ns[0].virt, sf->prev);
				return -1;
			}
			filters_size += sf->filter.len;
			nr_filters++;
		}

		args->seccomp_filters_n = nr_filters;

		rst_size = filters_size + nr_filters * sizeof(struct thread_seccomp_filter);
		args->seccomp_filters_pos = rst_mem_align_cpos(RM_PRIVATE);
		args->seccomp_filters = rst_mem_alloc(rst_size, RM_PRIVATE);
		if (!args->seccomp_filters) {
			pr_err("Can't allocate %zu bytes for filters on tid %d\n",
			       rst_size, item->threads[i]->ns[0].virt);
			return -ENOMEM;
		}
		args->seccomp_filters_data = (void *)args->seccomp_filters +
			nr_filters * sizeof(struct thread_seccomp_filter);

		sf = seccomp_img_entry->seccomp_filters[thread_core->seccomp_filter];
		for (j = off = 0; j < nr_filters; j++) {
			struct thread_seccomp_filter *f = &args->seccomp_filters[j];

			f->sock_fprog.len	= sf->filter.len / sizeof(struct sock_filter);
			f->sock_fprog.filter	= args->seccomp_filters_data + off;
			f->flags		= sf->flags;

			memcpy(f->sock_fprog.filter, sf->filter.data, sf->filter.len);

			off += sf->filter.len;
			sf = seccomp_img_entry->seccomp_filters[sf->prev];
		}
	}

	free_seccomp_filters();
	return 0;
}
