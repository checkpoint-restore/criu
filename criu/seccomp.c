#include <linux/filter.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ptrace.h>

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

#undef LOG_PREFIX
#define LOG_PREFIX "seccomp: "

static struct rb_root seccomp_tid_rb_root = RB_ROOT;
static struct seccomp_entry *seccomp_tid_entry_root;

static SeccompEntry *seccomp_img_entry;

struct seccomp_entry *seccomp_lookup(pid_t tid_real, bool create, bool mandatory)
{
	struct seccomp_entry *entry = NULL;

	struct rb_node *node = seccomp_tid_rb_root.rb_node;
	struct rb_node **new = &seccomp_tid_rb_root.rb_node;
	struct rb_node *parent = NULL;

	while (node) {
		struct seccomp_entry *this = rb_entry(node, struct seccomp_entry, node);

		parent = *new;
		if (tid_real < this->tid_real)
			node = node->rb_left, new = &((*new)->rb_left);
		else if (tid_real > this->tid_real)
			node = node->rb_right, new = &((*new)->rb_right);
		else
			return this;
	}

	if (create) {
		entry = xzalloc(sizeof(*entry));
		if (!entry)
			return NULL;
		rb_init_node(&entry->node);
		entry->tid_real = tid_real;

		entry->next = seccomp_tid_entry_root, seccomp_tid_entry_root = entry;
		rb_link_and_balance(&seccomp_tid_rb_root, &entry->node, parent, new);
	} else {
		if (mandatory)
			pr_err("Can't find entry on tid_real %d\n", tid_real);
	}

	return entry;
}

int seccomp_collect_entry(pid_t tid_real, unsigned int mode)
{
	struct seccomp_entry *entry;

	entry = seccomp_lookup(tid_real, true, false);
	if (!entry) {
		pr_err("Can't create entry on tid_real %d\n", tid_real);
		return -1;
	}
	entry->mode = mode;

	pr_debug("Collected tid_real %d mode %#x\n", tid_real, mode);
	return 0;
}

static void seccomp_free_chain(struct seccomp_entry *entry)
{
	struct seccomp_filter_chain *chain, *prev;

	for (chain = entry->chain; chain; chain = prev) {
		prev = chain->prev;

		xfree(chain->filter.filter.data);
		xfree(chain);
	}

	entry->nr_chains = 0;
	entry->chain = NULL;
}

void seccomp_free_entries(void)
{
	struct seccomp_entry *entry, *next;

	for (entry = seccomp_tid_entry_root; entry; entry = next) {
		next = entry->next;
		seccomp_free_chain(entry);
		xfree(entry);
	}

	seccomp_tid_rb_root = RB_ROOT;
	seccomp_tid_entry_root = NULL;
}

int seccomp_dump_thread(pid_t tid_real, ThreadCoreEntry *thread_core)
{
	struct seccomp_entry *entry = seccomp_find_entry(tid_real);
	if (!entry) {
		pr_err("Can't dump thread core on tid_real %d\n", tid_real);
		return -1;
	}

	if (entry->mode != SECCOMP_MODE_DISABLED) {
		thread_core->has_seccomp_mode = true;
		thread_core->seccomp_mode = entry->mode;

		if (entry->mode == SECCOMP_MODE_FILTER) {
			thread_core->has_seccomp_filter = true;
			thread_core->seccomp_filter = entry->img_filter_pos;
		}
	}

	return 0;
}

static int collect_filter(struct seccomp_entry *entry)
{
	seccomp_metadata_t meta_buf, *meta = &meta_buf;
	struct seccomp_filter_chain *chain, *prev;
	struct sock_filter buf[BPF_MAXINSNS];
	size_t i;
	int len;

	if (entry->mode != SECCOMP_MODE_FILTER)
		return 0;

	for (i = 0; true; i++) {
		len = ptrace(PTRACE_SECCOMP_GET_FILTER, entry->tid_real, i, buf);
		if (len < 0) {
			if (errno == ENOENT) {
				break;
			} else {
				pr_perror("Can't fetch filter on tid_real %d i %zu", entry->tid_real, i);
				return -1;
			}
		}

		if (meta) {
			meta->filter_off = i;

			if (ptrace(PTRACE_SECCOMP_GET_METADATA, entry->tid_real, sizeof(*meta), meta) < 0) {
				if (errno == EIO) {
					/* Old kernel, no METADATA support */
					meta = NULL;
				} else {
					pr_perror("Can't fetch seccomp metadata on tid_real %d pos %zu",
						  entry->tid_real, i);
					return -1;
				}
			}
		}

		chain = xzalloc(sizeof(*chain));
		if (!chain)
			return -1;

		seccomp_filter__init(&chain->filter);

		chain->filter.has_flags = true;
		chain->filter.flags = 0;

		chain->filter.filter.len = len * sizeof(struct sock_filter);
		chain->filter.filter.data = xmalloc(chain->filter.filter.len);
		if (!chain->filter.filter.data) {
			xfree(chain);
			return -1;
		}

		memcpy(chain->filter.filter.data, buf, chain->filter.filter.len);

		if (meta)
			chain->filter.flags |= meta->flags;

		prev = entry->chain, entry->chain = chain, chain->prev = prev;
		entry->nr_chains++;
	}

	return 0;
}

/*
 * When filter is being set up with SECCOMP_FILTER_FLAG_TSYNC then all
 * threads share same filters chain. Still without kernel support we
 * don't know if the chains are indeed were propagated by the flag above
 * or application installed identical chains manually.
 *
 * Thus we do a trick: if all threads are sharing chains we just drop
 * all ones except on a leader and assign SECCOMP_FILTER_FLAG_TSYNC there.
 * The rationale is simple: if application is using tsync it always can
 * assign new not-tsync filters after, but in reverse if we don't provide
 * tsync on restore the further calls with tsync will fail later.
 *
 * Proper fix needs some support from kernel side (presumably kcmp mode).
 */
static void try_use_tsync(struct seccomp_entry *leader, struct pstree_item *item)
{
	struct seccomp_filter_chain *chain_a, *chain_b;
	struct seccomp_entry *entry;
	size_t i, j;

	if (leader->mode != SECCOMP_MODE_FILTER)
		return;

	for (i = 0; i < item->nr_threads; i++) {
		entry = seccomp_find_entry(item->threads[i].real);
		BUG_ON(!entry);

		if (entry == leader)
			continue;

		if (entry->mode != leader->mode || entry->nr_chains != leader->nr_chains)
			return;

		chain_a = leader->chain;
		chain_b = entry->chain;

		for (j = 0; j < leader->nr_chains; j++) {
			BUG_ON((!chain_a || !chain_b));

			if (chain_a->filter.filter.len != chain_b->filter.filter.len)
				return;

			if (memcmp(chain_a->filter.filter.data, chain_b->filter.filter.data,
				   chain_a->filter.filter.len))
				return;

			chain_a = chain_a->prev;
			chain_b = chain_b->prev;
		}
	}

	/* OK, so threads can be restored with tsync */
	pr_debug("Use SECCOMP_FILTER_FLAG_TSYNC for tid_real %d\n", leader->tid_real);

	for (chain_a = leader->chain; chain_a; chain_a = chain_a->prev)
		chain_a->filter.flags |= SECCOMP_FILTER_FLAG_TSYNC;

	for (i = 0; i < item->nr_threads; i++) {
		entry = seccomp_find_entry(item->threads[i].real);
		BUG_ON(!entry);

		if (entry == leader)
			continue;

		pr_debug("\t Disable filter on tid_rea %d, will be propagated\n", entry->tid_real);

		entry->mode = SECCOMP_MODE_DISABLED;
		seccomp_free_chain(entry);
	}
}

static int collect_filters(struct pstree_item *item)
{
	struct seccomp_entry *leader, *entry;
	size_t i;

	if (item->pid->state == TASK_DEAD)
		return 0;

	leader = seccomp_find_entry(item->pid->real);
	if (!leader) {
		pr_err("Can't collect filter on leader tid_real %d\n", item->pid->real);
		return -1;
	}

	for (i = 0; i < item->nr_threads; i++) {
		entry = seccomp_find_entry(item->threads[i].real);
		if (!entry) {
			pr_err("Can't collect filter on tid_real %d\n", item->pid->real);
			return -1;
		}

		if (collect_filter(entry))
			return -1;
	}

	try_use_tsync(leader, item);
	return 0;
}

static int dump_seccomp_filters(void)
{
	SeccompEntry se = SECCOMP_ENTRY__INIT;
	struct seccomp_filter_chain *chain;
	struct seccomp_entry *entry;
	size_t img_filter_pos = 0, nr_chains = 0;
	struct rb_node *node;
	int ret;

	for (node = rb_first(&seccomp_tid_rb_root); node; node = rb_next(node)) {
		entry = rb_entry(node, struct seccomp_entry, node);
		nr_chains += entry->nr_chains;
	}

	se.n_seccomp_filters = nr_chains;
	if (nr_chains) {
		se.seccomp_filters = xmalloc(sizeof(*se.seccomp_filters) * nr_chains);
		if (!se.seccomp_filters)
			return -1;
	}

	for (node = rb_first(&seccomp_tid_rb_root); node; node = rb_next(node)) {
		entry = rb_entry(node, struct seccomp_entry, node);

		if (!entry->nr_chains)
			continue;

		for (chain = entry->chain; chain; chain = chain->prev) {
			if (img_filter_pos >= nr_chains) {
				pr_err("Unexpected position %zu > %zu\n", img_filter_pos, nr_chains);
				xfree(se.seccomp_filters);
				return -1;
			}

			se.seccomp_filters[img_filter_pos] = &chain->filter;
			if (chain != entry->chain) {
				chain->filter.has_prev = true;
				chain->filter.prev = img_filter_pos - 1;
			}
			img_filter_pos++;
		}

		entry->img_filter_pos = img_filter_pos - 1;
	}

	ret = pb_write_one(img_from_set(glob_imgset, CR_FD_SECCOMP), &se, PB_SECCOMP);

	xfree(se.seccomp_filters);

	for (node = rb_first(&seccomp_tid_rb_root); node; node = rb_next(node)) {
		entry = rb_entry(node, struct seccomp_entry, node);
		seccomp_free_chain(entry);
	}

	return ret;
}

int seccomp_collect_dump_filters(void)
{
	if (preorder_pstree_traversal(root_item, collect_filters) < 0)
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
	args->seccomp_filters_data =
		(void *)args->seccomp_filters + args->seccomp_filters_n * sizeof(struct thread_seccomp_filter);

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

		args->seccomp_mode = SECCOMP_MODE_DISABLED;
		args->seccomp_filters_pos = 0;
		args->seccomp_filters_n = 0;
		args->seccomp_filters = NULL;
		args->seccomp_filters_data = NULL;

		if (thread_core->has_seccomp_mode)
			args->seccomp_mode = thread_core->seccomp_mode;

		if (args->seccomp_mode != SECCOMP_MODE_FILTER)
			continue;

		if (thread_core->seccomp_filter >= seccomp_img_entry->n_seccomp_filters) {
			pr_err("Corrupted filter index on tid %d (%u > %zu)\n", item->threads[i].ns[0].virt,
			       thread_core->seccomp_filter, seccomp_img_entry->n_seccomp_filters);
			return -1;
		}

		sf = seccomp_img_entry->seccomp_filters[thread_core->seccomp_filter];
		if (sf->filter.len % (sizeof(struct sock_filter))) {
			pr_err("Corrupted filter len on tid %d (index %u)\n", item->threads[i].ns[0].virt,
			       thread_core->seccomp_filter);
			return -1;
		}
		filters_size = sf->filter.len;
		nr_filters = 1;

		while (sf->has_prev) {
			if (sf->prev >= seccomp_img_entry->n_seccomp_filters) {
				pr_err("Corrupted filter index on tid %d (%u > %zu)\n", item->threads[i].ns[0].virt,
				       sf->prev, seccomp_img_entry->n_seccomp_filters);
				return -1;
			}

			sf = seccomp_img_entry->seccomp_filters[sf->prev];
			if (sf->filter.len % (sizeof(struct sock_filter))) {
				pr_err("Corrupted filter len on tid %d (index %u)\n", item->threads[i].ns[0].virt,
				       sf->prev);
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
			pr_err("Can't allocate %zu bytes for filters on tid %d\n", rst_size,
			       item->threads[i].ns[0].virt);
			return -ENOMEM;
		}
		args->seccomp_filters_data =
			(void *)args->seccomp_filters + nr_filters * sizeof(struct thread_seccomp_filter);

		sf = seccomp_img_entry->seccomp_filters[thread_core->seccomp_filter];
		for (j = off = 0; j < nr_filters; j++) {
			struct thread_seccomp_filter *f = &args->seccomp_filters[j];

			f->sock_fprog.len = sf->filter.len / sizeof(struct sock_filter);
			f->sock_fprog.filter = args->seccomp_filters_data + off;
			f->flags = sf->flags;

			memcpy(f->sock_fprog.filter, sf->filter.data, sf->filter.len);

			off += sf->filter.len;
			sf = seccomp_img_entry->seccomp_filters[sf->prev];
		}
	}

	free_seccomp_filters();
	return 0;
}
