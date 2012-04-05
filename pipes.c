#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "crtools.h"
#include "image.h"
#include "files.h"
#include "util-net.h"

/* The sequence of objects which should be restored:
 * pipe -> files struct-s -> fd-s.
 * pipe_entry describes  pipe's file structs-s.
 * A pipe has not own properties, so it has not own object.
 */

struct pipe_info {
	struct pipe_entry pe;
	struct list_head pipe_list;	/* all pipe_info with the same pipe_id
					 * This is pure circular list whiout head */
	struct list_head list;		/* list head for fdinfo_list_entry-s */
	struct list_head fd_head;
	int create;
};

static LIST_HEAD(pipes);

static struct pipe_info *find_pipe(int id)
{
	struct pipe_info *pi;

	list_for_each_entry(pi, &pipes, list)
		if (pi->pe.id == id)
			return pi;
	return NULL;
}

struct list_head *find_pipe_fd(int id)
{
	struct pipe_info *pi;

	pi = find_pipe(id);
	return &pi->fd_head;
}

int collect_pipes(void)
{
	struct pipe_info *pi = NULL, *tmp;
	int fd, ret = -1;

	fd = open_image_ro(CR_FD_PIPES);
	if (fd < 0)
		return -1;

	while (1) {
		int len;

		pi = xmalloc(sizeof(*pi));
		ret = -1;
		if (pi == NULL)
			break;

		ret = read_img_eof(fd, &pi->pe);
		if (ret <= 0)
			break;

		lseek(fd, pi->pe.bytes, SEEK_CUR);

		pr_info("Collected pipe entry ID %x PIPE ID %x\n",
					pi->pe.id, pi->pe.pipe_id);
		INIT_LIST_HEAD(&pi->fd_head);

		list_for_each_entry(tmp, &pipes, list)
			if (pi->pe.pipe_id == tmp->pe.pipe_id)
				break;

		if (&tmp->list == &pipes)
			INIT_LIST_HEAD(&pi->pipe_list);
		else
			list_add(&pi->pipe_list, &tmp->pipe_list);

		list_add_tail(&pi->list, &pipes);
	}

	xfree(pi);

	close(fd);
	return ret;
}

static void show_saved_pipe_fds(struct pipe_info *pi)
{
	struct fdinfo_list_entry *fle;

	pr_info("  `- ID %p %xpn", pi, pi->pe.id);
	list_for_each_entry(fle, &pi->fd_head, list)
		pr_info("   `- FD %d pid %d\n", fle->fd, fle->pid);
}

/* Choose who will restore a pipe. */
void mark_pipe_master()
{
	LIST_HEAD(head);

	pr_info("Pipes:\n");

	while (1) {
		struct fdinfo_list_entry *fle;
		struct pipe_info *pi, *pic, *p;
		int fd, pid;

		if (list_empty(&pipes))
			break;

		pi = list_first_entry(&pipes, struct pipe_info, list);
		list_move(&pi->list, &head);

		pr_info(" `- PIPE ID %x\n", pi->pe.pipe_id);
		show_saved_pipe_fds(pi);

		fle = list_first_entry(&pi->fd_head,
				struct fdinfo_list_entry, list);
		p = pi;
		fd = fle->fd;
		pid = fle->pid;

		list_for_each_entry(pic, &pi->pipe_list, pipe_list) {
			list_move(&pic->list, &head);

			fle = list_first_entry(&p->fd_head,
					struct fdinfo_list_entry, list);
			if (fle->pid < pid ||
			    (pid == fle->pid && fle->fd < fd)) {
				p = pic;
				fd = fle->fd;
				pid = fle->pid;
			}

			show_saved_pipe_fds(pic);
		}
		p->create = 1;
		pr_info("    by %x\n", p->pe.id);
	}

	list_splice(&head, &pipes);
}
