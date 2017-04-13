#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include "types.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "common/compiler.h"
#include "kerndat.h"
#include "vdso.h"
#include "util.h"
#include "criu-log.h"
#include "mem.h"
#include "vma.h"
#include <compel/compel.h>
#include <compel/plugins/std/syscall.h>

#ifdef LOG_PREFIX
# undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

struct vdso_symtable vdso_sym_rt = VDSO_SYMTABLE_INIT;
u64 vdso_pfn = VDSO_BAD_PFN;
struct vdso_symtable vdso_compat_rt = VDSO_SYMTABLE_INIT;
/*
 * The VMAs list might have proxy vdso/vvar areas left
 * from previous dump/restore cycle so we need to detect
 * them and eliminated from the VMAs list, they will be
 * generated again on restore if needed.
 */
int parasite_fixup_vdso(struct parasite_ctl *ctl, pid_t pid,
			struct vm_area_list *vma_area_list)
{
	unsigned long proxy_vdso_addr = VDSO_BAD_ADDR;
	unsigned long proxy_vvar_addr = VVAR_BAD_ADDR;
	struct vma_area *proxy_vdso_marked = NULL;
	struct vma_area *proxy_vvar_marked = NULL;
	struct parasite_vdso_vma_entry *args;
	int fd = -1, ret, exit_code = -1;
	u64 pfn = VDSO_BAD_PFN;
	struct vma_area *vma;
	off_t off;

	args = compel_parasite_args(ctl, struct parasite_vdso_vma_entry);
	if (kdat.pmap == PM_FULL) {
		BUG_ON(vdso_pfn == VDSO_BAD_PFN);
		fd = open_proc(pid, "pagemap");
		if (fd < 0)
			return -1;
	} else
		pr_info("Pagemap is unavailable, trying a slow way\n");

	list_for_each_entry(vma, &vma_area_list->h, list) {
		if (!vma_area_is(vma, VMA_AREA_REGULAR))
			continue;

		if (vma_area_is(vma, VMA_FILE_SHARED) ||
				vma_area_is(vma, VMA_FILE_PRIVATE))
			continue;
		/*
		 * It might be possible VVAR area from marked
		 * vDSO zone, we need to detect it earlier than
		 * VDSO_PROT test because VVAR_PROT is a subset
		 * of it but don't yield continue here,
		 * sigh... what a mess.
		 */
		BUILD_BUG_ON(!(VDSO_PROT & VVAR_PROT));

		if ((vma->e->prot & VVAR_PROT) == VVAR_PROT) {
			if (proxy_vvar_addr != VVAR_BAD_ADDR &&
			    proxy_vvar_addr == vma->e->start) {
				BUG_ON(proxy_vvar_marked);
				proxy_vvar_marked = vma;
				continue;
			}
		}

		if ((vma->e->prot & VDSO_PROT) != VDSO_PROT)
			continue;

		if (vma->e->start > kdat.task_size)
			continue;

		if (vma->e->flags & MAP_GROWSDOWN)
			continue;

		/*
		 * I need to poke every potentially marked vma,
		 * otherwise if task never called for vdso functions
		 * page frame number won't be reported.
		 *
		 * Moreover, if page frame numbers are not accessible
		 * we have to scan the vma zone for vDSO elf structure
		 * which gonna be a slow way.
		 */
		args->start = vma->e->start;
		args->len = vma_area_len(vma);
		if (!compel_mode_native(ctl))
			args->try_fill_symtable = false;
		else
			args->try_fill_symtable = (fd < 0) ? true : false;
		args->is_vdso = false;

		if (compel_rpc_call_sync(PARASITE_CMD_CHECK_VDSO_MARK, ctl)) {
			pr_err("Parasite failed to poke for mark\n");
			goto err;
		}

		/*
		 * Defer handling marked vdso until we walked over
		 * all vmas and restore potentially remapped vDSO
		 * area status.
		 */
		if (unlikely(args->is_marked)) {
			if (proxy_vdso_marked) {
				pr_err("Ow! Second vdso mark detected!\n");
				goto err;
			}
			proxy_vdso_marked = vma;
			proxy_vdso_addr = args->proxy_vdso_addr;
			proxy_vvar_addr = args->proxy_vvar_addr;
			continue;
		}

		/*
		 * If we have an access to pagemap we can handle vDSO
		 * status early. Otherwise, in worst scenario, where
		 * the dumpee has been remapping vdso on its own and
		 * the kernel version is < 3.16, the vdso won't be
		 * detected via procfs status so we have to parse
		 * symbols in parasite code.
		 */
		if (fd >= 0) {
			off = (vma->e->start / PAGE_SIZE) * sizeof(u64);
			ret = pread(fd, &pfn, sizeof(pfn), off);
			if (ret < 0 || ret != sizeof(pfn)) {
				pr_perror("Can't read pme for pid %d", pid);
				goto err;
			}

			pfn = PME_PFRAME(pfn);
			if (!pfn) {
				pr_err("Unexpected page fram number 0 for pid %d\n", pid);
				goto err;
			}
		}

		/*
		 * Setup proper VMA status. Note starting with 3.16
		 * the [vdso]/[vvar] marks are reported correctly
		 * even when they are remapped into a new place,
		 * but only since that particular version of the
		 * kernel!
		 */
		if ((pfn == vdso_pfn && pfn != VDSO_BAD_PFN) || args->is_vdso) {
			if (!vma_area_is(vma, VMA_AREA_VDSO)) {
				pr_debug("Restore vDSO status by pfn/symtable at %lx\n",
					 (long)vma->e->start);
				vma->e->status |= VMA_AREA_VDSO;
			}
		} else {
			/*
			 * Compat vDSO mremap support is only after v4.8,
			 * [vdso] vma name always stays after mremap.
			 */
			if (unlikely(vma_area_is(vma, VMA_AREA_VDSO)) &&
					compel_mode_native(ctl)) {
				pr_debug("Drop mishinted vDSO status at %lx\n",
					 (long)vma->e->start);
				vma->e->status &= ~VMA_AREA_VDSO;
			}
		}
	}

	/*
	 * There is marked vdso, it means such vdso is autogenerated
	 * and must be dropped from vma list.
	 */
	if (proxy_vdso_marked) {
		pr_debug("vdso: Found marked at %lx (proxy vDSO at %lx VVAR at %lx)\n",
			 (long)proxy_vdso_marked->e->start,
			 (long)proxy_vdso_addr, (long)proxy_vvar_addr);

		/*
		 * Don't forget to restore the proxy vdso/vvar status, since
		 * it's unknown to the kernel.
		 */
		list_for_each_entry(vma, &vma_area_list->h, list) {
			if (vma->e->start == proxy_vdso_addr) {
				vma->e->status |= VMA_AREA_REGULAR | VMA_AREA_VDSO;
				pr_debug("vdso: Restore proxy vDSO status at %lx\n",
					 (long)vma->e->start);
			} else if (vma->e->start == proxy_vvar_addr) {
				vma->e->status |= VMA_AREA_REGULAR | VMA_AREA_VVAR;
				pr_debug("vdso: Restore proxy VVAR status at %lx\n",
					 (long)vma->e->start);
			}
		}

		pr_debug("vdso: Droppping marked vdso at %lx\n",
			 (long)proxy_vdso_marked->e->start);
		list_del(&proxy_vdso_marked->list);
		xfree(proxy_vdso_marked);
		vma_area_list->nr--;

		if (proxy_vvar_marked) {
			pr_debug("vdso: Droppping marked vvar at %lx\n",
				 (long)proxy_vvar_marked->e->start);
			list_del(&proxy_vvar_marked->list);
			xfree(proxy_vvar_marked);
			vma_area_list->nr--;
		}
	}
	exit_code = 0;
err:
	close_safe(&fd);
	return exit_code;
}

static int vdso_parse_maps(pid_t pid, struct vdso_symtable *s)
{
	int exit_code = -1;
	char *buf;
	struct bfd f;

	*s = (struct vdso_symtable)VDSO_SYMTABLE_INIT;

	f.fd = open_proc(pid, "maps");
	if (f.fd < 0)
		return -1;

	if (bfdopenr(&f))
		goto err;

	while (1) {
		unsigned long start, end;
		char *has_vdso, *has_vvar;

		buf = breadline(&f);
		if (buf == NULL)
			break;
		if (IS_ERR(buf))
			goto err;

		has_vdso = strstr(buf, "[vdso]");
		if (!has_vdso)
			has_vvar = strstr(buf, "[vvar]");
		else
			has_vvar = NULL;

		if (!has_vdso && !has_vvar)
			continue;

		if (sscanf(buf, "%lx-%lx", &start, &end) != 2) {
			pr_err("Can't find vDSO/VVAR bounds\n");
			goto err;
		}

		if (has_vdso) {
			if (s->vma_start != VDSO_BAD_ADDR) {
				pr_err("Got second vDSO entry\n");
				goto err;
			}
			s->vma_start = start;
			s->vma_end = end;
		} else {
			if (s->vvar_start != VVAR_BAD_ADDR) {
				pr_err("Got second VVAR entry\n");
				goto err;
			}
			s->vvar_start = start;
			s->vvar_end = end;
		}
	}

	exit_code = 0;
err:
	bclose(&f);
	return exit_code;
}

static int validate_vdso_addr(struct vdso_symtable *s)
{
	/*
	 * Validate its structure -- for new vDSO format the
	 * structure must be like
	 *
	 * 7fff1f5fd000-7fff1f5fe000 r-xp 00000000 00:00 0 [vdso]
	 * 7fff1f5fe000-7fff1f600000 r--p 00000000 00:00 0 [vvar]
	 *
	 * The areas may be in reverse order.
	 *
	 * 7fffc3502000-7fffc3504000 r--p 00000000 00:00 0 [vvar]
	 * 7fffc3504000-7fffc3506000 r-xp 00000000 00:00 0 [vdso]
	 *
	 */
	if (s->vma_start != VDSO_BAD_ADDR) {
		if (s->vvar_start != VVAR_BAD_ADDR) {
			if (s->vma_end != s->vvar_start &&
			    s->vvar_end != s->vma_start) {
				pr_err("Unexpected rt vDSO area bounds\n");
				return -1;
			}
		}
	} else {
		pr_err("Can't find rt vDSO\n");
		return -1;
	}

	return 0;
}

static int vdso_fill_self_symtable(struct vdso_symtable *s)
{

	if (vdso_parse_maps(PROC_SELF, s))
		return -1;

	if (vdso_fill_symtable(s->vma_start, s->vma_end - s->vma_start, s))
		return -1;

	if (validate_vdso_addr(s))
		return -1;

	pr_debug("rt [vdso] %lx-%lx [vvar] %lx-%lx\n",
		 s->vma_start, s->vma_end,
		 s->vvar_start, s->vvar_end);

	return 0;
}

#ifdef CONFIG_COMPAT
static int vdso_mmap_compat(struct vdso_symtable *native,
		struct vdso_symtable *compat, void *vdso_buf, size_t buf_size)
{
	pid_t pid;
	int status, ret = -1;
	int fds[2];

	if (pipe(fds)) {
		pr_perror("Failed to open pipe");
		return -1;
	}

	pid = fork();
	if (pid == 0) {
		if (close(fds[1])) {
			pr_perror("Failed to close pipe");
			syscall(__NR_exit, 1);
		}

		compat_vdso_helper(native, fds[0], log_get_fd(),
				vdso_buf, buf_size);

		BUG();
	}

	if (close(fds[0])) {
		pr_perror("Failed to close pipe");
		goto out_kill;
	}
	waitpid(pid, &status, WUNTRACED);

	if (WIFEXITED(status)) {
		pr_err("Compat vdso helper exited with %d\n",
				WEXITSTATUS(status));
		goto out_kill;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Compat vdso helper isn't stopped\n");
		goto out_kill;
	}

	if (vdso_parse_maps(pid, compat))
		goto out_kill;

	if (validate_vdso_addr(compat))
		goto out_kill;

	if (kill(pid, SIGCONT)) {
		pr_perror("Failed to kill(SIGCONT) for compat vdso helper\n");
		goto out_kill;
	}
	if (write(fds[1], &compat->vma_start, sizeof(void *)) !=
			sizeof(compat->vma_start)) {
		pr_perror("Failed write to pipe\n");
		goto out_kill;
	}
	waitpid(pid, &status, WUNTRACED);

	if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret)
			pr_err("Helper for mmaping compat vdso failed with %d\n", ret);
		goto out_close;
	}
	pr_err("Compat vDSO helper didn't exit, status: %d\n", status);

out_kill:
	kill(pid, SIGKILL);
out_close:
	if (close(fds[1]))
		pr_perror("Failed to close pipe");
	return ret;
}

#define COMPAT_VDSO_BUF_SZ		(PAGE_SIZE*2)
static int vdso_fill_compat_symtable(struct vdso_symtable *native,
		struct vdso_symtable *compat)
{
	void *vdso_mmap;
	int ret = -1;

	vdso_mmap = mmap(NULL, COMPAT_VDSO_BUF_SZ, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANON, -1, 0);
	if (vdso_mmap == MAP_FAILED) {
		pr_perror("Failed to mmap buf for compat vdso");
		return -1;
	}

	if (vdso_mmap_compat(native, compat, vdso_mmap, COMPAT_VDSO_BUF_SZ)) {
		pr_err("Failed to mmap compatible vdso with helper process\n");
		goto out_unmap;
	}

	if (vdso_fill_symtable_compat((uintptr_t)vdso_mmap,
				compat->vma_end - compat->vma_start, compat)) {
		pr_err("Failed to parse mmaped compatible vdso blob\n");
		goto out_unmap;
	}

	pr_debug("compat [vdso] %lx-%lx [vvar] %lx-%lx\n",
		 compat->vma_start, compat->vma_end,
		 compat->vvar_start, compat->vvar_end);
	ret = 0;

out_unmap:
	if (munmap(vdso_mmap, COMPAT_VDSO_BUF_SZ))
		pr_perror("Failed to unmap buf for compat vdso");
	return ret;
}

#else /* CONFIG_COMPAT */
static int vdso_fill_compat_symtable(struct vdso_symtable *native,
		struct vdso_symtable *compat)
{
	return 0;
}
#endif /* CONFIG_COMPAT */

int vdso_init(void)
{
	if (vdso_fill_self_symtable(&vdso_sym_rt)) {
		pr_err("Failed to fill self vdso symtable\n");
		return -1;
	}
	if (kdat.compat_cr &&
			vdso_fill_compat_symtable(&vdso_sym_rt, &vdso_compat_rt)) {
		pr_err("Failed to fill compat vdso symtable\n");
		return -1;
	}

	if (kdat.pmap != PM_FULL)
		pr_info("VDSO detection turned off\n");
	else if (vaddr_to_pfn(vdso_sym_rt.vma_start, &vdso_pfn))
		return -1;

	return 0;
}
