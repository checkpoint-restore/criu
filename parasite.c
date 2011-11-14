#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "compiler.h"
#include "types.h"
#include "syscall.h"
#include "parasite.h"
#include "image.h"
#include "util.h"
#include "crtools.h"

#ifdef CONFIG_X86_64

static void *brk_start, *brk_end, *brk_tail;

static struct page_entry page;
static struct vma_entry vma;

static void brk_init(void *brk)
{
	brk_start = brk_tail = brk;
	brk_end = brk_start + PARASITE_BRK_SIZE;
}

static void *brk_alloc(unsigned long bytes)
{
	void *addr = NULL;
	if (brk_end > (brk_tail + bytes)) {
		addr	= brk_tail;
		brk_tail+= bytes;
	}
	return addr;
}

static void brk_free(unsigned long bytes)
{
	if (brk_start >= (brk_tail - bytes))
		brk_tail -= bytes;
}

static unsigned long builtin_strlen(char *str)
{
	unsigned long len = 0;
	while (*str++)
		len++;
	return len;
}

static const unsigned char hex[] = "0123456789abcdef";
static char *long2hex(unsigned long v)
{
	static char buf[32];
	char *p = buf;
	int i;

	for (i = sizeof(long) - 1; i >= 0; i--) {
		*p++ = hex[ ((((unsigned char *)&v)[i]) & 0xf0) >> 4 ];
		*p++ = hex[ ((((unsigned char *)&v)[i]) & 0x0f) >> 0 ];
	}
	*p = 0;

	return buf;
}

static void sys_write_msg(const char *msg)
{
	int size = 0;
	while (msg[size])
		size++;
	sys_write(1, msg, size);
}

/*
 * This is the main page dumping routine, it's executed
 * inside a victim process space.
 */
static int dump_pages(parasite_args_cmd_dumppages_t *args)
{
	int ret = PARASITE_ERR_FAIL;
	unsigned long nrpages, pfn, length;
	unsigned long prot_old, prot_new;
	unsigned char *map_brk = NULL;
	unsigned char *map;
	bool dump_all = false;

	args->nrpages_dumped = 0;
	prot_old = prot_new = 0;

	if (args->fd == -1UL) {
		args->fd = sys_open(args->open_path, args->open_flags, args->open_mode);
		if ((long)args->fd < 0) {
			sys_write_msg("sys_open failed\n");
			ret = PARASITE_ERR_OPEN;
			goto err;
		}
	}

	/* Start from the end of file */
	sys_lseek(args->fd, 0, SEEK_END);

	length	= args->vma_entry.end - args->vma_entry.start;
	nrpages	= length / PAGE_SIZE;

	/*
	 * brk should allow us to handle up to 128M of memory,
	 * otherwise call for mmap.
	 */
	map = brk_alloc(nrpages);
	if (map) {
		map_brk = map;
	} else {
		map = (void *)sys_mmap(NULL, nrpages,
				       PROT_READ   | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS,
				       -1, 0);
		if ((long)map < 0) {
			sys_write_msg("sys_mmap failed\n");
			ret = PARASITE_ERR_MMAP;
			goto err;
		}
	}

	dump_all = !!(args->vma_entry.status & VMA_DUMP_ALL);

	/*
	 * Try to change page protection if needed so we would
	 * be able to dump contents.
	 */
	if (!(args->vma_entry.prot & PROT_READ)) {
		prot_old = (unsigned long)args->vma_entry.prot;
		prot_new = prot_old | PROT_READ;
		if (sys_mprotect((unsigned long)args->vma_entry.start,
				 (unsigned long)vma_entry_len(&args->vma_entry),
				 prot_new)) {
			sys_write_msg("sys_mprotect failed\n");
			ret = PARASITE_ERR_MPROTECT;
			goto err_free;
		}
	}

	/*
	 * Dumping the whole VMA range is not a common operation
	 * so stick for mincore as a basis.
	 */

	if (sys_mincore((unsigned long)args->vma_entry.start, length, map)) {
		sys_write_msg("sys_mincore failed\n");
		ret = PARASITE_ERR_MINCORE;
		goto err_free;
	}

	ret = 0;
	for (pfn = 0; pfn < nrpages; pfn++) {
		unsigned long vaddr, written;

		if ((map[pfn] & PAGE_RSS) || dump_all) {
			/*
			 * That's the optimized write of
			 * page_entry structure, see image.h
			 */
			vaddr = (unsigned long)args->vma_entry.start + pfn * PAGE_SIZE;
			written = 0;

			written += sys_write(args->fd, &vaddr, sizeof(vaddr));
			written += sys_write(args->fd, (void *)vaddr, PAGE_SIZE);
			if (written != sizeof(vaddr) + PAGE_SIZE) {
				ret = PARASITE_ERR_WRITE;
				sys_write_msg("sys_write on page failed\n");
				goto err_free;
			}

			args->nrpages_dumped++;
		}
	}

	/*
	 * Don't left pages readable if they were not.
	 */
	if (prot_old != prot_new) {
		if (sys_mprotect((unsigned long)args->vma_entry.start,
				 (unsigned long)vma_entry_len(&args->vma_entry),
				 prot_old)) {
			sys_write_msg("PANIC: Ouch! sys_mprotect failed on resore\n");
			ret = PARASITE_ERR_MPROTECT;
			goto err_free;
		}
	}

err_free:
	if (map_brk)
		brk_free(nrpages);
	else
		sys_munmap(map, nrpages);
err:
	return ret;
}

static int __used parasite_service(unsigned long cmd, void *args, void *brk)
{
	brk_init(brk);

	switch (cmd) {
	case PARASITE_CMD_KILLME:
		sys_close(0);
		break;
	case PARASITE_CMD_PINGME:
		break;
	case PARASITE_CMD_DUMPPAGES:
		return dump_pages((parasite_args_cmd_dumppages_t *)args);
		break;
	default:
		sys_write_msg("Unknown command to parasite\n");
		break;
	}

	return 0;
}

static void __parasite_head __used parasite_head(void)
{
	/*
	 * The linker will handle the stack allocation.
	 */
	asm volatile("parasite_head_start:							\n\t"
		     "leaq parasite_stack(%rip), %rsp						\n\t"
		     "pushq $0									\n\t"
		     "movq %rsp, %rbp								\n\t"
		     "movl parasite_cmd(%rip), %edi						\n\t"
		     "leaq parasite_args(%rip), %rsi						\n\t"
		     "leaq parasite_brk(%rip), %rdx						\n\t"
		     "call parasite_service							\n\t"
		     "parasite_service_complete:						\n\t"
		     "int $0x03									\n\t"
		     ".align 8									\n\t"
		     "parasite_cmd:								\n\t"
		     ".long 0									\n\t"
		     "parasite_args:								\n\t"
		     ".long 0									\n\t"
		     ".skip "__stringify(PARASITE_ARG_SIZE)",0					\n\t"
		     ".skip "__stringify(PARASITE_STACK_SIZE)", 0				\n\t"
		     "parasite_stack:								\n\t"
		     ".long 0									\n\t"
		     "parasite_brk:								\n\t"
		     ".skip "__stringify(PARASITE_BRK_SIZE)", 0					\n\t"
		     ".long 0									\n\t");
}

#else /* CONFIG_X86_64 */
# error x86-32 bit mode not yet implemented
#endif /* CONFIG_X86_64 */
