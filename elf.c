#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <sys/sendfile.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "syscall.h"
#include "util.h"

#include "image.h"
#include "elf.h"

#define ELF_MAX_PHDR	((65536U / sizeof(Elf64_Phdr)) - 1)
#define ELF_MAX_PAGES	((1 << 30) / PAGE_IMAGE_SIZE)

/*
 * Convert the c/r core file into elf
 * executable, the kernel will handle it.
 */
int convert_to_elf(char *elf_path, int fd_core)
{
	Elf64_Ehdr elf_ehdr;
	Elf64_Phdr elf_phdr;

	Elf64_Half e_phnum = 0;
	Elf64_Addr e_entry = 0;

	struct page_entry page_entry;
	unsigned long nrpages = 0;
	struct core_entry core;
	struct vma_area area;
	struct vma_entry vma;
	u64 va;

	unsigned long phoff = 0;
	unsigned long phoff_regs, phoff_pages;

	int fd_elf;
	int ret = -1;

	fd_elf = open(elf_path, O_RDWR | O_CREAT | O_EXCL, 0700);
	if (fd_elf < 0) {
		pr_perror("Can't open %s\n", elf_path);
		goto err;
	}

	memset(&elf_ehdr, 0, sizeof(elf_ehdr));
	memset(&area, 0, sizeof(area));

	memcpy(elf_ehdr.e_ident, ELFMAG, SELFMAG);
	elf_ehdr.e_ident[EI_CLASS]	= ELFCLASS64;
	elf_ehdr.e_ident[EI_DATA]	= ELFDATA2LSB;
	elf_ehdr.e_ident[EI_VERSION]	= EV_CURRENT;

	elf_ehdr.e_type			= ET_CKPT;
	elf_ehdr.e_machine		= EM_X86_64;
	elf_ehdr.e_version		= EV_CURRENT;
	elf_ehdr.e_phoff		= sizeof(elf_ehdr);
	elf_ehdr.e_ehsize		= sizeof(elf_ehdr);
	elf_ehdr.e_phentsize		= sizeof(Elf64_Phdr);

	/* Get EP */
	lseek(fd_core, MAGIC_OFFSET, SEEK_SET);
	read_ptr_safe(fd_core, &core, err_close);

	/*
	 * Count the numbers of segments. Each segment
	 * is the VMA record with appropriate permissions.
	 * Then we need one big segment which would hold
	 * all the pages dumped.
	 */
	lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
	while(1) {
		read_ptr_safe(fd_core, &vma, err_close);
		if (vma.start == 0 && vma.end == 0)
			break;
		e_phnum++;
	}

	while (1) {
		read_ptr_safe(fd_core, &va, err_close);
		nrpages++;
		if (va == 0)
			break;
		lseek(fd_core, PAGE_SIZE, SEEK_CUR);
	}

	/* Figure out if we're overflowed */
	if (e_phnum > ELF_MAX_PHDR) {
		pr_err("Too many VMA areas (%li of %li allowed)\n",
		       e_phnum, ELF_MAX_PHDR);
		goto err_close;
	} else if (nrpages > ELF_MAX_PAGES) {
		pr_err("Too many pages to restore (%li of %li allowed)\n",
		       nrpages, ELF_MAX_PAGES);
		goto err_close;
	}

	/*
	 * We can write elf header now.
	 */
	lseek(fd_elf, 0, SEEK_SET);
	elf_ehdr.e_phnum	= e_phnum + 2;
	elf_ehdr.e_entry	= core.gpregs.ip;
	write_ptr_safe(fd_elf, &elf_ehdr, err_close);

	/* Offset in file (after all headers) */
	phoff = elf_ehdr.e_phnum * sizeof(elf_phdr) + sizeof(elf_ehdr);

	/* VMAs to headers */
	e_phnum = 0;
	lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
	while(1) {
		read_ptr_safe(fd_core, &vma, err_close);
		if (vma.start == 0 && vma.end == 0)
			break;

		memset(&elf_phdr, 0, sizeof(elf_phdr));

		elf_phdr.p_type		= PT_CKPT_VMA;
		elf_phdr.p_offset	= phoff;
		elf_phdr.p_vaddr	= vma.start;
		elf_phdr.p_paddr	= vma.start;
		elf_phdr.p_filesz	= sizeof(vma);
		elf_phdr.p_memsz	= vma.end - vma.start;
		elf_phdr.p_align	= 0x1000;

		if (vma.prot & PROT_READ)
			elf_phdr.p_flags |= PF_R;
		if (vma.prot & PROT_WRITE)
			elf_phdr.p_flags |= PF_W;
		if (vma.prot & PROT_EXEC)
			elf_phdr.p_flags |= PF_X;

		write_ptr_safe(fd_elf, &elf_phdr, err_close);

		phoff += sizeof(vma);
	}

	/* The binfmt header */
	memset(&elf_phdr, 0, sizeof(elf_phdr));

	elf_phdr.p_type		= PT_CKPT_CORE;
	elf_phdr.p_flags	= PF_R;
	elf_phdr.p_offset	= phoff;
	elf_phdr.p_vaddr	= 0;
	elf_phdr.p_filesz	= sizeof(core);
	elf_phdr.p_memsz	= sizeof(core);
	elf_phdr.p_align	= 0x1000;

	write_ptr_safe(fd_elf, &elf_phdr, err_close);

	phoff += sizeof(core);

	/* The pages and binfmt header */
	memset(&elf_phdr, 0, sizeof(elf_phdr));

	elf_phdr.p_type		= PT_CKPT_PAGES;
	elf_phdr.p_flags	= PF_R;
	elf_phdr.p_offset	= phoff;
	elf_phdr.p_vaddr	= 0;
	elf_phdr.p_filesz	= nrpages * (sizeof(page_entry));
	elf_phdr.p_memsz	= nrpages * (sizeof(page_entry));
	elf_phdr.p_align	= 0x1000;

	write_ptr_safe(fd_elf, &elf_phdr, err_close);

	/* Now write real contents for program segments */
	lseek(fd_core, GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
	while(1) {
		read_ptr_safe(fd_core, &vma, err_close);
		if (vma.start == 0 && vma.end == 0)
			break;
		area.vma = vma, pr_info_vma(&area);
		write_ptr_safe(fd_elf, &vma, err_close);
	}

	write_ptr_safe(fd_elf, &core, err_close);

	if (sendfile(fd_elf, fd_core, NULL, nrpages * (sizeof(page_entry))) !=
	    nrpages * (sizeof(page_entry))) {
		pr_perror("Can't send %li bytes to elf\n",
			  (long)(nrpages * (sizeof(page_entry))));
		goto err;
	}

	ret = 0;

err_close:
	close(fd_elf);
err:
	return ret;
}
