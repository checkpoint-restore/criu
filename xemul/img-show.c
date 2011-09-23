#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <linux/types.h>
#include <string.h>
#include "img_structs.h"
#include "binfmt_img.h"

static int show_fdinfo(int fd)
{
	char data[1024];
	struct fdinfo_entry e;

	while (1) {
		int ret;

		ret = read(fd, &e, sizeof(e));
		if (ret == 0)
			break;
		if (ret != sizeof(e)) {
			perror("Can't read");
			return 1;
		}

		ret = read(fd, data, e.len);
		if (ret != e.len) {
			perror("Can't read");
			return 1;
		}

		data[e.len] = '\0';
		switch (e.type) {
		case FDINFO_FD:
			printf("fd %d [%s] pos %lx flags %o\n", (int)e.addr, data, e.pos, e.flags);
			break;
		case FDINFO_MAP:
			printf("map %lx [%s] flags %o\n", e.addr, data, e.flags);
			break;
		default:
			fprintf(stderr, "Unknown fdinfo entry type %d\n", e.type);
			return 1;
		}
	}

	return 0;
}

#define PAGE_SIZE	4096

static int show_mem(int fd)
{
	__u64 vaddr;
	unsigned int data[2];

	while (1) {
		if (read(fd, &vaddr, 8) == 0)
			break;
		if (vaddr == 0)
			break;

		read(fd, &data[0], sizeof(unsigned int));
		lseek(fd, PAGE_SIZE - 2 * sizeof(unsigned int), SEEK_CUR);
		read(fd, &data[1], sizeof(unsigned int));

		printf("\tpage 0x%lx [%x...%x]\n", (unsigned long)vaddr, data[0], data[1]);
	}

	return 0;
}

static int show_pages(int fd)
{
	return show_mem(fd);
}

static int show_shmem(int fd)
{
	int r;
	struct shmem_entry e;

	while (1) {
		r = read(fd, &e, sizeof(e));
		if (r == 0)
			return 0;
		if (r != sizeof(e)) {
			perror("Can't read shmem entry");
			return 1;
		}

		printf("%016lx-%016lx %016x\n", e.start, e.end, e.shmid);
	}
}

static char *segval(__u16 seg)
{
	switch (seg) {
		case CKPT_X86_SEG_NULL:		return "nul";
		case CKPT_X86_SEG_USER32_CS:	return "cs32";
		case CKPT_X86_SEG_USER32_DS:	return "ds32";
		case CKPT_X86_SEG_USER64_CS:	return "cs64";
		case CKPT_X86_SEG_USER64_DS:	return "ds64";
	}

	if (seg & CKPT_X86_SEG_TLS)
		return "tls";
	if (seg & CKPT_X86_SEG_LDT)
		return "ldt";

	return "[unknown]";
}

static int show_regs(int fd)
{
	struct binfmt_regs_image ri;

	if (read(fd, &ri, sizeof(ri)) != sizeof(ri)) {
		perror("Can't read registers from image");
		return 1;
	}

	printf("Registers:\n");

	printf("\tr15:     %016lx\n", ri.r.r15);
	printf("\tr14:     %016lx\n", ri.r.r14);
	printf("\tr13:     %016lx\n", ri.r.r13);
	printf("\tr12:     %016lx\n", ri.r.r12);
	printf("\tr11:     %016lx\n", ri.r.r11);
	printf("\tr10:     %016lx\n", ri.r.r10);
	printf("\tr9:      %016lx\n", ri.r.r9);
	printf("\tr8:      %016lx\n", ri.r.r8);
	printf("\tax:      %016lx\n", ri.r.ax);
	printf("\torig_ax: %016lx\n", ri.r.orig_ax);
	printf("\tbx:      %016lx\n", ri.r.bx);
	printf("\tcx:      %016lx\n", ri.r.cx);
	printf("\tdx:      %016lx\n", ri.r.dx);
	printf("\tsi:      %016lx\n", ri.r.si);
	printf("\tdi:      %016lx\n", ri.r.di);
	printf("\tip:      %016lx\n", ri.r.ip);
	printf("\tflags:   %016lx\n", ri.r.flags);
	printf("\tbp:      %016lx\n", ri.r.bp);
	printf("\tsp:      %016lx\n", ri.r.sp);
	printf("\tgs:      %016lx\n", ri.r.gs);
	printf("\tfs:      %016lx\n", ri.r.fs);
	printf("\tgsindex: %s\n", segval(ri.r.gsindex));
	printf("\tfsindex: %s\n", segval(ri.r.fsindex));
	printf("\tcs:      %s\n", segval(ri.r.cs));
	printf("\tss:      %s\n", segval(ri.r.ss));
	printf("\tds:      %s\n", segval(ri.r.ds));
	printf("\tes:      %s\n", segval(ri.r.es));

	printf("\ttls0     %016lx\n", ri.r.tls[0]);
	printf("\ttls1     %016lx\n", ri.r.tls[1]);
	printf("\ttls2     %016lx\n", ri.r.tls[2]);

	return 0;
}

static int show_mm(int fd, unsigned long *stack)
{
	struct binfmt_mm_image mi;

	if (read(fd, &mi, sizeof(mi)) != sizeof(mi)) {
		perror("Can't read mm from image");
		return 1;
	}

	printf("MM:\n");
	printf("\tflags:       %016lx\n", mi.flags);
	printf("\tdef_flags:   %016lx\n", mi.def_flags);
	printf("\tstart_code:  %016lx\n", mi.start_code);
	printf("\tend_code:    %016lx\n", mi.end_code);
	printf("\tstart_data:  %016lx\n", mi.start_data);
	printf("\tend_data:    %016lx\n", mi.end_data);
	printf("\tstart_brk:   %016lx\n", mi.start_brk);
	printf("\tbrk:         %016lx\n", mi.brk);
	printf("\tstart_stack: %016lx\n", mi.start_stack);
	printf("\targ_start:   %016lx\n", mi.arg_start);
	printf("\targ_end:     %016lx\n", mi.arg_end);
	printf("\tenv_start:   %016lx\n", mi.env_start);
	printf("\tenv_end:     %016lx\n", mi.env_end);

	*stack = mi.start_stack;

	return 0;
}

static int show_vmas(int fd, unsigned long stack)
{
	struct binfmt_vma_image vi;

	printf("VMAs:\n");
	while (1) {
		char *note = "";

		if (read(fd, &vi, sizeof(vi)) != sizeof(vi)) {
			perror("Can't read vma from image");
			return 1;
		}

		if (vi.start == 0 && vi.end == 0)
			return 0;

		if (vi.start <= stack && vi.end >= stack)
			note = "[stack]";

		printf("\t%016lx-%016lx file %d %016lx prot %x flags %x %s\n",
				vi.start, vi.end, vi.fd, vi.pgoff,
				vi.prot, vi.flags, note);
	}
}

static int show_privmem(int fd)
{
	printf("Pages:\n");
	return show_mem(fd);
}

static int show_core(int fd)
{
	__u32 version = 0;
	unsigned long stack;

	read(fd, &version, 4);
	if (version != BINFMT_IMG_VERS_0) {
		printf("Unsupported version %d\n", version);
		return 1;
	}

	/* the pad */
	read(fd, &version, 4);

	printf("Showing version 0\n");

	if (show_regs(fd))
		return 1;

	if (show_mm(fd, &stack))
		return 1;

	if (show_vmas(fd, stack))
		return 1;

	if (show_privmem(fd))
		return 1;

	return 0;
}

static int show_pstree(int fd)
{
	int ret;
	struct pstree_entry e;

	while (1) {
		int i;
		__u32 *ch;

		ret = read(fd, &e, sizeof(e));
		if (ret == 0)
			return 0;
		if (ret != sizeof(e)) {
			perror("Can't read processes entry");
			return 1;
		}

		printf("%d:", e.pid);
		i = e.nr_children * sizeof(__u32);
		ch = malloc(i);
		ret = read(fd, ch, i);
		if (ret != i) {
			perror("Can't read children list");
			return 1;
		}

		for (i = 0; i < e.nr_children; i++)
			printf(" %d", ch[i]);
		printf("\n");
	}
}

static int show_pipes(int fd)
{
	struct pipes_entry e;
	int ret;
	char buf[17];

	while (1) {
		ret = read(fd, &e, sizeof(e));
		if (ret == 0)
			break;
		if (ret != sizeof(e)) {
			perror("Can't read pipe entry");
			return 1;
		}

		printf("%d: %lx %o %d ", e.fd, e.pipeid, e.flags, e.bytes);
		if (e.flags & O_WRONLY) {
			printf("\n");

			if (e.bytes) {
				printf("Bogus pipe\n");
				return 1;
			}

			continue;
		}

		memset(buf, 0, sizeof(buf));
		ret = e.bytes;
		if (ret > 16)
			ret = 16;

		read(fd, buf, ret);
		printf("\t[%s", buf);
		if (ret < e.bytes)
			printf("...");
		printf("]\n");
		lseek(fd, e.bytes - ret, SEEK_CUR);
	}

	return 0;

}

int main(int argc, char **argv)
{
	__u32 type;
	int fd;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("Can't open");
		return 1;
	}

	read(fd, &type, 4);

	if (type == FDINFO_MAGIC)
		return show_fdinfo(fd);
	if (type == PAGES_MAGIC)
		return show_pages(fd);
	if (type == SHMEM_MAGIC)
		return show_shmem(fd);
	if (type == PSTREE_MAGIC)
		return show_pstree(fd);
	if (type == PIPES_MAGIC)
		return show_pipes(fd);
	if (type == BINFMT_IMG_MAGIC)
		return show_core(fd);

	printf("Unknown file type 0x%x\n", type);
	return 1;
}
