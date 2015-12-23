#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <time.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "zdtmtst.h"

const char *test_doc	= "Check if we can use vDSO using direct vDSO calls\n";
const char *test_author	= "Cyrill Gorcunov <gorcunov@openvz.org";

typedef int (__vdso_clock_gettime_t)(clockid_t clock, struct timespec *ts);
typedef long (__vdso_getcpu_t)(unsigned *cpu, unsigned *node, void *unused);
typedef int (__vdso_gettimeofday_t)(struct timeval *tv, struct timezone *tz);
typedef time_t (__vdso_time_t)(time_t *t);

#define TIME_DELTA_SEC		(3)

#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))

#define VDSO_BAD_ADDR		(-1ul)

struct vdso_symbol {
	char			name[32];
	unsigned long		offset;
};

#define VDSO_SYMBOL_INIT	{ .offset = VDSO_BAD_ADDR, }

/* Check if symbol present in symtable */
static inline bool vdso_symbol_empty(struct vdso_symbol *s)
{
	return s->offset == VDSO_BAD_ADDR && s->name[0] == '\0';
}

enum {
	VDSO_SYMBOL_CLOCK_GETTIME,
	VDSO_SYMBOL_GETCPU,
	VDSO_SYMBOL_GETTIMEOFDAY,
	VDSO_SYMBOL_TIME,

	VDSO_SYMBOL_MAX
};

#define VDSO_SYMBOL_CLOCK_GETTIME_NAME	"__vdso_clock_gettime"
#define VDSO_SYMBOL_GETCPU_NAME		"__vdso_getcpu"
#define VDSO_SYMBOL_GETTIMEOFDAY_NAME	"__vdso_gettimeofday"
#define VDSO_SYMBOL_TIME_NAME		"__vdso_time"

struct vdso_symtable {
	unsigned long		vma_start;
	unsigned long		vma_end;
	struct vdso_symbol	symbols[VDSO_SYMBOL_MAX];
};

#define VDSO_SYMTABLE_INIT						\
	{								\
		.vma_start	= VDSO_BAD_ADDR,			\
		.vma_end	= VDSO_BAD_ADDR,			\
		.symbols		= {				\
			[0 ... VDSO_SYMBOL_MAX - 1] =			\
				(struct vdso_symbol)VDSO_SYMBOL_INIT,	\
			},						\
	}

static bool __ptr_oob(void *ptr, void *start, size_t size)
{
	void *end = (void *)((unsigned long)start + size);
	return ptr > end || ptr < start;
}

static unsigned long elf_hash(const unsigned char *name)
{
	unsigned long h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000ul;
		if (g)
			h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

static int vdso_fill_symtable(char *mem, size_t size, struct vdso_symtable *t)
{
	Elf64_Phdr *dynamic = NULL, *load = NULL;
	Elf64_Ehdr *ehdr = (void *)mem;
	Elf64_Dyn *dyn_strtab = NULL;
	Elf64_Dyn *dyn_symtab = NULL;
	Elf64_Dyn *dyn_strsz = NULL;
	Elf64_Dyn *dyn_syment = NULL;
	Elf64_Dyn *dyn_hash = NULL;
	Elf64_Word *hash = NULL;
	Elf64_Phdr *phdr;
	Elf64_Dyn *d;

	Elf64_Word *bucket, *chain;
	Elf64_Word nbucket, nchain;

	/*
	 * See Elf specification for this magic values.
	 */
	const char elf_ident[] = {
		0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	const char *vdso_symbols[VDSO_SYMBOL_MAX] = {
		[VDSO_SYMBOL_CLOCK_GETTIME]	= VDSO_SYMBOL_CLOCK_GETTIME_NAME,
		[VDSO_SYMBOL_GETCPU]		= VDSO_SYMBOL_GETCPU_NAME,
		[VDSO_SYMBOL_GETTIMEOFDAY]	= VDSO_SYMBOL_GETTIMEOFDAY_NAME,
		[VDSO_SYMBOL_TIME]		= VDSO_SYMBOL_TIME_NAME,
	};

	char *dynsymbol_names;
	unsigned int i, j, k;

	BUILD_BUG_ON(sizeof(elf_ident) != sizeof(ehdr->e_ident));

	test_msg("Parsing at %lx %lx\n", (long)mem, (long)mem + (long)size);

	/*
	 * Make sure it's a file we support.
	 */
	if (memcmp(ehdr->e_ident, elf_ident, sizeof(elf_ident))) {
		pr_perror("Elf header magic mismatch");
		return -EINVAL;
	}

	/*
	 * We need PT_LOAD and PT_DYNAMIC here. Each once.
	 */
	phdr = (void *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (__ptr_oob(phdr, mem, size))
			goto err_oob;
		switch (phdr->p_type) {
		case PT_DYNAMIC:
			if (dynamic) {
				pr_perror("Second PT_DYNAMIC header");
				return -EINVAL;
			}
			dynamic = phdr;
			break;
		case PT_LOAD:
			if (load) {
				pr_perror("Second PT_LOAD header");
				return -EINVAL;
			}
			load = phdr;
			break;
		}
	}

	if (!load || !dynamic) {
		pr_perror("One of obligated program headers is missed");
		return -EINVAL;
	}

	test_msg("PT_LOAD p_vaddr: %lx\n", (unsigned long)load->p_vaddr);

	/*
	 * Dynamic section tags should provide us the rest of information
	 * needed. Note that we're interested in a small set of tags.
	 */
	d = (void *)&mem[dynamic->p_offset];
	for (i = 0; i < dynamic->p_filesz / sizeof(*d); i++, d++) {
		if (__ptr_oob(d, mem, size))
			goto err_oob;

		if (d->d_tag == DT_NULL) {
			break;
		} else if (d->d_tag == DT_STRTAB) {
			dyn_strtab = d;
		} else if (d->d_tag == DT_SYMTAB) {
			dyn_symtab = d;
		} else if (d->d_tag == DT_STRSZ) {
			dyn_strsz = d;
		} else if (d->d_tag == DT_SYMENT) {
			dyn_syment = d;
		} else if (d->d_tag == DT_HASH) {
			dyn_hash = d;
		}
	}

	if (!dyn_strtab || !dyn_symtab || !dyn_strsz || !dyn_syment || !dyn_hash) {
		pr_perror("Not all dynamic entries are present");
		return -EINVAL;
	}

	dynsymbol_names = &mem[dyn_strtab->d_un.d_val - load->p_vaddr];
	if (__ptr_oob(dynsymbol_names, mem, size))
		goto err_oob;

	hash = (void *)&mem[(unsigned long)dyn_hash->d_un.d_ptr - (unsigned long)load->p_vaddr];
	if (__ptr_oob(hash, mem, size))
		goto err_oob;

	nbucket = hash[0];
	nchain = hash[1];
	bucket = &hash[2];
	chain = &hash[nbucket + 2];

	test_msg("nbucket %lu nchain %lu bucket %p chain %p\n",
	       (long)nbucket, (long)nchain, bucket, chain);

	for (i = 0; i < ARRAY_SIZE(vdso_symbols); i++) {
		k = elf_hash((const unsigned char *)vdso_symbols[i]);

		for (j = bucket[k % nbucket]; j < nchain && chain[j] != STN_UNDEF; j = chain[j]) {
			Elf64_Sym *sym = (void *)&mem[dyn_symtab->d_un.d_ptr - load->p_vaddr];
			char *name;

			sym = &sym[j];
			if (__ptr_oob(sym, mem, size))
				continue;

			if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC &&
			    ELF64_ST_BIND(sym->st_info) != STB_GLOBAL)
				continue;

			name = &dynsymbol_names[sym->st_name];
			if (__ptr_oob(name, mem, size))
				continue;

			if (strcmp(name, vdso_symbols[i]))
				continue;

			memcpy(t->symbols[i].name, name, sizeof(t->symbols[i].name));
			t->symbols[i].offset = (unsigned long)sym->st_value - load->p_vaddr;
			test_msg("symbol %s offset %lx\n", t->symbols[i].name, t->symbols[i].offset);
			break;
		}
	}

	return 0;

err_oob:
	pr_perror("Corrupted Elf data");
	return -EFAULT;
}

static int vdso_fill_self_symtable(struct vdso_symtable *s)
{
	char buf[512];
	int ret = -1;
	FILE *maps;

	*s = (struct vdso_symtable)VDSO_SYMTABLE_INIT;

	maps = fopen("/proc/self/maps", "r");
	if (!maps) {
		pr_perror("Can't open self-vma");
		return -1;
	}

	while (fgets(buf, sizeof(buf), maps)) {
		unsigned long start, end;

		if (!strstr(buf, "[vdso]"))
			continue;

		ret = sscanf(buf, "%lx-%lx", &start, &end);
		if (ret != 2) {
			ret = -1;
			pr_perror("Can't find vDSO bounds");
			goto err;
		}

		s->vma_start = start;
		s->vma_end = end;

		ret = vdso_fill_symtable((void *)start, end - start, s);
		break;
	}

	test_msg("[vdso] %lx-%lx\n", s->vma_start, s->vma_end);
err:
	fclose(maps);
	return ret;
}

static int vdso_clock_gettime_handler(void *func)
{
	__vdso_clock_gettime_t *vdso_clock_gettime = func;
	struct timespec ts1, ts2;

	clock_gettime(CLOCK_REALTIME, &ts1);
	vdso_clock_gettime(CLOCK_REALTIME, &ts2);

	test_msg("clock_gettime: tv_sec %li vdso_clock_gettime: tv_sec %li\n",
		 ts1.tv_sec, ts2.tv_sec);

	if (abs(ts1.tv_sec - ts2.tv_sec) > TIME_DELTA_SEC) {
		pr_perror("Delta is too big");
		return -1;
	}

	return 0;
}

static int vdso_getcpu_handler(void *func)
{
	__vdso_getcpu_t *vdso_getcpu = func;
	unsigned cpu, node;

	vdso_getcpu(&cpu, &node, NULL);
	test_msg("vdso_getcpu: cpu %d node %d\n", cpu, node);

	return 0;
}

static int vdso_gettimeofday_handler(void *func)
{
	__vdso_gettimeofday_t *vdso_gettimeofday = func;
	struct timeval tv1, tv2;
	struct timezone tz;

	gettimeofday(&tv1, &tz);
	vdso_gettimeofday(&tv2, &tz);

	test_msg("gettimeofday: tv_sec %li vdso_gettimeofday: tv_sec %li\n",
		 tv1.tv_sec, tv2.tv_sec);

	if (abs(tv1.tv_sec - tv2.tv_sec) > TIME_DELTA_SEC) {
		pr_perror("Delta is too big");
		return -1;
	}

	return 0;
}

static int vdso_time_handler(void *func)
{
	__vdso_time_t *vdso_time = func;
	time_t t1, t2;

	t1 = time(NULL);
	t2 = vdso_time(NULL);

	test_msg("time: %li vdso_time: %li\n", (long)t1, (long)t1);

	if (abs(t1 - t2) > TIME_DELTA_SEC) {
		pr_perror("Delta is too big");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	typedef int (handler_t)(void *func);

	struct vdso_symtable symtable;
	size_t i;

	handler_t *handlers[VDSO_SYMBOL_MAX] = {
		[VDSO_SYMBOL_CLOCK_GETTIME]	= vdso_clock_gettime_handler,
		[VDSO_SYMBOL_GETCPU]		= vdso_getcpu_handler,
		[VDSO_SYMBOL_GETTIMEOFDAY]	= vdso_gettimeofday_handler,
		[VDSO_SYMBOL_TIME]		= vdso_time_handler,
	};

	test_init(argc, argv);

	if (vdso_fill_self_symtable(&symtable)) {
		pr_perror("Faied to parse vdso");
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE(symtable.symbols); i++) {
		struct vdso_symbol *s = &symtable.symbols[i];
		handler_t *func;

		if (vdso_symbol_empty(s) || i > ARRAY_SIZE(handlers))
			continue;
		func = handlers[i];

		if (func((void *)(s->offset + symtable.vma_start))) {
			pr_perror("Handler error");
			return -1;
		}
	}

	test_daemon();
	test_waitsig();

	/*
	 * After restore the vDSO must remain in old place.
	 */
	for (i = 0; i < ARRAY_SIZE(symtable.symbols); i++) {
		struct vdso_symbol *s = &symtable.symbols[i];
		handler_t *func;

		if (vdso_symbol_empty(s) || i > ARRAY_SIZE(handlers))
			continue;
		func = handlers[i];

		if (func((void *)(s->offset + symtable.vma_start))) {
			fail("Handler error");
			return -1;
		}
	}

	pass();

	return 0;
}
