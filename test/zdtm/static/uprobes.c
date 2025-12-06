#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <tracefs.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Test the --allow-uprobes option";
const char *test_author = "Shashank Balaji <shashank.mahadasyam@sony.com>";

#define UPROBE_GROUP_NAME	"zdtm"
#define UPROBE_EVENT_NAME	"uprobes_test"
#define UPROBED_FUNCTION	uprobe_target

/*
 * A uprobe can be set at the start of a function, but not all instructions
 * will trigger the creation of a uprobes vma.
 *
 * Examples:
 * - aarch64: if the function is a single `ret`, then no vma creation
 * - x64: if the function is `nop; ret`, then no vma creation
 *
 * So to guarantee vma creation, create a volatile dummy variable (to prevent
 * compiler optimization) and use it (to prevent "unused variable" warning)
 */
void UPROBED_FUNCTION(void) {
	volatile int dummy = 0;
	dummy += 1;
}
/* Calling via volatile function pointer ensures noinline at callsite */
typedef void (*func_ptr)(void);
volatile func_ptr uprobe_target_alias = UPROBED_FUNCTION;

struct uprobe_context {
	struct tracefs_instance *instance;
	struct tracefs_dynevent *uprobe;
};

volatile bool got_sigtrap = false;

/*
 * Returns the file offset of a symbol in the executable of this program
 * Returns 0 on failure
*/
uint64_t calc_sym_offset(const char *sym_name)
{
	GElf_Shdr section_header;
	Elf_Scn *section = NULL;
	Elf_Data *symtab_data;
	uint64_t offset = 0;
	char buf[PATH_MAX];
	GElf_Sym symbol;
	ssize_t n_bytes;
	int n_entries;
	Elf *elf;
	int fd;
	int i;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		pr_err("ELF version of libelf is lower than that of the program\n");
		return 0;
	}

	n_bytes = readlink("/proc/self/exe", buf, sizeof(buf));
	if (n_bytes < 0) {
		pr_perror("Failed to readlink /proc/self/exe");
		return 0;
	}
	buf[n_bytes] = '\0';

	fd = open(buf, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to open self-executable");
		return 0;
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) {
		pr_err("%s\n", elf_errmsg(elf_errno()));
		goto out_fd;
	}

	/* Look for the symbol table section and its header */
	while ((section = elf_nextscn(elf, section)) != NULL) {
		gelf_getshdr(section, &section_header);
		if (section_header.sh_type == SHT_SYMTAB)
			break;
	}
	if (!section) {
		pr_err("Failed to find symbol table\n");
		goto out_elf;
	}
	symtab_data = elf_getdata(section, NULL);
	n_entries = section_header.sh_size / section_header.sh_entsize;

	/* Look for a symbol with the required name */
	for (i = 0; i < n_entries; i++) {
		gelf_getsym(symtab_data, i, &symbol);
		/* Symbol table's sh_link is the index of the string table section header */
		if (!strcmp(sym_name,
			    elf_strptr(elf, section_header.sh_link, symbol.st_name)))
			break;
	}
	if (i == n_entries) {
		pr_err("Failed to find symbol \"%s\"\n", sym_name);
		goto out_elf;
	}

	/* Get the section the symbol belongs to (mostly .text) */
	section = elf_getscn(elf, symbol.st_shndx);
	gelf_getshdr(section, &section_header);
	offset = symbol.st_value - section_header.sh_addr + section_header.sh_offset;

out_elf:
	elf_end(elf);
out_fd:
	close(fd);
	return offset;
}

/*
 * Set and enable a uprobe on the file at the given offset
 * Returns struct uprobe_context with members set to NULL on failure
*/
struct uprobe_context enable_uprobe(const char *file, uint64_t offset)
{
	struct tracefs_instance *trace_instance;
	struct tracefs_dynevent *uprobe;
	struct uprobe_context context = {};

	trace_instance = tracefs_instance_create("zdtm_uprobes_test");
	if (!trace_instance) {
		pr_perror("Failed to create tracefs instance");
		return context;
	}
	tracefs_instance_reset(trace_instance);

	uprobe = tracefs_uprobe_alloc(UPROBE_GROUP_NAME, UPROBE_EVENT_NAME, file, offset, NULL);
	if (!uprobe) {
		pr_perror("Failed to allocate uprobe");
		goto instance_destroy;
	}

	if (tracefs_dynevent_create(uprobe)) {
		pr_perror("Failed to create uprobe");
		goto uprobe_free;
	}

	if (tracefs_event_enable(trace_instance, UPROBE_GROUP_NAME, UPROBE_EVENT_NAME)) {
		pr_perror("Failed to enable uprobe");
		goto uprobe_destroy;
	}

	context.instance = trace_instance;
	context.uprobe   = uprobe;
	return context;

uprobe_destroy:
	tracefs_dynevent_destroy(uprobe, false);
uprobe_free:
	tracefs_dynevent_free(uprobe);
instance_destroy:
	tracefs_instance_destroy(trace_instance);
	tracefs_instance_free(trace_instance);
	return context;
}

void destroy_uprobe(struct uprobe_context context)
{
	tracefs_dynevent_destroy(context.uprobe, true);
	tracefs_dynevent_free(context.uprobe);
	tracefs_instance_destroy(context.instance);
	tracefs_instance_free(context.instance);
}

/*
 * Check for the existence of the "[uprobes]" vma in /proc/self/maps
 * Returns -1 on failure, 0 if not found, 1 if found
*/
int uprobes_vma_exists(void)
{
	FILE *f;
	char buf[LINE_MAX];
	int ret = 0;

	f = fopen("/proc/self/maps", "r");
	if (!f) {
		pr_perror("Failed to open /proc/self/maps");
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		if (strstr(buf, "[uprobes]")) {
			ret = 1;
			break;
		}
	}
	if (ret == 0 && !feof(f)) {
		pr_err("Failed to finish reading /proc/self/maps\n");
		ret = -1;
	}

	fclose(f);
	return ret;
}

/*
 * SIGTRAP is sent if execution reaches a previously set uprobed location, and
 * the corresponding uprobe is not active. We don't want this to happen on restore
*/
void sigtrap_handler(int signo, siginfo_t *info, void* context)
{
	if (info->si_code == SI_KERNEL) {
		got_sigtrap = true;
		fail("SIGTRAP on attempting to call uprobed function");
	}
}

int main(int argc, char **argv)
{
	struct uprobe_context context;
	struct sigaction sa;
	char buf[PATH_MAX];
	uint64_t offset;
	int n_bytes;
	int ret = 1;

	test_init(argc, argv);

	offset = calc_sym_offset(__stringify(UPROBED_FUNCTION));
	if (!offset)
		return 1;

	n_bytes = readlink("/proc/self/exe", buf, sizeof(buf));
	if (n_bytes < 0) {
		pr_perror("Failed to readlink /proc/self/exe");
		return 1;
	}
	buf[n_bytes] = '\0';

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = sigtrap_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTRAP, &sa, NULL)) {
		pr_perror("Failed to set SIGTRAP handler");
		return 1;
	}

	context = enable_uprobe(buf, offset);
	if (!context.instance)
		return 1;

	/*
	 * Execution must reach the uprobed location at least once
	 * for the kernel to create the uprobes vma
	*/
	uprobe_target_alias();

	switch (uprobes_vma_exists()) {
	case -1:
		goto out_uprobe;
		break;
	case 0:
		pr_err("uprobes vma does not exist\n");
		goto out_uprobe;
		break;
	case 1:
		test_msg("Found uprobes vma\n");
		break;
	}

	test_daemon();
	test_waitsig();

	/*
	 * Calling the uprobed function after restore should not cause
	 * a SIGTRAP, since the uprobe is still active
	*/
	uprobe_target_alias();
	if (!got_sigtrap) {
		pass();
		ret = 0;
	}

out_uprobe:
	destroy_uprobe(context);
	return ret;
}
