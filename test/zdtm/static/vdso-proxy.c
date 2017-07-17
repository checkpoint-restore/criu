#include <stdbool.h>
#include <stdlib.h>

#include "zdtmtst.h"

const char *test_doc	= "Compare mappings before/after C/R for vdso/vvar presence. Should run iterative under vdso proxy fault-injection.\n";
const char *test_author	= "Dmitry Safonov <dsafonov@virtuozzo.com>";

#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))
#define VDSO_BAD_ADDR		(-1ul)
#define MAX_VMAS		80
#define BUF_SIZE		1024

/*
 * After C/R with vdso trampolines insertion, there should
 * be added one or two vmas: vdso and possibly vvar.
 * We need to check that nr. vmas after C/R <= +2 new vmas.
 * Also previous vdso/vvar vma should still be present after C/R.
 */
struct vm_area {
	unsigned long start;
	unsigned long end;
	bool is_vvar_or_vdso;
};

static char buf[BUF_SIZE];

static int parse_maps(struct vm_area *vmas)
{
	FILE *maps;
	int i;

	maps = fopen("/proc/self/maps", "r");
	if (maps == NULL) {
		pr_err("Failed to open maps file: %m\n");
		return -1;
	}

	for (i = 0; i < MAX_VMAS; i++) {
		struct vm_area *v = &vmas[i];
		char *end;

		if (fgets(buf, BUF_SIZE, maps) == NULL)
			break;

		v->start = strtoul(buf, &end, 16);
		v->end = strtoul(end + 1, NULL, 16);
		v->is_vvar_or_vdso |= strstr(buf, "[vdso]") != NULL;
		v->is_vvar_or_vdso |= strstr(buf, "[vvar]") != NULL;
		test_msg("[NOTE]\tVMA: [%#lx, %#lx]\n", v->start, v->end);
	}

	if (i == MAX_VMAS) {
		pr_err("Number of VMAs is bigger than reserved array's size\n");
		return -1;
	}

	if (fclose(maps)) {
		pr_err("Failed to close maps file: %m\n");
		return -1;
	}

	return i;
}

int compare_vmas(struct vm_area *vmax, struct vm_area *vmay)
{
	if (vmax->start > vmay->start)
		return 1;
	if (vmax->start < vmay->start)
		return -1;
	if (vmax->end > vmay->end)
		return 1;
	if (vmax->end < vmay->end)
		return -1;

	return 0;
}

static int check_vvar_vdso(struct vm_area *before, struct vm_area *after)
{
	int i, j = 0;

	for (i = 0; i < MAX_VMAS && j < MAX_VMAS; i++, j++) {
		int cmp = compare_vmas(&before[i], &after[j]);

		if (cmp == 0)
			continue;

		if (cmp < 0) {/* Lost mapping */
			test_msg("[NOTE]\tLost mapping: %#lx-%#lx\n",
				before[i].start, before[i].end);
			j--;
			if (before[i].is_vvar_or_vdso) {
				fail("Lost vvar/vdso mapping");
				return -1;
			}
			continue;
		}

		test_msg("[NOTE]\tNew mapping appeared: %#lx-%#lx\n",
			after[j].start, after[j].end);
		i--;
	}

	return 0;
}

static struct vm_area vmas_before[MAX_VMAS];
static struct vm_area vmas_after[MAX_VMAS];

int main(int argc, char *argv[])
{
	int nr_before, nr_after;

	test_init(argc, argv);

	test_msg("[NOTE]\tMappings before:\n");
	nr_before = parse_maps(vmas_before);
	if (nr_before < 0) {
		pr_perror("Faied to parse maps");
		return -1;
	}

	test_daemon();
	test_waitsig();

	test_msg("[NOTE]\tMappings after:\n");
	nr_after = parse_maps(vmas_after);
	if (nr_after < 0) {
		pr_perror("Faied to parse maps");
		return -1;
	}

	/* After restore vDSO/VVAR blobs must remain in the old place. */
	if (check_vvar_vdso(vmas_before, vmas_after))
		return -1;

	if (nr_before + 2 < nr_after) {
		fail("There is more than two (VVAR/vDSO) vmas added after C/R");
		return -1;
	}

	pass();

	return 0;
}
