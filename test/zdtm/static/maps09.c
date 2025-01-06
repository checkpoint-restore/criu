#include <sys/mman.h>

#include "zdtmtst.h"

#define MEM_SIZE   (4UL * (1UL << 20)) /* 4MB */
#define MEM_OFFSET (MEM_SIZE - PAGE_SIZE)

const char *test_doc = "Test MAP_HUGETLB mapping";
const char *test_author = "Bui Quang Minh <minhquangbui99@gmail.com>";

int main(int argc, char **argv)
{
	void *m1, *m2;
	dev_t dev1, dev2;
	uint32_t crc;

	test_init(argc, argv);
	m1 = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_HUGETLB | MAP_SHARED | MAP_ANONYMOUS, 0, 0);
	if (m1 == MAP_FAILED) {
		pr_perror("Failed to mmap %lu Mb anonymous shared memory", MEM_SIZE >> 20);
		return 1;
	}

	dev1 = get_mapping_dev(m1);
	if (dev1 == (dev_t)-1) {
		fail("Can't get mapping dev");
		return 1;
	}

	m2 = mmap(NULL, MEM_SIZE, PROT_READ | PROT_WRITE, MAP_HUGETLB | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (m2 == MAP_FAILED) {
		pr_perror("Failed to mmap %lu Mb anonymous private memory", MEM_SIZE >> 20);
		return 1;
	}

	dev2 = get_mapping_dev(m2);
	if (dev2 == (dev_t)-1) {
		fail("Can't get mapping dev");
		return 1;
	}

	crc = ~0;
	datagen(m1, PAGE_SIZE, &crc);
	crc = ~0;
	datagen(m1 + MEM_OFFSET, PAGE_SIZE, &crc);
	crc = ~0;
	datagen(m2, PAGE_SIZE, &crc);
	crc = ~0;
	datagen(m2 + MEM_OFFSET, PAGE_SIZE, &crc);
	crc = ~0;

	test_daemon();
	test_waitsig();

	crc = ~0;
	if (datachk(m1, PAGE_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}
	crc = ~0;
	if (datachk(m1 + MEM_OFFSET, PAGE_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}
	crc = ~0;
	if (datachk(m2, PAGE_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}
	crc = ~0;
	if (datachk(m2 + MEM_OFFSET, PAGE_SIZE, &crc)) {
		fail("Data mismatch");
		return 1;
	}

	if (dev1 != get_mapping_dev(m1)) {
		fail("Mapping dev mismatch");
		return 1;
	}

	if (dev2 != get_mapping_dev(m2)) {
		fail("Mapping dev mismatch");
		return 1;
	}

	pass();

	return 0;
}
