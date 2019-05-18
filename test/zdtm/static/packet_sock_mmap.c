#include "zdtmtst.h"

const char *test_doc = "static test for packet sockets mmaps";
const char *test_author = "Pavel Emelyanov <xemul@parallels.com>";

#include <stdio.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/version.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/mman.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0)

struct tpacket_req3 {
	unsigned int tp_block_size;
	unsigned int tp_block_nr;
	unsigned int tp_frame_size;
	unsigned int tp_frame_nr;
	unsigned int tp_retire_blk_tov;
	unsigned int tp_sizeof_priv;
	unsigned int tp_feature_req_word;
};

#endif

static void check_map_is_there(unsigned long addr, int sk)
{
	FILE *f;
	char line[64];
	struct stat ss;

	fstat(sk, &ss);
	f = fopen("/proc/self/maps", "r");
	while (fgets(line, sizeof(line), f) != NULL) {
		unsigned long start;
		int maj, min, ino;

		sscanf(line, "%lx-%*x %*s %*s %x:%x %d %*s", &start, &maj, &min, &ino);
		if ((start == addr) && ss.st_dev == makedev(maj, min) && ss.st_ino == ino) {
			pass();
			fclose(f);
			return;
		}
	}

	fail("No socket mapping found");
}

int main(int argc, char **argv)
{
	int sk;
	struct tpacket_req3 ring;
	void *mem;

	test_init(argc, argv);

	sk = socket(PF_PACKET, SOCK_RAW, 0);
	if (sk < 0) {
		pr_perror("Can't create socket 1");
		return 1;
	}

	memset(&ring, 0, sizeof(ring));
	ring.tp_block_size = PAGE_SIZE;
	ring.tp_block_nr = 1;
	ring.tp_frame_size = 1024;
	ring.tp_frame_nr = (ring.tp_block_size / ring.tp_frame_size) * ring.tp_block_nr;
	if (setsockopt(sk, SOL_PACKET, PACKET_RX_RING, &ring, sizeof(ring)) < 0) {
		pr_perror("Can't set rx ring");
		return 1;
	}

	memset(&ring, 0, sizeof(ring));
	ring.tp_block_size = PAGE_SIZE;
	ring.tp_block_nr = 1;
	ring.tp_frame_size = 1024;
	ring.tp_frame_nr = (ring.tp_block_size / ring.tp_frame_size) * ring.tp_block_nr;
	if (setsockopt(sk, SOL_PACKET, PACKET_TX_RING, &ring, sizeof(ring)) < 0) {
		pr_perror("Can't set tx ring");
		return 1;
	}

	mem = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FILE, sk, 0);
	if (mem == MAP_FAILED) {
		pr_perror("Can't mmap socket");
		return 1;
	}

	test_daemon();
	test_waitsig();

	check_map_is_there((unsigned long)mem, sk);

	return 0;
}
