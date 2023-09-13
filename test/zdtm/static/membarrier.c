#include <linux/membarrier.h>
#include <sys/syscall.h>
#include <stdbool.h>
#include "zdtmtst.h"

const char *test_doc = "Test membarrier() migration";
const char *test_author = "Michał Mirosław <emmir@google.com>";

/*
 * Define membarrier() CMDs to avoid depending on exact kernel header version.
 */
#define MEMBARRIER_CMD_GLOBAL_EXPEDITED			    (1 << 1)
#define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED	    (1 << 2)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED		    (1 << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED	    (1 << 4)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE	    (1 << 5)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (1 << 6)
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ		    (1 << 7)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ	    (1 << 8)
#define MEMBARRIER_CMD_GET_REGISTRATIONS		    (1 << 9)

static int membarrier(int cmd, unsigned int flags, int cpu_id)
{
	return syscall(__NR_membarrier, cmd, flags, cpu_id);
}

static const struct {
	const char *name_suffix;
	int register_cmd;
	int execute_cmd;
} membarrier_cmds[] = {
	{ "GLOBAL_EXPEDITED",            MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
		MEMBARRIER_CMD_GLOBAL_EXPEDITED },
	{ "PRIVATE_EXPEDITED",           MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
		MEMBARRIER_CMD_PRIVATE_EXPEDITED },
	{ "PRIVATE_EXPEDITED_SYNC_CORE", MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
		MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE },
	{ "PRIVATE_EXPEDITED_RSEQ",      MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
		MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ },
};
static const int n_membarrier_cmds = sizeof(membarrier_cmds) / sizeof(*membarrier_cmds);

static int register_membarriers(void)
{
	int barriers_supported, barriers_registered;
	bool all_ok = true;

	barriers_supported = membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
	if (barriers_supported < 0) {
		fail("membarrier() not supported by running kernel");
		return -1;
	}

	barriers_registered = 0;
	for (int i = 0; i < n_membarrier_cmds; ++i) {
		if (~barriers_supported & membarrier_cmds[i].register_cmd)
			continue;

		barriers_registered |= membarrier_cmds[i].register_cmd;

		if (membarrier(membarrier_cmds[i].register_cmd, 0, 0) < 0) {
			pr_perror("membarrier(REGISTER_%s)", membarrier_cmds[i].name_suffix);
			all_ok = false;
		}
	}

	if (!all_ok) {
		fail("can't register membarrier()s - tried %#x, kernel %#x",
		     barriers_registered, barriers_supported);
		return -1;
	}

	if (!barriers_registered) {
		fail("no known membarrier() cmds are supported by the kernel");
		return -1;
	}

	return barriers_registered;
}

static bool check_membarriers_compat(int barriers_registered)
{
	bool all_ok = true;

	for (int i = 0; i < n_membarrier_cmds; ++i) {
		if (~barriers_registered & membarrier_cmds[i].register_cmd)
			continue;
		if (membarrier(membarrier_cmds[i].execute_cmd, 0, 0) < 0) {
			pr_perror("membarrier(%s)", membarrier_cmds[i].name_suffix);
			all_ok = false;
		}
	}

	if (!all_ok)
		fail("membarrier() check failed");

	return all_ok;
}

static bool check_membarriers_get_registrations(int barriers_registered)
{
	int ret = membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS, 0, 0);
	if (ret < 0) {
		if (errno == EINVAL) {
			test_msg("membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS) not supported by running kernel");
			return true;
		}
		fail("membarrier(MEMBARRIER_CMD_GET_REGISTRATIONS)");
		return false;
	}
	if (ret != barriers_registered) {
		fail("MEMBARRIER_CMD_GET_REGISTRATIONS check failed, expected: %d, got: %d",
		     barriers_registered, ret);
		return false;
	}

	return true;
}

static bool check_membarriers(int barriers_registered)
{
	return check_membarriers_compat(barriers_registered) &&
	       check_membarriers_get_registrations(barriers_registered);
}

int main(int argc, char **argv)
{
	int barriers_registered;

	test_init(argc, argv);

	barriers_registered = register_membarriers();
	if (barriers_registered < 0)
		return 1;

	test_msg("Pre-migration membarriers check\n");
	if (!check_membarriers(barriers_registered))
		return 1;

	test_daemon();
	test_waitsig();

	test_msg("Post-migration membarriers check\n");
	if (!check_membarriers(barriers_registered))
		return 1;

	pass();
	return 0;
}
