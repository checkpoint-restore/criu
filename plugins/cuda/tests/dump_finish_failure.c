/* Loaded next to the CUDA plugin for ZDTM dump-finish failure tests. */
#include <errno.h>

#include "criu-plugin.h"
#include "mock/mock.h"

/* Fail cleanup after a successful dump, so CRIU resumes the tasks. */
static int dump_finish_failure(int ret)
{
	if (ret || !getenv("CRIU_CUDA_MOCK_DUMP_FINISH_ERROR") || !mock_failure())
		return -ENOTSUP;

	return -EIO;
}

CR_PLUGIN_REGISTER_DUMMY("dump_finish_failure")
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_FINISH, dump_finish_failure)
