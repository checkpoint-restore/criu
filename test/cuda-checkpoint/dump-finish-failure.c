/* Loaded next to the CUDA plugin by backend-errors.py. */
#include <errno.h>

#include "criu-plugin.h"

/* Fail cleanup after a successful dump, so CRIU resumes the tasks. */
static int dump_finish_failure(int ret)
{
	return ret ? -ENOTSUP : -EIO;
}

CR_PLUGIN_REGISTER_DUMMY("dump_finish_failure")
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_FINISH, dump_finish_failure)
