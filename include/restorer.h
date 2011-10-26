#ifndef CR_RESTORER_H__
#define CR_RESTORER_H__

#include <signal.h>

#include "image.h"

#define RESTORER_ARGS_SIZE	512
#define RESTORER_STACK_MIDDLE	(16 << 10)
#define RESTORER_STACK_SIZE	(RESTORER_STACK_MIDDLE * 2)

long restorer(long cmd);

typedef long (*restorer_fcall_t) (long cmd);

#define RESTORER_CMD__NONE		0
#define RESTORER_CMD__GET_ARG_OFFSET	1
#define RESTORER_CMD__GET_SELF_LEN	2
#define RESTORER_CMD__PR_ARG_STRING	3
#define RESTORER_CMD__RESTORE_CORE	4

struct restore_core_args {
	void	*self_entry;		/* restorer placed at */
	long	self_size;		/* size for restorer granted */
	char	core_path[64];		/* path to a core file */
	char	self_vmas_path[64];	/* path to a self-vmas file */
};

struct rt_sigframe {
	char			*pretcode;
	struct ucontext		uc;
	struct siginfo		info;

	/* fp state follows here */
};

#endif /* CR_RESTORER_H__ */
