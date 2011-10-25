#ifndef CR_RESTORER_H__
#define CR_RESTORER_H__

#include <signal.h>

#include "image.h"

#define RESTORER_ARGS_SIZE	512
#define RESTORER_SIZE		8192

long restorer(long cmd);

typedef long (*restorer_fcall_t) (long cmd);

enum {
	RESTORER_CMD__NONE,
	RESTORER_CMD__GET_ARG_OFFSET,
	RESTORER_CMD__PR_ARG_STRING,
	RESTORER_CMD__RESTORE_CORE,
	RESTORER_CMD__MAX,
};

struct restore_core_args {
	void	*self_entry;	/* restorer placed at */
	long	self_size;	/* size for restorer granted */
	char	core_path[0];	/* path to a core file */
};

struct rt_sigframe {
	char			*pretcode;
	struct ucontext		uc;
	struct siginfo		info;

	/* fp state follows here */
};

#endif /* CR_RESTORER_H__ */
