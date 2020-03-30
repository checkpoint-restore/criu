#ifndef __CR_ASM_GENERIC_FCNTL_H__
#define __CR_ASM_GENERIC_FCNTL_H__

#include <sys/types.h>
#include <fcntl.h>

#ifndef F_SETOWN_EX
#define F_SETOWN_EX	15
#define F_GETOWN_EX	16

struct f_owner_ex {
	int	type;
	pid_t	pid;
};

#endif

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS	17
#endif

/*
 * These things are required to compile on CentOS-6
 */
#ifndef F_LINUX_SPECIFIC_BASE
# define F_LINUX_SPECIFIC_BASE	1024
#endif

#ifndef F_SETPIPE_SZ
# define F_SETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
# define F_GETPIPE_SZ	(F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_ADD_SEALS
# define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#endif

#ifndef F_GET_SEALS
# define F_GET_SEALS (F_LINUX_SPECIFIC_BASE + 10)
#endif

#ifndef O_PATH
# define O_PATH		010000000
#endif

#ifndef __O_TMPFILE
#define __O_TMPFILE     020000000
#endif

#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#endif /* __CR_ASM_GENERIC_FCNTL_H__ */
