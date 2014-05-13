#ifndef __CR_PRCTL_H__
#define __CR_PRCTL_H__

#ifndef PR_SET_NAME
# define PR_SET_NAME		15
#endif
#ifndef PR_GET_NAME
# define PR_GET_NAME		16
#endif
#ifndef PR_CAPBSET_DROP
# define PR_CAPBSET_DROP	24
#endif
#ifndef PR_GET_SECUREBITS
# define PR_GET_SECUREBITS	27
#endif
#ifndef PR_SET_SECUREBITS
# define PR_SET_SECUREBITS	28
#endif
#ifndef PR_GET_DUMPABLE
# define PR_GET_DUMPABLE	3
#endif
#ifndef PR_SET_DUMPABLE
# define PR_SET_DUMPABLE	4
#endif

#ifndef PR_SET_MM
#define PR_SET_MM		35
# define PR_SET_MM_START_CODE		1
# define PR_SET_MM_END_CODE		2
# define PR_SET_MM_START_DATA		3
# define PR_SET_MM_END_DATA		4
# define PR_SET_MM_START_STACK		5
# define PR_SET_MM_START_BRK		6
# define PR_SET_MM_BRK			7
# define PR_SET_MM_ARG_START		8
# define PR_SET_MM_ARG_END		9
# define PR_SET_MM_ENV_START		10
# define PR_SET_MM_ENV_END		11
# define PR_SET_MM_AUXV			12
# define PR_SET_MM_EXE_FILE		13
#endif

#ifndef PR_GET_TID_ADDRESS
# define PR_GET_TID_ADDRESS	40
#endif

#endif /* __CR_PRCTL_H__ */
