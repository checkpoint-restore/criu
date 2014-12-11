#ifndef __CR_ERRNO_H__
#define __CR_ERRNO_H__

void set_cr_errno(int err);
int get_cr_errno(void);

/*
 * List of symbolic error names:
 * ESRCH	- no process can be found corresponding to that specified by pid
 * EEXIST	- process with such pid already exists
 * EBADRQC	- bad options
 */

#endif /* __CR_ERRNO_H__ */
