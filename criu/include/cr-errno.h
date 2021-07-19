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

#define set_task_cr_err(new_err) atomic_cmpxchg(&task_entries->cr_err, 0, new_err)
#define get_task_cr_err()	 atomic_read(&task_entries->cr_err)

#endif /* __CR_ERRNO_H__ */
