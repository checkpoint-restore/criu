#ifndef __COMPEL_UAPI_TASK_STATE_H__
#define __COMPEL_UAPI_TASK_STATE_H__

/*
 * Task state, as returned by compel_wait_task()
 * and used in arguments to compel_resume_task().
 */
enum __compel_task_state
{
	COMPEL_TASK_ALIVE	= 0x01,
	COMPEL_TASK_DEAD	= 0x02,
	COMPEL_TASK_STOPPED	= 0x03,
	COMPEL_TASK_ZOMBIE	= 0x06,
	/* Don't ever change the above values, they are used by CRIU! */

	COMPEL_TASK_MAX		= 0x7f
};

#endif /* __COMPEL_UAPI_TASK_STATE_H__ */
