#ifndef __CR_RST_MALLOC__H__
#define __CR_RST_MALLOC__H__

/*
 * On restore we need differetn types of memory allocation.
 * Here's an engine that tries to generalize them all. The
 * main difference is in how the buffer with objects is being
 * grown up.
 *
 * Buffers, that are to be used by restorer will be remapped
 * into restorer address space with rst_mem_remap() call. Thus
 * we have to either keep track of all the buffers and objects,
 * or keep objects one-by-one in a plain linear buffer. The
 * engine uses the 2nd approach.
 */

enum {
	/*
	 * Shared non-remapable allocations. These can happen only
	 * in "global" context, i.e. when objects are allocated to
	 * be used by any process to be restored. The objects are
	 * not going to be used in restorer blob, thus allocation
	 * engine grows buffers in a simple manner.
	 */
	RM_SHARED,
	/*
	 * Shared objects, that are about to be used in restorer
	 * blob. For these the *_remap_* stuff below is used to get
	 * the actual pointer on any object. Growing a buffer is
	 * done with mremap, so that we don't have to keep track
	 * of all the buffer chunks and can remap them in restorer
	 * in one call.
	 */
	RM_SHREMAP,
	/*
	 * Privately used objects. Buffer grow and remap is the
	 * same as for SHREMAP, but memory regions are MAP_PRIVATE.
	 */
	RM_PRIVATE,

	RST_MEM_TYPES,
};

/*
 * Disables SHARED and SHREMAP allocations, turns on PRIVATE
 */
extern void rst_mem_switch_to_private(void);
/* 
 * Reports a cookie of a current shared buffer position, that
 * can later be used in rst_mem_cpos() to find out the object
 * pointer.
 */
extern unsigned long rst_mem_cpos(int type);
extern void *rst_mem_remap_ptr(unsigned long pos, int type);
/*
 * Allocate and free objects. We don't need to free arbitrary
 * object, thus allocation is simple (linear) and only the
 * last object can be freed (pop-ed from buffer).
 */
extern void *rst_mem_alloc(unsigned long size, int type);
extern void rst_mem_free_last(int type);
/*
 * Routines to remap SHREMAP and PRIVATE into restorer address space
 */
extern unsigned long rst_mem_remap_size(void);
extern int rst_mem_remap(void *to);

#endif /* __CR_RST_MALLOC__H__ */
