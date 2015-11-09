#ifndef __CR_BITMAP_H__
#define __CR_BITMAP_H__

extern void bitmap_set(unsigned long *map, int start, int nr);
extern void bitmap_clear(unsigned long *map, int start, int nr);

#endif /* __CR_BITMAP_H__ */
