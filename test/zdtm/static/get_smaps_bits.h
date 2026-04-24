#ifndef ZDTM_GET_SMAPS_BITS_H_
#define ZDTM_GET_SMAPS_BITS_H_

extern int get_smaps_bits(unsigned long where, unsigned long *flags, unsigned long *madv);
extern int is_vma_range_fmt(char *line, unsigned long *start, unsigned long *end);

#endif /* ZDTM_GET_SMAPS_BITS_H_ */
