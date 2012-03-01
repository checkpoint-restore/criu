#ifndef RESTORER_LOG_H__
#define RESTORER_LOG_H__
extern long vprint_num(char *buf, long num);

extern void write_hex_n(unsigned long num);
extern void write_num_n(long num);
extern void write_num(long num);
extern void write_string_n(char *str);
extern void write_string(char *str);
extern void restorer_set_logfd(int fd);
#endif
