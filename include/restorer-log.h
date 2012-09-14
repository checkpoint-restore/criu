#ifndef RESTORER_LOG_H__
#define RESTORER_LOG_H__

#include "log-levels.h"

extern long vprint_num(char *buf, long num);

extern void write_hex_n_on_level(unsigned int loglevel, unsigned long num);
extern void write_num_n_on_level(unsigned int loglevel, long num);
extern void write_num_on_level(unsigned int loglevel, long num);
extern void write_str_n_on_level(unsigned int loglevel, char *str);

extern void restorer_set_logfd(int fd);
extern void restorer_set_loglevel(unsigned int loglevel);

#define write_str_err(str)	print_on_level(LOG_ERROR, str)
#define write_str_n_err(str)	write_str_n_on_level(LOG_ERROR, str)

#define	write_num_err(num)	write_num_on_level(LOG_ERROR, num)
#define write_num_n_err(num)	write_num_n_on_level(LOG_ERROR, num)

#define write_str_info(str)	print_on_level(LOG_INFO, str)
#define write_str_n_info(str)	write_str_n_on_level(LOG_INFO, str)

#define write_num_info(num)	write_num_on_level(LOG_INFO, num)
#define write_num_n_info(num)	write_num_n_on_level(LOG_INFO, num)

#define write_hex_n_err(num)	write_hex_n_on_level(LOG_ERROR, num)

#endif /* RESTORER_LOG_H__ */
