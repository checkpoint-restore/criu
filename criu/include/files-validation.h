#ifndef __CR_FILES_VALIDATION_H__
#define __CR_FILES_VALIDATION_H__

#include "files.h"

#include "images/regfile.pb-c.h"

struct fd_parms;

extern int store_validation_data_build_id(RegFileEntry *rfe, int lfd,
						const struct fd_parms *p);
extern int store_validation_data_checksum(RegFileEntry *rfe, int lfd,
						const struct fd_parms *p);

extern int validate_with_build_id(const int fd, const struct stat *fd_status,
					const struct reg_file_info *rfi);
extern int validate_with_checksum(const int fd, const struct stat *fd_status,
					const struct reg_file_info *rfi);

#endif /* __CR_FILES_VALIDATION_H__ */