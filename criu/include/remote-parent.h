#ifndef __CR_REMOTE_PARENT_H__
#define __CR_REMOTE_PARENT_H__

#include <stdbool.h>
#include <sys/uio.h>

#include "types.h"

struct remote_parent_writer;
struct remote_parent_coverage;

int remote_parent_writer_open(int fd_type, unsigned long img_id, struct remote_parent_writer **writer);
int remote_parent_writer_record(struct remote_parent_writer *writer, const struct iovec *iov, u32 flags);
void remote_parent_writer_close(struct remote_parent_writer *writer);
int remote_parent_finish(bool commit);

int remote_parent_coverage_open(int dirfd, int fd_type, unsigned long img_id,
				struct remote_parent_coverage **coverage);
int remote_parent_coverage_exists(int dirfd, int fd_type, unsigned long img_id);
bool remote_parent_coverage_contains(const struct remote_parent_coverage *coverage,
				     unsigned long vaddr, unsigned long len);
void remote_parent_coverage_close(struct remote_parent_coverage *coverage);

#endif /* __CR_REMOTE_PARENT_H__ */
