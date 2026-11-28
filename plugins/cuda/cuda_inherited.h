#ifndef CUDA_INHERITED_H
#define CUDA_INHERITED_H

#include <stdbool.h>
#include <stdint.h>

#define CUDA_INHERITED_FILES_IMAGE "cuda-inherited-files.img"

struct stat;

/*
 * A worker forked after CUDA started can still access NVIDIA files and
 * mappings even though it has no CUDA restore thread of its own. Discarding
 * these resources requires the application's explicit opt-in.
 */

/*
 * Inspect live descendants of paused CUDA tasks in the frozen process tree,
 * before any CUDA task is checkpointed and releases its mappings and files.
 */
int cuda_inherited_scan(bool (*is_cuda_task)(int pid), bool discard);

/* Whether the scan matched this range and device file to a CUDA ancestor. */
bool cuda_inherited_omit_vma(int pid, uint64_t start, uint64_t end, const struct stat *st);

/* Record the external file id if fd is an inherited NVIDIA descriptor; -ENOTSUP if not. */
int cuda_inherited_dump_file(int fd, int id);

/* Write the complete set of external file ids after all tasks have been dumped. */
int cuda_inherited_dump_files(void);

/* Load the ids before CRIU forks the tasks that will reopen the descriptors. */
int cuda_inherited_restore_init(void);

/* Open /dev/null for an inherited descriptor's id; -ENOTSUP for any other id. */
int cuda_inherited_restore_file(int id);

void cuda_inherited_fini(void);

#endif /* CUDA_INHERITED_H */
