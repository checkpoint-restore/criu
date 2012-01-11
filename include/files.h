#ifndef FILES_H_
#define FILES_H_

extern int prepare_fds(int pid);
extern int prepare_fd_pid(int pid);
extern int prepare_fdinfo_global(void);
extern int try_fixup_file_map(int pid, struct vma_entry *vma_entry, int fd);

#endif /* FILES_H_ */
