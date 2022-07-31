#ifndef __CR_SYSCALL_H__
#define __CR_SYSCALL_H__

static inline int sys_fsopen(const char *fsname, unsigned int flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}
static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key, const char *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
static inline int sys_fsmount(int fd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fd, flags, attr_flags);
}

#endif /* __CR_SYSCALL_H__ */