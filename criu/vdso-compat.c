#include <sys/syscall.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "parasite-syscall.h"
#include "parasite.h"
#include "vdso.h"

static void exit_on(int ret, int err_fd, char *reason)
{
	if (ret) {
		syscall(__NR_write, err_fd, reason, strlen(reason));
		syscall(__NR_exit, ret);
	}
}
/*
 * Because of restrictions of ARCH_MAP_VDSO_* API, new vDSO blob
 * can be mapped only if there is no vDSO blob present for a process.
 * This is a helper process, it unmaps 64-bit vDSO and maps 32-bit vDSO.
 * Then it copies vDSO blob to shared with CRIU mapping.
 *
 * The purpose is to fill compat vdso's symtable (vdso_compat_rt).
 * It's an optimization to fill symtable only once at CRIU restore
 * for all restored tasks.
 *
 * @native		- 64-bit vDSO blob (for easy unmap)
 * @pipe_fd		- to get size of compat blob from /proc/.../maps
 * @err_fd		- to print error messages
 * @vdso_buf, buf_size	- shared with CRIU buffer
 *
 * WARN: This helper shouldn't call pr_err() or any syscall with
 *	 Glibc's wrapper function - it may very likely blow up.
 */
void compat_vdso_helper(struct vdso_symtable *native, int pipe_fd,
		int err_fd, void *vdso_buf, size_t buf_size)
{
	size_t vma_size;
	void *vdso_addr;
	long vdso_size;
	long ret;

	if (native->vma_start != VDSO_BAD_ADDR) {
		vma_size = native->vma_end - native->vma_start;
		ret = syscall(__NR_munmap, native->vma_start, vma_size);
		exit_on(ret, err_fd, "Error: Failed to unmap native vdso\n");
	}

	if (native->vvar_start != VVAR_BAD_ADDR) {
		vma_size = native->vvar_end - native->vvar_start;
		ret = syscall(__NR_munmap, native->vvar_start, vma_size);
		exit_on(ret, err_fd, "Error: Failed to unmap native vvar\n");
	}

	ret = syscall(__NR_arch_prctl, ARCH_MAP_VDSO_32, native->vma_start);
	if (ret < 0)
		exit_on(ret, err_fd, "Error: ARCH_MAP_VDSO failed\n");

	vdso_size = ret;
	if (vdso_size > buf_size)
		exit_on(-1, err_fd, "Error: Compatible vdso's size is bigger than reserved buf\n");

	/* Stop so CRIU could parse smaps to find 32-bit vdso's size */
	ret = syscall(__NR_kill, syscall(__NR_getpid), SIGSTOP);
	exit_on(ret, err_fd, "Error: Can't stop myself with SIGSTOP (having a good time)\n");

	ret = syscall(__NR_read, pipe_fd, &vdso_addr, sizeof(void *));
	if (ret != sizeof(void *))
		exit_on(-1, err_fd, "Error: Can't read size of mmaped vdso from pipe\n");

	memcpy(vdso_buf, vdso_addr, vdso_size);

	syscall(__NR_exit, 0);
}
