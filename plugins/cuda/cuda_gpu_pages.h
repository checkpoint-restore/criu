/*
 * cuda_gpu_pages.h - fast dump/restore of cuda-checkpoint staging pages
 *
 * After the CUDA checkpoint (cuda-checkpoint --action checkpoint or
 * cuCheckpointProcessCheckpoint()), the driver moves the GPU memory into new
 * anonymous private mappings ("staging VMAs") in the target process. Left
 * alone, those pages go through CRIU's generic page dump and restore, which
 * moves them at a fraction of the storage bandwidth and keeps a VRAM-sized
 * copy in the page images. Instead:
 *
 *   Dump: scan /proc/<pid>/maps before and after the checkpoint, diff to
 *         find the new staging VMAs, copy them out with process_vm_readv()
 *         into gpu-pages-<pid>.img (O_DIRECT, buffered fallback), then free
 *         them in the target with an injected madvise(MADV_DONTNEED) so the
 *         regular page dump sees empty pages. The VMAs stay in the address
 *         space and CRIU restores them as ordinary empty mappings.
 *
 *   Restore: inject madvise(MADV_HUGEPAGE) for each staging VMA, then fill
 *            them with N worker threads that read the image (O_DIRECT) into
 *            bounce buffers and write into the target with
 *            process_vm_writev(), so the page faults happen in parallel
 *            across cores. The backend's CUDA restore then moves the pages
 *            back into VRAM.
 *
 */

#ifndef CUDA_GPU_PAGES_H
#define CUDA_GPU_PAGES_H

#include <stdint.h>

#define GPU_PAGES_MAGIC	  0x47505544u /* "GPUD" */
#define GPU_IO_CHUNK_SIZE (64 * 1024 * 1024)
/* Page data starts at this offset in the image file (page-aligned for O_DIRECT) */
#define GPU_PAGES_DATA_OFFSET 4096

struct gpu_region {
	uint64_t start;
	uint64_t size;
};

struct gpu_pages_hdr {
	uint32_t magic;
	uint32_t num_regions;
};

double now_ms(void);

int scan_anon_private_vmas(int pid, struct gpu_region **out, int *count);

int diff_anon_vmas(struct gpu_region *before, int n_before,
		   struct gpu_region *after, int n_after,
		   struct gpu_region **diff_out, int *diff_count);

int dump_gpu_pages(int pid, int img_dir_fd, struct gpu_region *regions, int count);

uint64_t find_syscall_addr(int pid);

long inject_syscall(int tid, uint64_t syscall_addr,
		    long nr, long a1, long a2, long a3,
		    long a4, long a5, long a6);

int inject_madvise_dontneed(int tid, uint64_t addr, uint64_t len, uint64_t syscall_addr);

int release_gpu_pages(int tid, uint64_t syscall_addr, struct gpu_region *regions, int count);

int restore_gpu_pages(int pid, int tid, uint64_t syscall_addr, int img_dir_fd);

#endif /* CUDA_GPU_PAGES_H */
