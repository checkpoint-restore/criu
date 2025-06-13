#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <semaphore.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>

#include "imgset.h"
#include "image.h"
#include "files.h"
#include "file-ids.h"
#include "mount.h"
#include "fs-magic.h"
#include "namespaces.h"

#include "protobuf.h"
#include "util.h"
#include "images/posix-sem.pb-c.h"
#include "images/fdinfo.pb-c.h"

/* glibc constants */
#ifndef SEM_VALUE_MAX
#define SEM_VALUE_MAX (2147483647)
#endif

/* >=2.2 glibc semaphore structure constants */
#define SEM_VALUE_SHIFT 1
#define SEM_VALUE_MASK (~(unsigned int)0)

struct posix_sem_info {
	struct file_desc d;
	PosixSemEntry *pse;
};

static LIST_HEAD(posix_sem_list);

static bool is_posix_semaphore_file(const char *path, const struct fd_parms *parms)
{
	if (parms->fs_type != TMPFS_MAGIC)
		return false;
		
	/* POSIX semaphores are stored as /dev/shm/sem.name */
	if (strncmp(path, "dev/shm/sem.", 12) == 0) {
		return true;
	}
	
	return false;
}

/*
 * check for deleted POSIX semaphore file
 */
static bool is_deleted_posix_semaphore_file(const char *path, const struct fd_parms *parms)
{
	if (parms->fs_type != TMPFS_MAGIC)
		return false;
		
	/* look for pattern like "dev/shm/sem.<id> (deleted)" */
	if (strncmp(path, "dev/shm/sem.", 12) == 0) {
		if (strstr(path, " (deleted)") || strstr(path, "/sem.")) {
			return true;
		}
	}
	
	return false;
}

static char *extract_sem_name(const char *path)
{
	const char *sem_prefix = "sem.";
	char *sem_start, *sem_end;
	char *name;
	int name_len;
	
	sem_start = strstr(path, sem_prefix);
	if (!sem_start) {
		pr_err("Invalid semaphore path format: %s\n", path);
		return NULL;
	}
	
	sem_start += strlen(sem_prefix);
	
	sem_end = strchr(sem_start, ' ');
	if (!sem_end) {
		sem_end = strchr(sem_start, '\0');
	}
	
	if (sem_end <= sem_start) {
		pr_err("Empty semaphore name in path: %s\n", path);
		return NULL;
	}
	
	name_len = sem_end - sem_start;
	name = xmalloc(name_len + 1);
	if (!name)
		return NULL;
		
	strncpy(name, sem_start, name_len);
	name[name_len] = '\0';
	
	pr_debug("Extracted semaphore name: '%s' from path: '%s'\n", name, path);
	return name;
}

/*
 * Get the current value of a POSIX semaphore
 * For existing semaphores, use the POSIX API
 * For deleted semaphores, try to read the value directly from the file
 */
static int get_semaphore_value_from_fd(int fd, const char *sem_name, bool is_deleted)
{
	int value = 0;
	sem_t *sem;
	ssize_t bytes_read;
	struct stat st;
	
	if (!is_deleted && sem_name) {
		/* For existing semaphores, use the POSIX API */
		sem = sem_open(sem_name, 0);
		if (sem == SEM_FAILED) {
			pr_debug("Can't open semaphore %s to get value: %s\n", sem_name, strerror(errno));
		} else {
			if (sem_getvalue(sem, &value) < 0) {
				pr_perror("Can't get value of semaphore %s", sem_name);
                /* Default to 0 or error out? */
				value = 0;
			} else {
				pr_info("Got semaphore value %d from semaphore %s\n", value, sem_name);
			}
			
			if (sem_close(sem) < 0) {
				pr_perror("Can't close semaphore %s", sem_name);
			}
			
			pr_info("Determined semaphore value: %d for fd %d (name: %s)\n", value, fd, sem_name);
			return value;
		}
	}
	
	/* For deleted semaphores or if sem_open failed, try to read directly */
	pr_debug("Attempting to read semaphore value directly from fd %d\n", fd);
	
	if (lseek(fd, 0, SEEK_SET) < 0) {
		pr_perror("Can't seek to beginning of semaphore file");
		return 0;
	}
	
	/* Get file size to determine semaphore format */
	if (fstat(fd, &st) < 0) {
		pr_perror("Cannot stat semaphore file for fd %d", fd);
		return 0;
	}
	
	pr_debug("Semaphore file size: %ld bytes\n", st.st_size);
	
	/* Modern glibc format typical size 16+ bytes */
	if (st.st_size >= 16) {
		uint64_t data64;
		unsigned int uvalue;
		
		/* Try 64-bit atomic format */
		if (lseek(fd, 0, SEEK_SET) >= 0) {
			bytes_read = read(fd, &data64, sizeof(uint64_t));
			if (bytes_read == sizeof(uint64_t)) {
				/* Extract value from lower 32 bits */
				value = (int)(data64 & SEM_VALUE_MASK);
				if (value >= 0 && value <= SEM_VALUE_MAX) {
					pr_info("Read semaphore value %d from 64-bit data field (fd %d)\n", value, fd);
					return value;
				}
				pr_debug("64-bit value %d out of range, trying other formats\n", value);
			}
		}
		
		/* 32-bit systems or older glibc <2.2 */
		if (lseek(fd, 0, SEEK_SET) >= 0) {
			bytes_read = read(fd, &uvalue, sizeof(unsigned int));
			if (bytes_read == sizeof(unsigned int)) {
				int shifted_value = (int)(uvalue >> SEM_VALUE_SHIFT);
				if (shifted_value >= 0 && shifted_value <= SEM_VALUE_MAX) {
					pr_info("Read semaphore value %d from shifted field (fd %d)\n", shifted_value, fd);
					return shifted_value;
				}
				
				if (uvalue <= SEM_VALUE_MAX) {
					pr_info("Read semaphore value %d from unshifted field (fd %d)\n", (int)uvalue, fd);
					return (int)uvalue;
				}
				pr_debug("32-bit values out of range: shifted=%d, unshifted=%u\n", shifted_value, uvalue);
			}
		}
	}
	
	/* Legacy glibc <2.2 format just unsigned int */
	if (st.st_size >= sizeof(unsigned int)) {
		unsigned int legacy_value;
		
		if (lseek(fd, 0, SEEK_SET) >= 0) {
			bytes_read = read(fd, &legacy_value, sizeof(unsigned int));
			if (bytes_read == sizeof(unsigned int) && legacy_value <= SEM_VALUE_MAX) {
				pr_info("Read semaphore value %d from legacy format (fd %d)\n", (int)legacy_value, fd);
				return (int)legacy_value;
			}
			pr_debug("Legacy value %u out of range\n", legacy_value);
		}
	}
	
    /* Fall back for different data types */
	if (st.st_size >= sizeof(long)) {
		long lvalue;
		
		if (lseek(fd, 0, SEEK_SET) >= 0) {
			bytes_read = read(fd, &lvalue, sizeof(long));
			if (bytes_read == sizeof(long) && lvalue >= 0 && lvalue <= SEM_VALUE_MAX) {
				pr_info("Read semaphore value %d as long (fd %d)\n", (int)lvalue, fd);
				return (int)lvalue;
			}
			pr_debug("Long value %ld out of range\n", lvalue);
		}
	}
	
	/* Try reading just the first int as final attempt */
	if (st.st_size >= sizeof(int)) {
		int int_value;
		
		if (lseek(fd, 0, SEEK_SET) >= 0) {
			bytes_read = read(fd, &int_value, sizeof(int));
			if (bytes_read == sizeof(int) && int_value >= 0 && int_value <= SEM_VALUE_MAX) {
				pr_info("Read semaphore value %d as int (fd %d)\n", int_value, fd);
				return int_value;
			}
			pr_debug("Int value %d out of range\n", int_value);
		}
	}
	
    /* Everything failed, again default to 0 or error out? */
	pr_warn("Could not determine semaphore value from fd %d (file size: %ld), defaulting to 0\n", 
		fd, st.st_size);
	return 0;
} 

/*
 * Dump one POSIX semaphore
 */
static int dump_one_posix_sem(int lfd, u32 id, const struct fd_parms *p)
{
	struct fd_link _link, *link;
	struct cr_img *img;
	char *sem_name;
	int sem_value;
	PosixSemEntry pse = POSIX_SEM_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	bool is_deleted = false;
	
	pr_info("Dumping POSIX semaphore fd %d with id %#x\n", lfd, id);
	
	if (!p->link) {
		if (fill_fdlink(lfd, p, &_link))
			return -1;
		link = &_link;
	} else {
		link = p->link;
	}
	
	/* Check if this is a deleted semaphore */
	is_deleted = strstr(link->name, " (deleted)") != NULL;
	
	/* Extract semaphore name from path */
	sem_name = extract_sem_name(link->name + 1);
	if (!sem_name) {
		pr_err("Invalid POSIX semaphore path: %s\n", link->name + 1);
		return -1;
	}
	
	/* Get current semaphore value from the file descriptor */
	sem_value = get_semaphore_value_from_fd(lfd, is_deleted ? NULL : sem_name, is_deleted);
	if (sem_value < 0) {
		pr_warn("Can't get semaphore value for %s, defaulting to 0\n", sem_name);
		sem_value = 0;
	}
	
	/* Semaphore entry */
	pse.name = sem_name;
	pse.value = sem_value;
	pse.mode = p->stat.st_mode;
	pse.uid = p->stat.st_uid;
	pse.gid = p->stat.st_gid;
	pse.dev = p->stat.st_dev;
	pse.ino = p->stat.st_ino;
	pse.fd_id = id;
	
	/* File entry */
	fe.type = FD_TYPES__POSIX_SEM;
	fe.id = id;
	fe.psm = &pse;
	
	img = img_from_set(glob_imgset, CR_FD_FILES);
	if (pb_write_one(img, &fe, PB_FILE) < 0) {
		pr_err("Failed to write POSIX semaphore entry\n");
		xfree(sem_name);
		return -1;
	}
	
	pr_info("Successfully dumped POSIX semaphore %s (value=%d, deleted=%s)\n", 
			sem_name, sem_value, is_deleted ? "yes" : "no");
	
	xfree(sem_name);
	return 0;
}

const struct fdtype_ops posix_sem_dump_ops = {
	.type = FD_TYPES__POSIX_SEM,
	.dump = dump_one_posix_sem,
};

/*
 * Open/restore a POSIX semaphore for migration
 * This recreates the semaphore with the correct value and returns a fd
 */
static int posix_sem_open(struct file_desc *d, int *new_fd)
{
	struct posix_sem_info *psi = container_of(d, struct posix_sem_info, d);
	PosixSemEntry *pse = psi->pse;
	sem_t *sem;
	int fd = -1;
	unsigned int value;
	char sem_path[PATH_MAX];
	struct stat st;
	int retry_count = 0;
	const int max_retries = 3;
	
	pr_info("Restoring POSIX semaphore %s (value=%u) for cross-host migration\n", 
			pse->name, pse->value);
	
	/* Unlink any existing semaphore with the same name */
	sem_unlink(pse->name);
	
	/* Create new semaphore with the stored value */
	value = pse->value;
	
retry_create:
	sem = sem_open(pse->name, O_CREAT | O_EXCL, pse->mode, value);
	if (sem == SEM_FAILED) {
		if (errno == EEXIST && retry_count < max_retries) {
			/* Another process might have created it, try to unlink and retry */

            /*
             * This is dangerous for same node c/r but the usage of this feature
             * is under the assumption that it's a migration. There are other options here:
             * 1. Checking for active processes using the semaphore
             * 2. Verify the state of the semaphore that it could have been from a same node c/r
             *    left over.
             * 3. Use a temp name and rename it after creation. This only works when coordinating
             *    with the other process.
             */

			pr_debug("Semaphore %s exists, unlinking and retrying\n", pse->name);
			sem_unlink(pse->name);
			retry_count++;
            /* Delay for timing issues with cleanup from sem_unlink */
			usleep(1000 * retry_count);
			goto retry_create;
		}
		pr_perror("Can't create POSIX semaphore %s after %d retries", pse->name, retry_count);
		return -1;
	}
	
	pr_info("Successfully created POSIX semaphore %s with initial value %u\n", 
			pse->name, value);
	
	/* 
	 * Get the file descriptor associated with the semaphore.
	 */
	snprintf(sem_path, sizeof(sem_path), "/dev/shm/sem.%s", pse->name);
	
	fd = open(sem_path, O_RDWR);
	if (fd < 0) {
		pr_perror("Can't open semaphore file %s", sem_path);
		goto cleanup_sem;
	}
	
	if (fstat(fd, &st) == 0) {
		pr_debug("Semaphore file %s: mode=0%o, uid=%u, gid=%u\n", 
				 sem_path, st.st_mode, st.st_uid, st.st_gid);
		
        /* I'm not sure how criu should handle this for migration */
		if (getuid() == 0 || geteuid() == 0) {
			if (fchown(fd, pse->uid, pse->gid) < 0) {
				pr_debug("Can't restore ownership of semaphore file %s\n", sem_path);
			}
			if (fchmod(fd, pse->mode) < 0) {
				pr_debug("Can't restore mode of semaphore file %s\n", sem_path);
			}
		}
	}
	
	sem_close(sem);
	
	*new_fd = fd;
	
	pr_info("Successfully restored POSIX semaphore %s with fd %d (cross-host migration)\n", 
			pse->name, fd);
	return 0;

cleanup_sem:
	sem_close(sem);
	sem_unlink(pse->name);
	return -1;
}

static char *posix_sem_name(struct file_desc *d, char *buf, size_t s)
{
	struct posix_sem_info *psi = container_of(d, struct posix_sem_info, d);
	snprintf(buf, s, "POSIX semaphore %s", psi->pse->name);
	return buf;
}

static struct file_desc_ops posix_sem_desc_ops = {
	.type = FD_TYPES__POSIX_SEM,
	.open = posix_sem_open,
	.name = posix_sem_name,
};

/*
 * Collect one POSIX semaphore entry
 */
static int collect_one_posix_sem(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct posix_sem_info *psi = obj;
	
	psi->pse = pb_msg(msg, PosixSemEntry);
	
	pr_info("Collected POSIX semaphore %s (value=%u, id=%#x)\n", 
			psi->pse->name, psi->pse->value, psi->pse->fd_id);
	
	list_add_tail(&psi->d.fd_info_head, &posix_sem_list);
	
	return file_desc_add(&psi->d, psi->pse->fd_id, &posix_sem_desc_ops);
}

struct collect_image_info posix_sem_cinfo = {
	.fd_type = CR_FD_POSIX_SEM,
	.pb_type = PB_POSIX_SEM,
	.priv_size = sizeof(struct posix_sem_info),
	.collect = collect_one_posix_sem,
	.flags = COLLECT_SHARED,
};

/*
 * Check if we should handle this file as a POSIX semaphore
 * This includes both existing and deleted semaphores
 */
bool should_dump_posix_semaphore(const char *path, const struct fd_parms *parms)
{
	return is_posix_semaphore_file(path, parms) || 
	       is_deleted_posix_semaphore_file(path, parms);
}

/*
 * Try to dump as POSIX semaphore if applicable
 * Returns:
 *   1 - Successfully handled as POSIX semaphore
 *   0 - Not a POSIX semaphore, continue with normal processing  
 *  -1 - Error during POSIX semaphore processing
 */
int try_dump_posix_semaphore(const char *path, int lfd, u32 id, const struct fd_parms *parms)
{
	int ret;
	
	if (!should_dump_posix_semaphore(path, parms))
		return 0;
		
	pr_info("Detected POSIX semaphore file: %s\n", path);
	ret = dump_one_posix_sem(lfd, id, parms);
	if (ret == 0) {
		return 1;
	} else {
		return -1;
	}
}

/*
 * Open POSIX semaphore for VMA mapping during restore
 * This function is called during VMA preparation to assign the correct
 * file descriptor to POSIX semaphore VMAs
 */
int open_posix_sem_vma(int pid, struct vma_area *vma)
{
	struct file_desc *fd_desc;
	struct posix_sem_info *psi;
	int sem_fd;
	
	pr_info("Opening POSIX semaphore VMA %" PRIx64 "-%" PRIx64 " (shmid=%" PRIx64 ")\n", 
			vma->e->start, vma->e->end, vma->e->shmid);
	
	/* Find the POSIX semaphore file descriptor by shmid */
	list_for_each_entry(psi, &posix_sem_list, d.fd_info_head) {
		if (psi->pse->ino == vma->e->shmid) {
			pr_info("Found matching POSIX semaphore %s for VMA (ino=%" PRIx64 ")\n", 
					psi->pse->name, vma->e->shmid);
			
			fd_desc = &psi->d;
			if (!inherited_fd(fd_desc, &sem_fd)) {
				if (posix_sem_open(fd_desc, &sem_fd) < 0) {
					pr_err("Failed to open POSIX semaphore %s\n", psi->pse->name);
					return -1;
				}
			}
			
			pr_info("Assigned fd %d to POSIX semaphore VMA %" PRIx64 "-%" PRIx64 "\n", 
					sem_fd, vma->e->start, vma->e->end);
			
			vma->e->fd = sem_fd;
			vma->e->status |= VMA_CLOSE;
			return 0;
		}
	}
	
	pr_err("No POSIX semaphore found for VMA %" PRIx64 "-%" PRIx64 " (shmid=%" PRIx64 ")\n", 
		   vma->e->start, vma->e->end, vma->e->shmid);
	return -1;
}
