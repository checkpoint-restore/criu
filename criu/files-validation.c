#include <elf.h>

/*
 * If the build-id exists, then it will most likely be present in the
 * beginning of the file. Therefore only the first 1MB will be mapped
 * and checked.
 */
#define BUILD_ID_MAP_SIZE 1048576

/*
 * The file is read and processed in chunks and the required bytes in each
 * chunk contribute to the checksum.
 */
#define CHKSM_CHUNK_SIZE 10485760

#include "cr_options.h"
#include "imgset.h"
#include "util.h"
#include "files-reg.h"
#include "files-validation.h"

/*
 * Gets the build-id (If it exists) from 32-bit ELF files.
 * Returns the number of bytes of the build-id if it could
 * be obtained, else -1.
 */
static int get_build_id_32(Elf32_Ehdr *file_header, unsigned char **build_id,
				const int fd, size_t mapped_size)
{
	int size, num_iterations;
	size_t file_header_end;
	Elf32_Phdr *program_header, *program_header_end;
	Elf32_Nhdr *note_header_end, *note_header = NULL;

	file_header_end = (size_t) file_header + mapped_size;
	if (sizeof(Elf32_Ehdr) > mapped_size)
		return -1;

	/*
	 * If the file doesn't have atleast 1 program header entry, it definitely can't
	 * have a build-id.
	 */
	if (!file_header->e_phnum) {
		pr_warn("Couldn't find any program headers for file with fd %d\n", fd);
		return -1;
	}

	program_header = (Elf32_Phdr *) (file_header->e_phoff + (char *) file_header);
	if (program_header <= (Elf32_Phdr *) file_header)
		return -1;

	program_header_end = (Elf32_Phdr *) (file_header_end - sizeof(Elf32_Phdr));

	/*
	 * If the file has a build-id, it will be in the PT_NOTE program header
	 * entry AKA the note sections.
	 */
	for (num_iterations = 0; num_iterations < file_header->e_phnum; num_iterations++, program_header++) {
		if (program_header > program_header_end)
			break;
		if (program_header->p_type != PT_NOTE)
			continue;

		note_header = (Elf32_Nhdr *) (program_header->p_offset + (char *) file_header);
		if (note_header <= (Elf32_Nhdr *) file_header) {
			note_header = NULL;
			continue;
		}

		note_header_end = (Elf32_Nhdr *) min_t(char*,
						(char *) note_header + program_header->p_filesz,
						(char *) (file_header_end - sizeof(Elf32_Nhdr)));

		/* The note type for the build-id is NT_GNU_BUILD_ID. */
		while (note_header <= note_header_end && note_header->n_type != NT_GNU_BUILD_ID)
			note_header = (Elf32_Nhdr *) ((char *) note_header + sizeof(Elf32_Nhdr) +
							ALIGN(note_header->n_namesz, 4) +
							ALIGN(note_header->n_descsz, 4));

		if (note_header > note_header_end) {
			note_header = NULL;
			continue;
		}
		break;
	}

	if (!note_header) {
		pr_warn("Couldn't find the build-id note for file with fd %d\n", fd);
		return -1;
	}

	/*
	 * If the size of the notes description is too large or is invalid
	 * then the build-id could not be obtained.
	 */
	if (note_header->n_descsz <= 0 || note_header->n_descsz > 512) {
		pr_warn("Invalid description size for build-id note for file with fd %d\n", fd);
		return -1;
	}

	size = note_header->n_descsz;
	note_header = (Elf32_Nhdr *) ((char *) note_header + sizeof(Elf32_Nhdr) +
					ALIGN(note_header->n_namesz, 4));
	note_header_end = (Elf32_Nhdr *) (file_header_end - size);
	if (note_header <= (Elf32_Nhdr *) file_header || note_header > note_header_end)
		return -1;

	*build_id = (unsigned char *) xmalloc(size);
	if (!*build_id)
		return -1;

	memcpy(*build_id, (void *) note_header, size);
	return size;
}

/*
 * Gets the build-id (If it exists) from 64-bit ELF files.
 * Returns the number of bytes of the build-id if it could
 * be obtained, else -1.
 */
static int get_build_id_64(Elf64_Ehdr *file_header, unsigned char **build_id,
				const int fd, size_t mapped_size)
{
	int size, num_iterations;
	size_t file_header_end;
	Elf64_Phdr *program_header, *program_header_end;
	Elf64_Nhdr *note_header_end, *note_header = NULL;

	file_header_end = (size_t) file_header + mapped_size;
	if (sizeof(Elf64_Ehdr) > mapped_size)
		return -1;

	/*
	 * If the file doesn't have atleast 1 program header entry, it definitely can't
	 * have a build-id.
	 */
	if (!file_header->e_phnum) {
		pr_warn("Couldn't find any program headers for file with fd %d\n", fd);
		return -1;
	}

	program_header = (Elf64_Phdr *) (file_header->e_phoff + (char *) file_header);
	if (program_header <= (Elf64_Phdr *) file_header)
		return -1;

	program_header_end = (Elf64_Phdr *) (file_header_end - sizeof(Elf64_Phdr));

	/*
	 * If the file has a build-id, it will be in the PT_NOTE program header
	 * entry AKA the note sections.
	 */
	for (num_iterations = 0; num_iterations < file_header->e_phnum; num_iterations++, program_header++) {
		if (program_header > program_header_end)
			break;
		if (program_header->p_type != PT_NOTE)
			continue;

		note_header = (Elf64_Nhdr *) (program_header->p_offset + (char *) file_header);
		if (note_header <= (Elf64_Nhdr *) file_header) {
			note_header = NULL;
			continue;
		}

		note_header_end = (Elf64_Nhdr *) min_t(char*,
						(char *) note_header + program_header->p_filesz,
						(char *) (file_header_end - sizeof(Elf64_Nhdr)));

		/* The note type for the build-id is NT_GNU_BUILD_ID. */
		while (note_header <= note_header_end && note_header->n_type != NT_GNU_BUILD_ID)
			note_header = (Elf64_Nhdr *) ((char *) note_header + sizeof(Elf64_Nhdr) +
							ALIGN(note_header->n_namesz, 4) +
							ALIGN(note_header->n_descsz, 4));

		if (note_header > note_header_end) {
			note_header = NULL;
			continue;
		}
		break;
	}

	if (!note_header) {
		pr_warn("Couldn't find the build-id note for file with fd %d\n", fd);
		return -1;
	}

	/*
	 * If the size of the notes description is too large or is invalid
	 * then the build-id could not be obtained.
	 */
	if (note_header->n_descsz <= 0 || note_header->n_descsz > 512) {
		pr_warn("Invalid description size for build-id note for file with fd %d\n", fd);
		return -1;
	}

	size = note_header->n_descsz;
	note_header = (Elf64_Nhdr *) ((char *) note_header + sizeof(Elf64_Nhdr) +
					ALIGN(note_header->n_namesz, 4));
	note_header_end = (Elf64_Nhdr *) (file_header_end - size);
	if (note_header <= (Elf64_Nhdr *) file_header || note_header > note_header_end)
		return -1;

	*build_id = (unsigned char *) xmalloc(size);
	if (!*build_id)
		return -1;

	memcpy(*build_id, (void *) note_header, size);
	return size;
}

/*
 * Finds the build-id of the file by checking if the file is an ELF file
 * and then calling either the 32-bit or the 64-bit function as necessary.
 * Returns the number of bytes of the build-id if it could be
 * obtained, else -1.
 */
static int get_build_id(const int fd, const struct stat *fd_status,
				unsigned char **build_id)
{
	char buf[SELFMAG+1];
	void *start_addr;
	size_t mapped_size;
	int ret = -1;

	if (read(fd, buf, SELFMAG+1) != SELFMAG+1)
		return -1;

	/*
	 * The first 4 bytes contain a magic number identifying the file as an
	 * ELF file. They should contain the characters ‘\x7f’, ‘E’, ‘L’, and
	 * ‘F’, respectively. These characters are together defined as ELFMAG.
	 */
	if (strncmp(buf, ELFMAG, SELFMAG))
		return -1;

	/*
	 * If the build-id exists, then it will most likely be present in the
	 * beginning of the file. Therefore at most only the first 1 MB of the
	 * file is mapped.
	 */
	mapped_size = min_t(size_t, fd_status->st_size, BUILD_ID_MAP_SIZE);
	start_addr = mmap(0, mapped_size, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (start_addr == MAP_FAILED) {
		pr_warn("Couldn't mmap file with fd %d", fd);
		return -1;
	}

	if (buf[EI_CLASS] == ELFCLASS32)
		ret = get_build_id_32(start_addr, build_id, fd, mapped_size);
	if (buf[EI_CLASS] == ELFCLASS64)
		ret = get_build_id_64(start_addr, build_id, fd, mapped_size);
	
	munmap(start_addr, mapped_size);
	return ret;
}

static inline void checksum_iterator_init(u64 *iter)
{
	switch (opts.file_validation_chksm_config) {
	case FILE_VALIDATION_CHKSM_FULL:
		*iter = 0;
		break;
	case FILE_VALIDATION_CHKSM_FIRST:
		*iter = 0;
		break;
	case FILE_VALIDATION_CHKSM_PERIOD:
		*iter = 0;
		break;
	}
}

static inline void checksum_iterator_next(u64 *iter)
{
	switch (opts.file_validation_chksm_config) {
	case FILE_VALIDATION_CHKSM_FULL:
		*iter += 1;
		break;
	case FILE_VALIDATION_CHKSM_FIRST:
		*iter += 1;
		break;
	case FILE_VALIDATION_CHKSM_PERIOD:
		*iter += opts.file_validation_chksm_parameter;
		break;
	}
}

static inline bool checksum_iterator_stop(u64 iter)
{
	switch (opts.file_validation_chksm_config) {
	case FILE_VALIDATION_CHKSM_FULL:
		return false;
	case FILE_VALIDATION_CHKSM_FIRST:
		if (iter >= opts.file_validation_chksm_parameter)
			return true;
		else
			return false;
	case FILE_VALIDATION_CHKSM_PERIOD:
		return false;
	default:
		return true;
	}
}

/*
 * Does the actual work of calculating the CRC32C checksum of "some"
 * parts of the file. These "some" parts depend on the configuration chosen.
 * By default, the first 1024 bytes of the file or the entire file, which ever
 * is smaller, is considered.
 * Returns true if the checksum could be obtained, else it returns false.
 */
static bool calculate_checksum(const int fd, const struct stat *fd_status,
				u32 *checksum)
{
	int tmp;
	u32 byte, mask;
	u64 up_bound, low_bound = 0, offset = 0;
	unsigned char *buf;

	/* At most, the first 10MB of the file is mapped. */
	up_bound = min_t(size_t, fd_status->st_size, CHKSM_CHUNK_SIZE);
	buf = mmap(0, up_bound, PROT_READ, MAP_PRIVATE | MAP_FILE, fd, 0);
	if (buf == MAP_FAILED) {
		pr_warn("Couldn't mmap file with fd %d", fd);
		return false;
	}

	*checksum = 0xFFFFFFFF;
	checksum_iterator_init(&offset);

	while (!checksum_iterator_stop(offset) && offset >= low_bound && offset < up_bound) {

		byte = buf[offset-low_bound];

		*checksum = *checksum ^ byte;
		for (tmp = 0; tmp < 8; tmp++) {
			mask = -(*checksum & 1);

			/*
			 * Little endian notation is used.
			 * The Castagnoli polynomial (0x82F63B78) is used instead of
			 * 0xEDB88320 and is the difference between CRC32C and CRC32.
			 */
			*checksum = (*checksum >> 1) ^ (0x82F63B78 & mask);
		}

		checksum_iterator_next(&offset);

		/*
		 * If the new iterator position is outside the mapped region (Bytes in the range
		 * low_bound and up_bound) of the file, the current region needs to be unmapped
		 * and the next portion (At most the next 10MB) of the file needs to be mapped.
		 */
		if (offset >= up_bound && offset < fd_status->st_size &&
				up_bound != fd_status->st_size) {

			munmap(buf, up_bound - low_bound);

			low_bound = round_down(offset, sysconf(_SC_PAGE_SIZE));
			up_bound = min_t(size_t, fd_status->st_size, low_bound + CHKSM_CHUNK_SIZE);

			buf = mmap(0, up_bound - low_bound, PROT_READ, MAP_PRIVATE | MAP_FILE,
					fd, low_bound);
		}
		if (buf == MAP_FAILED) {
			pr_warn("Couldn't mmap file with fd %d", fd);
			return false;
		}
	}
	*checksum = ~*checksum;

	munmap(buf, up_bound - low_bound);
	return true;
}

/*
 * Finds and stores the build-id of a file, if it exists, so that it can be validated
 * while restoring.
 * Returns 1 if the build-id of the file could be stored, -1 if there was an error
 * or 0 if the build-id could not be obtained.
 */
int store_validation_data_build_id(RegFileEntry *rfe, int lfd,
						const struct fd_parms *p)
{
	unsigned char *build_id = NULL;
	int build_id_size, allocated_size;
	int fd;

	/*
	 * Checks whether the file is atleast big enough to try and read the first
	 * four (SELFMAG) bytes which should correspond to the ELF magic number
	 * and the next byte which indicates whether the file is 32-bit or 64-bit.
	 */
	if (p->stat.st_size < SELFMAG+1)
		return 0;

	fd = open_proc(PROC_SELF, "fd/%d", lfd);
	if (fd < 0) {
		pr_err("Build-ID (For validation) could not be obtained for file %s because can't open the file\n",
				rfe->name);
		return -1;
	}

	build_id_size = get_build_id(fd, &(p->stat), &build_id);
	close(fd);
	if (!build_id || build_id_size == -1)
		return 0;

	allocated_size = round_up(build_id_size, sizeof(uint32_t));
	rfe->build_id = xzalloc(allocated_size);
	if (!rfe->build_id) {
		pr_warn("Build-ID (For validation) could not be set for file %s\n",
				rfe->name);
		return -1;
	}

	rfe->n_build_id = allocated_size / sizeof(uint32_t);
	memcpy(rfe->build_id, (void *) build_id, build_id_size);

	xfree(build_id);
	return 1;
}

/*
 * Finds and stores the CRC32C checksum of a file so that it can be validated
 * while restoring.
 * Returns 1 if the checksum of the file could be stored, -1 if there was an error
 * or 0 if the checksum could not be obtained.
 */
int store_validation_data_checksum(RegFileEntry *rfe, int lfd,
						const struct fd_parms *p)
{
	u32 checksum;
	int fd;

	if (!p->stat.st_size)
		return 0;

	fd = open_proc(PROC_SELF, "fd/%d", lfd);
	if (fd < 0) {
		pr_err("Checksum (For validation) could not be obtained for file %s because can't open the file\n",
				rfe->name);
		return -1;
	}

	if (!calculate_checksum(fd, &(p->stat), &checksum)) {
		close(fd);
		pr_err("Could not obtain checksum for file %s\n", rfe->name);
		return -1;
	}
	close(fd);

	rfe->has_checksum = true;
	rfe->checksum = checksum;

	rfe->has_checksum_config = true;
	rfe->checksum_config = opts.file_validation_chksm_config;

	rfe->has_checksum_parameter = true;
	rfe->checksum_parameter = opts.file_validation_chksm_parameter;

	return 1;
}

/*
 * Compares the file's build-id with the stored value.
 * Returns 1 if the build-id of the file matches the build-id that was stored
 * while dumping, -1 if there is a mismatch or 0 if the build-id has not been
 * stored or could not be obtained.
 */
int validate_with_build_id(const int fd, const struct stat *fd_status,
					const struct reg_file_info *rfi)
{
	unsigned char *build_id;
	int build_id_size;

	if (!rfi->rfe->has_size)
		return 1;

	if (!rfi->rfe->n_build_id)
		return 0;

	build_id = NULL;
	build_id_size = get_build_id(fd, fd_status, &build_id);
	if (!build_id || build_id_size == -1)
		return 0;

	if (round_up(build_id_size, sizeof(uint32_t)) != rfi->rfe->n_build_id * sizeof(uint32_t)) {
		pr_err("File %s has bad build-ID length %d (expect %d)\n", rfi->path,
				round_up(build_id_size, sizeof(uint32_t)),
				(int) (rfi->rfe->n_build_id * sizeof(uint32_t)));
		xfree(build_id);
		return -1;
	}

	if (memcmp(build_id, rfi->rfe->build_id, build_id_size)) {
		pr_err("File %s has bad build-ID\n", rfi->path);
		xfree(build_id);
		return -1;
	}

	xfree(build_id);
	return 1;
}

/*
 * Compares the file's CRC32C checksum with the stored value.
 * Returns 1 if the checksum of the file matches the checksum that was stored
 * while dumping, -1 if there is a mismatch or 0 if the checksum has not been
 * stored or could not be obtained.
 */
int validate_with_checksum(const int fd, const struct stat *fd_status,
					const struct reg_file_info *rfi)
{
	u32 checksum;

	if (!rfi->rfe->has_size)
		return 1;

	if (!rfi->rfe->has_checksum || !rfi->rfe->has_checksum_config ||
		!rfi->rfe->has_checksum_parameter)
		return 0;

	/*
	 * If the checksum configuration used while dumping is not the same as the current
	 * checksum configuration, then the user is informed of this and the checksum
	 * configuration used while dumping is considered.
	 */
	if (opts.file_validation_chksm_config != rfi->rfe->checksum_config) {
		pr_warn("Checksum configuration (For validation) doesn't match the configuration used for dumping file %s\n",
				rfi->path);
		opts.file_validation_chksm_config = rfi->rfe->checksum_config;
	}

	/*
	 * If the checksum parameter used while dumping is not the same as the current
	 * checksum parameter, then the user is informed of this and the checksum parameter
	 * used while dumping is considered. If the checksum config is to checksum the entire
	 * file, then no changes need to be made since the checksum parameter isn't used anyway.
	 */
	if (opts.file_validation_chksm_config != FILE_VALIDATION_CHKSM_FULL &&
			opts.file_validation_chksm_parameter != rfi->rfe->checksum_parameter) {
		pr_warn("Checksum parameter (For validation) doesn't match the parameter used for dumping file %s\n",
				rfi->path);
		opts.file_validation_chksm_parameter = rfi->rfe->checksum_parameter;
	}

	if (!calculate_checksum(fd, fd_status, &checksum)) {
		pr_warn("Could not validate with checksum for file %s\n", rfi->path);
		return 0;
	}

	if (checksum == rfi->rfe->checksum)
		return 1;

	pr_err("File %s has bad checksum %x (expect %x)\n",
			rfi->path, checksum, rfi->rfe->checksum);
	return -1;
}