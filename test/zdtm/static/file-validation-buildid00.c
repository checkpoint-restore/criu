#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#include "zdtmtst.h"

const char *test_doc	= "File validation test for build-id with 1 PT_NOTE header in a 32 bit ELF file (Should fail during restore)";
const char *test_author	= "Ajay Bharadwaj <ajayrbharadwaj@gmail.com>";

char *filename;
TEST_OPTION(filename, string, "file name", 1);

#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))

int main(int argc, char **argv)
{
	Elf32_Ehdr file_header;
	Elf32_Phdr program_header;
	Elf32_Nhdr note_header;

	int fd, name_size, build_id_size, i, tmp = '0';
	char name[] = "GNU";
	unsigned char build_id[] = {0xb, 0xb, 0xb, 0xb};

	test_init(argc, argv);

	memset(&file_header, 0, sizeof(file_header));
	memset(&program_header, 0, sizeof(program_header));
	memset(&note_header, 0, sizeof(note_header));

	name_size = ALIGN(sizeof(name), 4);
	build_id_size = ALIGN(sizeof(build_id), 4);

	file_header.e_ident[EI_MAG0]		= ELFMAG0;
	file_header.e_ident[EI_MAG1]		= ELFMAG1;
	file_header.e_ident[EI_MAG2]		= ELFMAG2;
	file_header.e_ident[EI_MAG3]		= ELFMAG3;
	file_header.e_ident[EI_CLASS]		= ELFCLASS32;
	file_header.e_ident[EI_DATA]		= ELFDATANONE;
	file_header.e_ident[EI_VERSION]		= EV_CURRENT;
	file_header.e_ident[EI_OSABI]		= ELFOSABI_NONE;
	file_header.e_ident[EI_ABIVERSION]	= 0;
	file_header.e_type			= ET_NONE;
	file_header.e_machine			= EM_NONE;
	file_header.e_version			= EV_CURRENT;
	file_header.e_entry			= 0;
	file_header.e_phoff			= sizeof(file_header);
	file_header.e_shoff			= 0;
	file_header.e_flags			= 0;
	file_header.e_ehsize			= sizeof(file_header);
	file_header.e_phentsize			= sizeof(program_header);
	file_header.e_phnum			= 1;
	file_header.e_shentsize			= 0;
	file_header.e_shnum			= 0;
	file_header.e_shstrndx			= SHN_UNDEF;

	program_header.p_type			= PT_NOTE;
	program_header.p_flags			= PF_R | PF_W;
	program_header.p_offset			= sizeof(file_header) + sizeof(program_header);
	program_header.p_vaddr			= sizeof(file_header) + sizeof(program_header);
	program_header.p_paddr			= 0;
	program_header.p_filesz			= sizeof(note_header) + name_size + build_id_size;
	program_header.p_memsz			= sizeof(note_header) + name_size + build_id_size;
	program_header.p_align			= 1;

	note_header.n_namesz			= sizeof(name);
	note_header.n_descsz			= sizeof(build_id);
	note_header.n_type			= NT_GNU_BUILD_ID;

	fd = open(filename, O_RDWR | O_CREAT, 0666);
	if (fd < 0) {
		pr_perror("Can't open %s", filename);
		return 1;
	}

	if (write(fd, &file_header, sizeof(file_header)) != sizeof(file_header) ||
		write(fd, &program_header, sizeof(program_header)) != sizeof(program_header) ||
		write(fd, &note_header, sizeof(note_header)) != sizeof(note_header))
		goto write_err;

	if (write(fd, name, sizeof(name)) != sizeof(name))
		goto write_err;
	for (i = 0; i < name_size-sizeof(name); i++)
		if (write(fd, &tmp, 1) != 1)
			goto write_err;

	if (write(fd, build_id, sizeof(build_id)) != sizeof(build_id))
		goto write_err;
	for (i = 0; i < build_id_size-sizeof(build_id); i++)
		if (write(fd, &tmp, 1) != 1)
			goto write_err;

	if (lseek(fd, 0, SEEK_SET) < 0)
	{
		pr_perror("lseek() failed");
		return -1;
	}

	test_daemon();
	test_waitsig();

	if (close(fd) < 0) {
		pr_perror("Can't close %s", filename);
		return 1;
	}

	fail("Restore passed even though the build-id in the file was altered\n");
	return 0;

write_err:
	pr_perror("write() failed");
	return 1;
}