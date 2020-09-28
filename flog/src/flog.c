#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/mman.h>

//#include <ffi.h>

#include "uapi/flog.h"
#include "util.h"

#define MAGIC 0xABCDABCD

#define BUF_SIZE (1<<20)
static char _mbuf[BUF_SIZE];
static char *mbuf = _mbuf;
static char *fbuf;
static uint64_t fsize;
static uint64_t mbuf_size = sizeof(_mbuf);

/*int flog_decode_all(int fdin, int fdout)
{
	flog_msg_t *m = (void *)mbuf;
	ffi_type *args[34] = {
		[0]		= &ffi_type_sint,
		[1]		= &ffi_type_pointer,
		[2 ... 33]	= &ffi_type_slong
	};
	void *values[34];
	ffi_cif cif;
	ffi_arg rc;
	size_t i, ret;
	char *fmt;

	values[0] = (void *)&fdout;

	while (1) {
		ret = read(fdin, mbuf, sizeof(m));
		if (ret == 0)
			break;
		if (ret < 0) {
			fprintf(stderr, "Unable to read a message: %m");
			return -1;
		}
		if (m->magic != MAGIC) {
			fprintf(stderr, "The log file was not properly closed\n");
			break;
		}
		ret = m->size - sizeof(m);
		if (m->size > mbuf_size) {
			fprintf(stderr, "The buffer is too small");
			return -1;
		}
		if (read(fdin, mbuf + sizeof(m), ret) != ret) {
			fprintf(stderr, "Unable to read a message: %m");
			return -1;
		}

		fmt = mbuf + m->fmt;
		values[1] = &fmt;

		for (i = 0; i < m->nargs; i++) {
			values[i + 2] = (void *)&m->args[i];
			if (m->mask & (1u << i)) {
				m->args[i] = (long)(mbuf + m->args[i]);
			}
		}

		if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, m->nargs + 2,
				 &ffi_type_sint, args) == FFI_OK)
			ffi_call(&cif, FFI_FN(dprintf), &rc, values);
	}
	return 0;
}*/

static int flog_enqueue(flog_msg_t *m)
{
	if (write(1, m, m->size) != m->size) {
		fprintf(stderr, "Unable to write a message\n");
		return -1;
	}
	return 0;
}

/*extern char *rodata_start;
extern char *rodata_end;
*/
/* Pre-allocate a buffer in a file and map it into memory. */
int flog_map_buf(int fdout)
{
	uint64_t off = 0;
	void *addr;

	/*
	 * Two buffers are mmaped into memory. A new one is mapped when a first
	 * one is completly filled.
	 */
	if (fbuf && (mbuf - fbuf < BUF_SIZE))
		return 0;

	if (fbuf) {
		if (munmap(fbuf, BUF_SIZE * 2)) {
			fprintf(stderr, "Unable to unmap a buffer: %m");
			return -1;
		}
		off = mbuf - fbuf - BUF_SIZE;
		fbuf = NULL;
	}

	if (fsize == 0)
		fsize += BUF_SIZE;
	fsize += BUF_SIZE;

	if (ftruncate(fdout, fsize)) {
		fprintf(stderr, "Unable to truncate a file: %m");
		return -1;
	}

	if (!fbuf)
		addr = mmap(NULL, BUF_SIZE * 2, PROT_WRITE | PROT_READ,
			    MAP_FILE | MAP_SHARED, fdout, fsize - 2 * BUF_SIZE);
	else
		addr = mremap(fbuf + BUF_SIZE, BUF_SIZE,
				BUF_SIZE * 2, MREMAP_FIXED, fbuf);
	if (addr == MAP_FAILED) {
		fprintf(stderr, "Unable to map a buffer: %m");
		return -1;
	}

	fbuf = addr;
	mbuf = fbuf + off;
	mbuf_size = 2 * BUF_SIZE;

	return 0;
}

int flog_close(int fdout)
{
	if (mbuf == _mbuf)
		return 0;

	munmap(fbuf, BUF_SIZE * 2);

	if (ftruncate(fdout, fsize - 2 * BUF_SIZE + mbuf - fbuf)) {
		fprintf(stderr, "Unable to truncate a file: %m");
		return -1;
	}
	return 0;
}

int flog_encode_msg(int fdout, unsigned int nargs, unsigned int mask, const char *format, ...)
{
	flog_msg_t *m;
	va_list argptr;
	char *str_start, *p;
	size_t i;

	if (mbuf != _mbuf && flog_map_buf(fdout))
		return -1;

	m = (void *) mbuf;

	m->nargs = nargs;
	m->mask = mask;

	str_start = (void *)m->args + sizeof(m->args[0]) * nargs;
	p = memccpy(str_start, format, 0, mbuf_size - (str_start - mbuf));
	if (p == NULL) {
		fprintf(stderr, "No memory for string argument\n");
		return -1;
	}
	m->fmt = str_start - mbuf;
	str_start = p;

	va_start(argptr, format);
	for (i = 0; i < nargs; i++) {
		m->args[i] = (long)va_arg(argptr, long);
		/*
		 * If we got a string, we should either
		 * reference it when in rodata, or make
		 * a copy (FIXME implement rodata refs).
		 */
		if (mask & (1u << i)) {
			p = memccpy(str_start, (void *)m->args[i], 0, mbuf_size - (str_start - mbuf));
			if (p == NULL) {
				fprintf(stderr, "No memory for string argument\n");
				va_end(argptr);
				return -1;
			}
			m->args[i] = str_start - mbuf;
			str_start = p;
		}
	}
	va_end(argptr);
	m->size = str_start - mbuf;

	/*
	 * A magic is required to know where we stop writing into a log file,
	 * if it was not properly closed.  The file is mapped into memory, so a
	 * space in the file is allocated in advance and at the end it can have
	 * some unused tail.
	 */
	m->magic = MAGIC;

	m->size = roundup(m->size, 8);
	if (mbuf == _mbuf) {
		if (flog_enqueue(m))
			return -1;
	} else {
		mbuf += m->size;
		mbuf_size -= m->size;
	}
	return 0;
}
