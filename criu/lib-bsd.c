#include <stddef.h>
#include <string.h>

#include "cr-libs.h"

/*
 * Adopted from Linux kernel
 */

/**
 * criu_strlcpy - Copy a %NULL terminated string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero). It does not pad
 * out the result like strncpy() does.
 */
static size_t criu_strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}

/**
 * criu_strlcat - Append a length-limited, %NULL-terminated string to another
 * @dest: The string to be appended to
 * @src: The string to append to it
 * @count: The size of the destination buffer.
 */
static size_t criu_strlcat(char *dest, const char *src, size_t count)
{
	size_t dsize = strlen(dest);
	size_t len = strlen(src);
	size_t res = dsize + len;

	/*
	 * It's assumed that @dsize strictly
	 * less than count. Otherwise it's
	 * a bug. But we left it to a caller.
	 */
	dest += dsize;
	count -= dsize;
	if (len >= count)
		len = count-1;
	memcpy(dest, src, len);
	dest[len] = 0;
	return res;
}

size_t strlcpy(char *dest, const char *src, size_t size)
{
	__typeof__(strlcpy) *f;

	f = shared_libs_lookup_once(LIB_BSD, __func__);
	if (f)
		return f(dest, src, size);
	else
		return criu_strlcpy(dest, src, size);
}

size_t strlcat(char *dest, const char *src, size_t count)
{
	__typeof__(strlcat) *f;

	f = shared_libs_lookup_once(LIB_BSD, __func__);
	if (f)
		return f(dest, src, count);
	else
		return criu_strlcat(dest, src, count);
}

void setproctitle_init(int argc, char *argv[], char *envp[])
{
	__typeof__(setproctitle_init) *f;

	f = shared_libs_lookup_once(LIB_BSD, __func__);
	if (f)
		f(argc, argv, envp);
}

void setproctitle(const char *fmt, ...)
{
	__typeof__(setproctitle) *f;

	f = shared_libs_lookup_once(LIB_BSD, __func__);
	if (f)
		f(fmt);
}
