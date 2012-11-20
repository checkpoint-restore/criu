#include <stdlib.h>

#include "zdtmtst.h"

/* update CRC-32 */
#define CRCPOLY 0xedb88320
static inline uint32_t crc32_le8(uint32_t crc, uint8_t datum)
{
	int i;
	crc ^= datum;
	for (i = 0; i < 8; i++)
		crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY : 0);
	return crc;
}

void datagen(uint8_t *buffer, unsigned length, uint32_t *crc)
{
	uint32_t rnd = 0;
	unsigned shift;

	for (shift = 0; length-- > 4; buffer++, shift--, rnd >>= 8) {
		if (!shift) {
			shift = 4;
			rnd = mrand48();
		}

		*buffer = rnd;
		if (crc)
			*crc = crc32_le8(*crc, *buffer);
	}

	if (crc) {
		*buffer++ = *crc;
		*buffer++ = *crc >> 8;
		*buffer++ = *crc >> 16;
		*buffer++ = *crc >> 24;
	}
}

void datagen2(uint8_t *buffer, unsigned length, uint32_t *crc)
{
	uint32_t rnd = 0;
	unsigned shift;

	for (shift = 0; length-- > 0; buffer++, shift--, rnd >>= 8) {
		if (!shift) {
			shift = 4;
			rnd = mrand48();
		}

		*buffer = rnd;
		if (crc)
			*crc = crc32_le8(*crc, *buffer);
	}
}

int datachk(const uint8_t *buffer, unsigned length, uint32_t *crc)
{
	uint32_t read_crc;

	for (; length-- > 4; buffer++)
		*crc = crc32_le8(*crc, *buffer);

	read_crc = buffer[0] |
		buffer[1] << 8  |
		buffer[2] << 16 |
		buffer[3] << 24;
	if (read_crc != *crc) {
		test_msg("Read: %x, Expected: %x\n", read_crc, *crc);
		return 1;
	}
	return 0;
}

int datasum(const uint8_t *buffer, unsigned length, uint32_t *crc)
{
	for (; length-- > 0; buffer++)
		*crc = crc32_le8(*crc, *buffer);

	return 0;
}
