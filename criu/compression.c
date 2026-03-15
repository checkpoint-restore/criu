#include <limits.h>
#include <stdint.h>
#include <string.h>

#include <lz4.h>

#include "page.h"
#include "log.h"
#include "compression.h"

#undef LOG_PREFIX
#define LOG_PREFIX "compression: "

int compress_data(const char *input_data, size_t input_size,
		  char *compressed_data, size_t output_size,
		  int acceleration)
{
	int ret;

	if (!input_data || !compressed_data || !input_size ||
	    input_size > LZ4_MAX_INPUT_SIZE || output_size > INT_MAX) {
		pr_err("Invalid compression buffer sizes: input=%zu output=%zu\n",
		       input_size, output_size);
		return -1;
	}

	if (acceleration < 1)
		acceleration = 1;

	ret = LZ4_compress_fast(input_data, compressed_data, input_size,
				output_size, acceleration);
	if (ret <= 0) {
		pr_err("Failed to compress data: %d\n", ret);
		return -1;
	}

	return ret;
}

static int decompress_data_nolog(const char *compressed_data,
				 int compressed_size, int original_size,
				 char *decompressed_data)
{
	int ret;

	ret = LZ4_decompress_safe(compressed_data, decompressed_data,
				  compressed_size, original_size);
	return ret == original_size ? 0 : -1;
}

int decompress_data(const char *compressed_data, int compressed_size,
		    int original_size, char *decompressed_data)
{
	int ret;

	if (!compressed_data || !decompressed_data || compressed_size <= 0 ||
	    original_size <= 0) {
		pr_err("Invalid decompression buffer sizes: input=%d output=%d\n",
		       compressed_size, original_size);
		return -1;
	}

	ret = LZ4_decompress_safe(compressed_data, decompressed_data,
				  compressed_size, original_size);

	if (ret != original_size) {
		pr_err("Decompression failed: expected %d bytes, got %d\n",
		       original_size, ret);
		return -1;
	}

	return 0;
}

int compress_region(const char *src, unsigned int n_pages, char *dst,
		    size_t dst_cap, int acceleration)
{
	size_t region_bytes;
	unsigned int i;
	int ret;

	if (n_pages == 0 || n_pages > MAX_REGION_PAGES) {
		pr_err("compress_region: invalid n_pages %u\n", n_pages);
		return -1;
	}
	if (!src || !dst) {
		pr_err("compress_region: invalid buffer\n");
		return -1;
	}
	region_bytes = (size_t)n_pages * PAGE_SIZE;

	/* Cheap pre-pass: every page in the region zero-filled? */
	for (i = 0; i < n_pages; i++) {
		if (!page_is_all_zero(src + (size_t)i * PAGE_SIZE))
			break;
	}
	if (i == n_pages)
		return 0;

	if (dst_cap < region_bytes) {
		pr_err("compress_region: dst buffer (%zu) smaller than region (%zu)\n",
		       dst_cap, region_bytes);
		return -1;
	}

	if (acceleration < 1)
		acceleration = 1;

	ret = LZ4_compress_fast(src, dst, region_bytes, dst_cap, acceleration);
	if (ret <= 0 || (size_t)ret >= REGION_COMPRESSION_THRESHOLD(region_bytes)) {
		/*
		 * LZ4 can fail when dst_cap is below LZ4 worst-case bound
		 * (which the caller should size correctly), or when the
		 * compressed size hits the threshold and we'd rather store
		 * raw. Either way, fall back to raw.
		 */
		memcpy(dst, src, region_bytes);
		return region_bytes;
	}

	return ret;
}

int decompress_region(const char *src, int compressed_size,
		      unsigned int n_pages, char *dst)
{
	size_t region_bytes;

	if (n_pages == 0 || n_pages > MAX_REGION_PAGES) {
		pr_err("decompress_region: invalid n_pages %u\n", n_pages);
		return -1;
	}
	if (compressed_size < 0) {
		pr_err("decompress_region: negative compressed_size %d\n",
		       compressed_size);
		return -1;
	}
	if (!dst || (compressed_size && !src)) {
		pr_err("decompress_region: invalid buffer\n");
		return -1;
	}
	region_bytes = (size_t)n_pages * PAGE_SIZE;

	if ((size_t)compressed_size > region_bytes) {
		pr_err("decompress_region: compressed_size %d > region %zu\n",
		       compressed_size, region_bytes);
		return -1;
	}

	if (compressed_size == 0) {
		memset(dst, 0, region_bytes);
		return 0;
	}

	if ((size_t)compressed_size == region_bytes) {
		memcpy(dst, src, region_bytes);
		return 0;
	}

	if (decompress_data_nolog(src, compressed_size, region_bytes, dst)) {
		pr_err("Region decompression failed (compressed_size=%d, n_pages=%u)\n",
		       compressed_size, n_pages);
		return -1;
	}

	return 0;
}
