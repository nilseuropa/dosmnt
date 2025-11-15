#ifndef DOSMNT_RLE_H
#define DOSMNT_RLE_H

#include <stddef.h>
#include <stdint.h>

size_t dosmnt_rle_compress(const uint8_t *src, size_t len, uint8_t *dst, size_t dst_cap);
int dosmnt_rle_decompress(const uint8_t *src, size_t len, uint8_t *dst, size_t dst_cap, size_t *out_len);

#endif /* DOSMNT_RLE_H */
