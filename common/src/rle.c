#include "dosmnt/rle.h"

#include <string.h>

/*
 * Encoding format:
 *  - Literal runs: header byte 0-0x7F storing (length-1), followed by that many literal bytes.
 *  - Repeated runs: header byte 0x80-0xFF storing (length-1) in the low 7 bits, followed by the repeated byte.
 * Literal runs are capped at 128 bytes, repeated runs at 128 repetitions.
 */

size_t dosmnt_rle_compress(const uint8_t *src, size_t len, uint8_t *dst, size_t dst_cap) {
    size_t in = 0;
    size_t out = 0;

    if (!src || !dst) {
        return (size_t)-1;
    }

    while (in < len) {
        size_t run = 1;
        while (in + run < len && src[in + run] == src[in] && run < 128) {
            ++run;
        }

        if (run >= 3) {
            if (out + 2 > dst_cap) {
                return (size_t)-1;
            }
            dst[out++] = (uint8_t)(0x80 | (run - 1));
            dst[out++] = src[in];
            in += run;
        } else {
            size_t lit_start = in;
            size_t lit_len = 0;
            do {
                ++lit_len;
                ++in;
                if (lit_len == 128 || in >= len) {
                    break;
                }
                run = 1;
                while (in + run < len && src[in + run] == src[in] && run < 128) {
                    ++run;
                }
            } while (run < 3);

            if (out + 1 + lit_len > dst_cap) {
                return (size_t)-1;
            }
            dst[out++] = (uint8_t)(lit_len - 1);
            memcpy(dst + out, src + lit_start, lit_len);
            out += lit_len;
        }
    }

    return out;
}

int dosmnt_rle_decompress(const uint8_t *src, size_t len, uint8_t *dst, size_t dst_cap, size_t *out_len) {
    size_t in = 0;
    size_t out = 0;

    if (!src || (!dst && dst_cap > 0)) {
        return -1;
    }

    while (in < len) {
        uint8_t header = src[in++];
        size_t count;

        if (header & 0x80) {
            if (in >= len) {
                return -1;
            }
            count = (size_t)(header & 0x7F) + 1;
            if (out + count > dst_cap) {
                return -1;
            }
            memset(dst + out, src[in], count);
            ++in;
            out += count;
        } else {
            count = (size_t)header + 1;
            if (in + count > len || out + count > dst_cap) {
                return -1;
            }
            memcpy(dst + out, src + in, count);
            in += count;
            out += count;
        }
    }

    if (out_len) {
        *out_len = out;
    }
    return 0;
}
