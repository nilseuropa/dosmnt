#ifndef DOSMNT_PROTOCOL_H
#define DOSMNT_PROTOCOL_H

#include <stdint.h>

#define DOSMNT_PREAMBLE_A 0xA5
#define DOSMNT_PREAMBLE_B 0x5A

#define DOSMNT_MAX_PAYLOAD 2048
#define DOSMNT_MAX_PATH    144
#define DOSMNT_MAX_DATA    1024

enum dosmnt_opcode {
    DOSMNT_OP_HELLO = 0x10,
    DOSMNT_OP_LIST  = 0x11,
    DOSMNT_OP_STAT  = 0x12,
    DOSMNT_OP_READ  = 0x13,
    DOSMNT_OP_BYE   = 0x1F
};

enum dosmnt_status {
    DOSMNT_STATUS_OK           = 0x00,
    DOSMNT_STATUS_MALFORMED    = 0x01,
    DOSMNT_STATUS_UNSUPPORTED  = 0x02,
    DOSMNT_STATUS_NOT_FOUND    = 0x03,
    DOSMNT_STATUS_IO_ERROR     = 0x04,
    DOSMNT_STATUS_NO_SPACE     = 0x05,
    DOSMNT_STATUS_TOO_LARGE    = 0x06,
    DOSMNT_STATUS_INTERNAL     = 0x07
};

enum dosmnt_dirent_type {
    DOSMNT_DIRENT_FILE = 0,
    DOSMNT_DIRENT_DIR  = 1
};

#define DOS_ATTR_READONLY  0x01
#define DOS_ATTR_HIDDEN    0x02
#define DOS_ATTR_SYSTEM    0x04
#define DOS_ATTR_VOLUME    0x08
#define DOS_ATTR_DIRECTORY 0x10
#define DOS_ATTR_ARCHIVE   0x20

#pragma pack(push, 1)
struct dosmnt_dirent {
    uint8_t  type;
    uint32_t size;
    uint32_t write_time; /* packed DOS date/time */
    uint8_t  name_len;
    /* name bytes follow */
};

struct dosmnt_stat {
    uint8_t  attributes;
    uint32_t size;
    uint32_t write_time; /* packed DOS date/time */
};
#pragma pack(pop)

static inline uint8_t dosmnt_response_opcode(uint8_t op) {
    return (uint8_t)(op | 0x80);
}

#endif /* DOSMNT_PROTOCOL_H */
