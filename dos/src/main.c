#include <conio.h>
#include <ctype.h>
#include <dos.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <direct.h>

#include "dos_serial.h"
#include "dosmnt/protocol.h"

#define SERIAL_DEFAULT_PORT 0x3F8
#define SERIAL_DEFAULT_BAUD 115200UL
#define COM_MAX 4

struct dosmnt_frame {
    uint8_t opcode;
    uint8_t seq;
    uint16_t length;
    uint8_t payload[DOSMNT_MAX_PAYLOAD];
};

static volatile int g_keep_running = 1;
static FILE *g_trace_file = NULL;
static FILE *g_active_file = NULL;
static char g_active_path[DOSMNT_MAX_PATH];
static struct dosmnt_frame g_frame;
static uint8_t g_response_buffer[DOSMNT_MAX_PAYLOAD];
static uint16_t g_serial_port = SERIAL_DEFAULT_PORT;
static uint32_t g_serial_baud = SERIAL_DEFAULT_BAUD;
enum active_mode {
    ACTIVE_MODE_NONE = 0,
    ACTIVE_MODE_READ,
    ACTIVE_MODE_WRITE
};
static enum active_mode g_active_mode = ACTIVE_MODE_NONE;
static uint32_t g_active_size = 0;

#define TRACE_LOG_NAME "DOSSRV.LOG"
static int g_trace = 0;

static void tracef(const char *fmt, ...);
static void log_line(const char *text);
static void init_trace_log(void);
static void close_trace_log(void);
static void reset_active_file(void);
static uint32_t get_file_size(FILE *fp);
static int parse_command_line(int argc, char **argv);
static int parse_com_port(const char *value, uint16_t *out);
static int parse_baud(const char *value, uint32_t *out);
static void print_usage(const char *prog_name);

static void tracef(const char *fmt, ...) {
    va_list ap;
    if (!g_trace) {
        return;
    }
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    if (g_trace_file != NULL) {
        va_start(ap, fmt);
        vfprintf(g_trace_file, fmt, ap);
        fflush(g_trace_file);
        va_end(ap);
    }
}

static void log_line(const char *text) {
    if (g_trace_file != NULL) {
        fputs(text, g_trace_file);
        fflush(g_trace_file);
    }
}

static void init_trace_log(void) {
    g_trace_file = fopen(TRACE_LOG_NAME, "wt");
    if (g_trace_file != NULL) {
        log_line("DOSMNT trace log started\r\n");
    } else {
        printf("Warning: unable to create %s\r\n", TRACE_LOG_NAME);
    }
}

static void close_trace_log(void) {
    if (g_trace_file != NULL) {
        log_line("DOSMNT trace log closed\r\n");
        fclose(g_trace_file);
        g_trace_file = NULL;
    }
}

static uint8_t compute_checksum(uint8_t opcode, uint8_t seq, uint16_t length, const uint8_t *payload) {
    uint16_t sum = opcode + seq + (uint8_t)length + (uint8_t)(length >> 8);
    uint16_t i;

    for (i = 0; i < length; ++i) {
        sum += payload[i];
    }

    return (uint8_t)(sum & 0xFF);
}

static void serial_send_frame(uint8_t opcode, uint8_t seq, const uint8_t *payload, uint16_t length) {
    uint8_t checksum;
    uint16_t i;

    if (length > DOSMNT_MAX_PAYLOAD) {
        length = DOSMNT_MAX_PAYLOAD;
    }

    checksum = compute_checksum(opcode, seq, length, payload);

    serial_write_byte(DOSMNT_PREAMBLE_A);
    serial_write_byte(DOSMNT_PREAMBLE_B);
    serial_write_byte(opcode);
    serial_write_byte(seq);
    serial_write_byte((uint8_t)(length & 0xFF));
    serial_write_byte((uint8_t)(length >> 8));

    for (i = 0; i < length; ++i) {
        serial_write_byte(payload[i]);
    }

    serial_write_byte(checksum);
}

static int wait_for_serial_byte(uint8_t *value) {
    while (!serial_has_byte()) {
        if (kbhit()) {
            int ch = getch();
            if (ch == 't' || ch == 'T') {
                g_trace = !g_trace;
                printf("\r\n[trace %s]%s\r\n",
                       g_trace ? "on" : "off",
                       (g_trace && g_trace_file) ? " (logging to " TRACE_LOG_NAME ")" : "");
                if (g_trace_file != NULL) {
                    log_line(g_trace ? "[trace on]\r\n" : "[trace off]\r\n");
                }
                continue;
            }
            if (ch == 0x1B || ch == 0x03) {
                g_keep_running = 0;
                return 0;
            }
        }
    }

    *value = serial_read_byte();
    return 1;
}

static int read_frame(struct dosmnt_frame *frame) {
    uint8_t byte;
    uint16_t i;
    uint8_t checksum;

    while (g_keep_running) {
        if (!wait_for_serial_byte(&byte)) {
            return 0;
        }
        if (byte != DOSMNT_PREAMBLE_A) {
            continue;
        }
        if (!wait_for_serial_byte(&byte)) {
            return 0;
        }
        if (byte != DOSMNT_PREAMBLE_B) {
            continue;
        }

        if (!wait_for_serial_byte(&frame->opcode) ||
            !wait_for_serial_byte(&frame->seq)) {
            return 0;
        }

        if (!wait_for_serial_byte(&byte)) {
            return 0;
        }
        frame->length = byte;
        if (!wait_for_serial_byte(&byte)) {
            return 0;
        }
        frame->length |= ((uint16_t)byte << 8);

        if (frame->length > DOSMNT_MAX_PAYLOAD) {
            /* Drop the frame by consuming bytes */
            for (i = 0; i < frame->length + 1; ++i) {
                if (!wait_for_serial_byte(&byte)) {
                    return 0;
                }
            }
            continue;
        }

        for (i = 0; i < frame->length; ++i) {
            if (!wait_for_serial_byte(&frame->payload[i])) {
                return 0;
            }
        }

        if (!wait_for_serial_byte(&checksum)) {
            return 0;
        }

        if (checksum != compute_checksum(frame->opcode, frame->seq, frame->length, frame->payload)) {
            /* invalid checksum, drop */
            continue;
        }

        tracef("[dosmnt] RX opcode=0x%02X len=%u\r\n", frame->opcode, frame->length);
        return 1;
    }

    return 0;
}

static void send_status(uint8_t opcode, uint8_t seq, uint8_t status,
                        const uint8_t *data, uint16_t data_len) {
    uint8_t *payload = g_response_buffer;

    if (data == NULL) {
        data_len = 0;
    }

    if (data_len + 1 > DOSMNT_MAX_PAYLOAD) {
        data_len = DOSMNT_MAX_PAYLOAD - 1;
    }

    if (data_len > 0 && data != payload + 1) {
        memcpy(payload + 1, data, data_len);
    }

    tracef("[dosmnt] TX opcode=0x%02X len=%u status=0x%02X\r\n",
           dosmnt_response_opcode(opcode), data_len + 1, status);
    payload[0] = status;
    serial_send_frame(dosmnt_response_opcode(opcode), seq, payload, data_len + 1);
}

static void normalize_path(char *path);
static int is_drive_root(const char *path);
static int is_current_directory(const char *path);

static uint32_t pack_dos_timestamp(uint16_t date, uint16_t time) {
    return ((uint32_t)date << 16) | (uint32_t)time;
}

static uint8_t read_path_string(const uint8_t *payload, uint16_t length, uint16_t offset,
                                char *out_path, uint16_t *consumed) {
    uint16_t max_len;
    uint16_t i;
    const uint8_t *src;

    if (offset >= length) {
        return DOSMNT_STATUS_MALFORMED;
    }

    src = payload + offset;
    max_len = (uint16_t)(length - offset);

    for (i = 0; i < max_len; ++i) {
        uint8_t ch = src[i];
        if (ch == 0) {
            break;
        }
        if (i >= DOSMNT_MAX_PATH - 1) {
            return DOSMNT_STATUS_TOO_LARGE;
        }
        if (ch == '/') {
            ch = '\\';
        }
        out_path[i] = (char)toupper(ch);
    }

    if (i == max_len) {
        return DOSMNT_STATUS_MALFORMED;
    }

    out_path[i] = '\0';

    if (out_path[0] == '\0') {
        strcpy(out_path, ".\\");
    }

    if (consumed != NULL) {
        *consumed = (uint16_t)(i + 1);
    }

    return DOSMNT_STATUS_OK;
}

static void normalize_path(char *path) {
    size_t len;

    if (path == NULL) {
        return;
    }

    len = strlen(path);
    if (len == 0) {
        strcpy(path, ".\\");
        return;
    }

    if (len == 2 && path[1] == ':') {
        path[2] = '\\';
        path[3] = '\0';
        return;
    }

    if (len > 0 && path[len - 1] == '\\') {
        if (!(len == 3 && path[1] == ':' && path[2] == '\\')) {
            path[len - 1] = '\0';
        }
    }

    len = strlen(path);
    if (len == 2 && path[1] == ':') {
        path[2] = '\\';
        path[3] = '\0';
    }
}

static int is_drive_root(const char *path) {
    return path != NULL &&
           strlen(path) == 3 &&
           path[1] == ':' &&
           path[2] == '\\';
}

static int is_current_directory(const char *path) {
    return path != NULL && strcmp(path, ".\\") == 0;
}

static uint32_t get_file_size(FILE *fp) {
    int handle;
    long len;

    if (fp == NULL) {
        return 0;
    }

    handle = _fileno(fp);
    if (handle < 0) {
        return 0;
    }

    len = _filelength(handle);
    if (len < 0) {
        return 0;
    }

    return (uint32_t)len;
}

static void make_directory_pattern(const char *input, char *pattern) {
    size_t len;

    strncpy(pattern, input, DOSMNT_MAX_PATH - 4);
    pattern[DOSMNT_MAX_PATH - 4] = '\0';

    len = strlen(pattern);

    if (len == 0) {
        strcpy(pattern, "*.*");
        return;
    }

    if (pattern[len - 1] != '\\' && pattern[len - 1] != '/' && pattern[len - 1] != ':') {
        if (len < DOSMNT_MAX_PATH - 2) {
            pattern[len++] = '\\';
            pattern[len] = '\0';
        }
    }

    if (len < DOSMNT_MAX_PATH - 3) {
        strcpy(pattern + len, "*.*");
    } else {
        pattern[len - 1] = '\0';
        strcat(pattern, "*.*");
    }
}

static uint8_t handle_stat(char *path, struct dosmnt_stat *out_stat) {
    struct find_t info;
    unsigned attr_mask = _A_NORMAL | _A_RDONLY | _A_HIDDEN | _A_SYSTEM |
                         _A_ARCH | _A_SUBDIR;
    normalize_path(path);

    if (is_drive_root(path)) {
        out_stat->attributes = DOS_ATTR_DIRECTORY;
        out_stat->size = 0;
        out_stat->write_time = 0;
        return DOSMNT_STATUS_OK;
    }

    if (_dos_findfirst(path, attr_mask, &info) != 0) {
        tracef("[dosmnt] findfirst miss path=%s\r\n", path);
        return DOSMNT_STATUS_NOT_FOUND;
    }

    out_stat->attributes = info.attrib;
    out_stat->size = info.size;

    if (g_active_file != NULL &&
        g_active_mode == ACTIVE_MODE_WRITE &&
        strcmp(g_active_path, path) == 0 &&
        g_active_size > out_stat->size) {
        out_stat->size = g_active_size;
    }

    out_stat->write_time = pack_dos_timestamp(info.wr_date, info.wr_time);

    return DOSMNT_STATUS_OK;
}

static void process_hello(const struct dosmnt_frame *frame) {
    uint8_t payload[40];
    struct find_t info;
    unsigned attr_mask = _A_VOLID;
    unsigned drive = 0;
    char pattern[6] = "A:\\*.*";
    int done;

    payload[0] = DOSMNT_STATUS_OK;
    payload[1] = 1; /* protocol version */
    payload[2] = 0x00; /* filesystem is writable */
    payload[3] = 0x00;
    memset(payload + 4, 0, 32);

    _dos_getdrive(&drive);
    if (drive >= 1 && drive <= 26) {
        pattern[0] = (char)('A' + drive - 1);
    }

    done = _dos_findfirst(pattern, attr_mask, &info);
    if (done == 0) {
        strncpy((char *)(payload + 4), info.name, 31);
    }

    serial_send_frame(dosmnt_response_opcode(DOSMNT_OP_HELLO), frame->seq, payload, 36);
}

static void process_list(const struct dosmnt_frame *frame) {
    char path[DOSMNT_MAX_PATH];
    char pattern[DOSMNT_MAX_PATH];
    struct find_t info;
    unsigned attr_mask = _A_SUBDIR | _A_NORMAL | _A_RDONLY |
                         _A_HIDDEN | _A_SYSTEM | _A_ARCH;
    uint8_t *buffer = g_response_buffer + 1;
    uint16_t offset = 0;
    uint8_t status;

    status = read_path_string(frame->payload, frame->length, 0, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    normalize_path(path);
    tracef("[dosmnt] LIST path=%s\r\n", path);
    make_directory_pattern(path, pattern);

    if (_dos_findfirst(pattern, attr_mask, &info) != 0) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_NOT_FOUND, NULL, 0);
        return;
    }

    do {
        struct dosmnt_dirent entry;
        uint8_t name_len;
        size_t needed;

        if ((info.attrib & _A_VOLID) != 0) {
            continue;
        }

        if (strcmp(info.name, ".") == 0 || strcmp(info.name, "..") == 0) {
            continue;
        }

        name_len = (uint8_t)strlen(info.name);
        entry.type = (info.attrib & _A_SUBDIR) ? DOSMNT_DIRENT_DIR : DOSMNT_DIRENT_FILE;
        entry.size = info.size;
        entry.write_time = pack_dos_timestamp(info.wr_date, info.wr_time);
        entry.name_len = name_len;

        needed = sizeof(entry) + name_len;
        if ((offset + needed) > (DOSMNT_MAX_PAYLOAD - 1)) {
            send_status(frame->opcode, frame->seq, DOSMNT_STATUS_TOO_LARGE, NULL, 0);
            return;
        }

        memcpy(buffer + offset, &entry, sizeof(entry));
        offset += (uint16_t)sizeof(entry);
        memcpy(buffer + offset, info.name, name_len);
        offset += name_len;
    } while (_dos_findnext(&info) == 0);

    send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, buffer, offset);
}

static void process_stat(const struct dosmnt_frame *frame) {
    char path[DOSMNT_MAX_PATH];
    struct dosmnt_stat st;
    uint8_t status;

    status = read_path_string(frame->payload, frame->length, 0, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    tracef("[dosmnt] STAT path=%s\r\n", path);
    status = handle_stat(path, &st);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK,
                (const uint8_t *)&st, sizeof(st));
}

static void process_read(const struct dosmnt_frame *frame) {
    uint32_t offset;
    uint16_t chunk_len;
    char path[DOSMNT_MAX_PATH];
    uint8_t status;
    uint8_t *buffer = g_response_buffer + 1;
    size_t bytes_read;

    if (frame->length < 6) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_MALFORMED, NULL, 0);
        return;
    }

    offset = (uint32_t)frame->payload[0] |
             ((uint32_t)frame->payload[1] << 8) |
             ((uint32_t)frame->payload[2] << 16) |
             ((uint32_t)frame->payload[3] << 24);
    chunk_len = (uint16_t)frame->payload[4] | ((uint16_t)frame->payload[5] << 8);

    if (chunk_len > DOSMNT_MAX_DATA) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_NO_SPACE, NULL, 0);
        return;
    }

    status = read_path_string(frame->payload, frame->length, 6, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    normalize_path(path);

    tracef("[dosmnt] READ path=%s offset=%lu len=%u\r\n",
           path, offset, (unsigned)chunk_len);

    if (offset == 0 || g_active_file == NULL ||
        strcmp(g_active_path, path) != 0 ||
        g_active_mode != ACTIVE_MODE_READ) {
        reset_active_file();
        g_active_file = fopen(path, "rb");
        if (g_active_file == NULL) {
            tracef("[dosmnt] fopen failed errno=%d path=%s\r\n", errno, path);
            send_status(frame->opcode, frame->seq, DOSMNT_STATUS_NOT_FOUND, NULL, 0);
            return;
        }
        strncpy(g_active_path, path, sizeof(g_active_path) - 1);
        g_active_path[sizeof(g_active_path) - 1] = '\0';
        g_active_mode = ACTIVE_MODE_READ;
    }

    if (fseek(g_active_file, (long)offset, SEEK_SET) != 0) {
        tracef("[dosmnt] fseek failed errno=%d path=%s offset=%lu\r\n",
               errno, path, offset);
        reset_active_file();
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_IO_ERROR, NULL, 0);
        return;
    }

    bytes_read = fread(buffer, 1, chunk_len, g_active_file);
    send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, buffer, (uint16_t)bytes_read);
}

static uint8_t resize_file(const char *path, uint32_t new_size) {
    int fd;

    fd = _open(path, O_BINARY | O_RDWR);
    if (fd < 0) {
        fd = _open(path, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, S_IWRITE | S_IREAD);
        if (fd < 0) {
            return (errno == ENOENT) ? DOSMNT_STATUS_NOT_FOUND : DOSMNT_STATUS_IO_ERROR;
        }
    }

    if (chsize(fd, (long)new_size) != 0) {
        _close(fd);
        return DOSMNT_STATUS_IO_ERROR;
    }

    _close(fd);

    if (g_active_file != NULL && strcmp(g_active_path, path) == 0) {
        reset_active_file();
    }

    return DOSMNT_STATUS_OK;
}

static void process_write(const struct dosmnt_frame *frame) {
    uint32_t offset;
    uint16_t chunk_len;
    uint16_t path_bytes;
    uint16_t data_offset;
    const uint8_t *data_ptr;
    char path[DOSMNT_MAX_PATH];
    uint8_t status;
    size_t written;

    if (frame->length < 6) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_MALFORMED, NULL, 0);
        return;
    }

    offset = (uint32_t)frame->payload[0] |
             ((uint32_t)frame->payload[1] << 8) |
             ((uint32_t)frame->payload[2] << 16) |
             ((uint32_t)frame->payload[3] << 24);
    chunk_len = (uint16_t)frame->payload[4] | ((uint16_t)frame->payload[5] << 8);

    if (chunk_len > DOSMNT_MAX_DATA) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_NO_SPACE, NULL, 0);
        return;
    }

    status = read_path_string(frame->payload, frame->length, 6, path, &path_bytes);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    data_offset = (uint16_t)(6 + path_bytes);
    if ((uint32_t)data_offset + chunk_len > frame->length) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_MALFORMED, NULL, 0);
        return;
    }

    data_ptr = frame->payload + data_offset;
    normalize_path(path);

    tracef("[dosmnt] WRITE path=%s offset=%lu len=%u\r\n",
           path, offset, (unsigned)chunk_len);

    if (chunk_len == 0) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, NULL, 0);
        return;
    }

    if (g_active_file == NULL ||
        strcmp(g_active_path, path) != 0 ||
        g_active_mode != ACTIVE_MODE_WRITE) {
        reset_active_file();
        g_active_file = fopen(path, "rb+");
        if (g_active_file == NULL) {
            g_active_file = fopen(path, "wb+");
        }
        if (g_active_file == NULL) {
            tracef("[dosmnt] fopen (write) failed errno=%d path=%s\r\n", errno, path);
            send_status(frame->opcode, frame->seq, DOSMNT_STATUS_NOT_FOUND, NULL, 0);
            return;
        }
        strncpy(g_active_path, path, sizeof(g_active_path) - 1);
        g_active_path[sizeof(g_active_path) - 1] = '\0';
        g_active_mode = ACTIVE_MODE_WRITE;
        g_active_size = get_file_size(g_active_file);
    }

    if (fseek(g_active_file, (long)offset, SEEK_SET) != 0) {
        tracef("[dosmnt] fseek (write) failed errno=%d path=%s offset=%lu\r\n",
               errno, path, offset);
        reset_active_file();
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_IO_ERROR, NULL, 0);
        return;
    }

    written = fwrite(data_ptr, 1, chunk_len, g_active_file);
    if (written != chunk_len) {
        tracef("[dosmnt] fwrite failed errno=%d path=%s len=%u wrote=%lu\r\n",
               errno, path, (unsigned)chunk_len, (unsigned long)written);
        reset_active_file();
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_IO_ERROR, NULL, 0);
        return;
    }

    fflush(g_active_file);
    {
        uint32_t end_pos = offset + chunk_len;
        if (end_pos > g_active_size) {
            g_active_size = end_pos;
        }
    }
    send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, NULL, 0);
}

static void process_setlen(const struct dosmnt_frame *frame) {
    char path[DOSMNT_MAX_PATH];
    uint32_t new_size;
    uint8_t status;

    if (frame->length < 4) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_MALFORMED, NULL, 0);
        return;
    }

    new_size = (uint32_t)frame->payload[0] |
               ((uint32_t)frame->payload[1] << 8) |
               ((uint32_t)frame->payload[2] << 16) |
               ((uint32_t)frame->payload[3] << 24);

    status = read_path_string(frame->payload, frame->length, 4, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    status = resize_file(path, new_size);
    send_status(frame->opcode, frame->seq, status, NULL, 0);
}

static uint8_t validate_modifiable_path(const char *path) {
    if (is_current_directory(path) || is_drive_root(path)) {
        return DOSMNT_STATUS_MALFORMED;
    }
    return DOSMNT_STATUS_OK;
}

static void process_mkdir(const struct dosmnt_frame *frame) {
    char path[DOSMNT_MAX_PATH];
    uint8_t status;

    status = read_path_string(frame->payload, frame->length, 0, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    normalize_path(path);
    tracef("[dosmnt] MKDIR path=%s\r\n", path);

    status = validate_modifiable_path(path);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    if (_mkdir(path) == 0) {
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, NULL, 0);
        return;
    }

    switch (errno) {
        case ENOENT:
            status = DOSMNT_STATUS_NOT_FOUND;
            break;
        case EEXIST:
            status = DOSMNT_STATUS_EXISTS;
            break;
        default:
            status = DOSMNT_STATUS_IO_ERROR;
            break;
    }
    send_status(frame->opcode, frame->seq, status, NULL, 0);
}

static void process_rmdir(const struct dosmnt_frame *frame) {
    char path[DOSMNT_MAX_PATH];
    uint8_t status;

    status = read_path_string(frame->payload, frame->length, 0, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    normalize_path(path);
    tracef("[dosmnt] RMDIR path=%s\r\n", path);

    status = validate_modifiable_path(path);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    if (_rmdir(path) == 0) {
        if (g_active_file != NULL && strcmp(g_active_path, path) == 0) {
            reset_active_file();
        }
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, NULL, 0);
        return;
    }

    switch (errno) {
        case ENOENT:
            status = DOSMNT_STATUS_NOT_FOUND;
            break;
#ifdef ENOTEMPTY
        case ENOTEMPTY:
            status = DOSMNT_STATUS_NOT_EMPTY;
            break;
#endif
        default:
            status = DOSMNT_STATUS_IO_ERROR;
            break;
    }
    send_status(frame->opcode, frame->seq, status, NULL, 0);
}

static void process_delete(const struct dosmnt_frame *frame) {
    char path[DOSMNT_MAX_PATH];
    uint8_t status;

    status = read_path_string(frame->payload, frame->length, 0, path, NULL);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    normalize_path(path);
    tracef("[dosmnt] DELETE path=%s\r\n", path);

    status = validate_modifiable_path(path);
    if (status != DOSMNT_STATUS_OK) {
        send_status(frame->opcode, frame->seq, status, NULL, 0);
        return;
    }

    if (_unlink(path) == 0) {
        if (g_active_file != NULL && strcmp(g_active_path, path) == 0) {
            reset_active_file();
        }
        send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, NULL, 0);
        return;
    }

    switch (errno) {
        case ENOENT:
            status = DOSMNT_STATUS_NOT_FOUND;
            break;
        default:
            status = DOSMNT_STATUS_IO_ERROR;
            break;
    }
    send_status(frame->opcode, frame->seq, status, NULL, 0);
}

static void process_frame(const struct dosmnt_frame *frame) {
    switch (frame->opcode) {
        case DOSMNT_OP_HELLO:
            process_hello(frame);
            break;
        case DOSMNT_OP_LIST:
            process_list(frame);
            break;
        case DOSMNT_OP_STAT:
            process_stat(frame);
            break;
        case DOSMNT_OP_READ:
            process_read(frame);
            break;
        case DOSMNT_OP_WRITE:
            process_write(frame);
            break;
        case DOSMNT_OP_SETLEN:
            process_setlen(frame);
            break;
        case DOSMNT_OP_MKDIR:
            process_mkdir(frame);
            break;
        case DOSMNT_OP_RMDIR:
            process_rmdir(frame);
            break;
        case DOSMNT_OP_DELETE:
            process_delete(frame);
            break;
        case DOSMNT_OP_BYE:
            reset_active_file();
            send_status(frame->opcode, frame->seq, DOSMNT_STATUS_OK, NULL, 0);
            break;
        default: {
            send_status(frame->opcode, frame->seq, DOSMNT_STATUS_UNSUPPORTED, NULL, 0);
            break;
        }
    }
}

int main(int argc, char **argv) {
    if (!parse_command_line(argc, argv)) {
        return 1;
    }

    init_trace_log();

    printf("DOSMNT resident server starting (Ctrl+Break to exit)\r\n");
    printf("Press 'T' to toggle trace output.\r\n");
    if (g_trace_file != NULL) {
        printf("Trace log file: %s\r\n", TRACE_LOG_NAME);
    }

    serial_init(g_serial_port, g_serial_baud);

    while (g_keep_running) {
        if (!read_frame(&g_frame)) {
            continue;
        }
        process_frame(&g_frame);
    }

    printf("\r\nDOSMNT server stopped.\r\n");
    reset_active_file();
    close_trace_log();
    return 0;
}
static void reset_active_file(void) {
    if (g_active_file != NULL) {
        fclose(g_active_file);
        g_active_file = NULL;
        g_active_path[0] = '\0';
    }
    g_active_mode = ACTIVE_MODE_NONE;
    g_active_size = 0;
}

static int parse_command_line(int argc, char **argv) {
    int i;

    g_serial_port = SERIAL_DEFAULT_PORT;
    g_serial_baud = SERIAL_DEFAULT_BAUD;

    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        const char *value;
        char option;

        if (arg == NULL || arg[0] == '\0') {
            continue;
        }
        if (arg[0] != '-' && arg[0] != '/') {
            printf("Unknown argument: %s\r\n", arg);
            print_usage(argv[0]);
            return 0;
        }

        option = (char)toupper((unsigned char)arg[1]);
        if (option == '?' || option == 'H') {
            print_usage(argv[0]);
            return 0;
        }

        if (arg[2] != '\0') {
            value = &arg[2];
        } else {
            if (i + 1 >= argc) {
                printf("Missing value for -%c\r\n", option);
                print_usage(argv[0]);
                return 0;
            }
            value = argv[++i];
        }

        switch (option) {
            case 'B':
                if (!parse_baud(value, &g_serial_baud)) {
                    printf("Invalid baud rate: %s\r\n", value);
                    print_usage(argv[0]);
                    return 0;
                }
                break;
            case 'C':
                if (!parse_com_port(value, &g_serial_port)) {
                    printf("Invalid COM port: %s\r\n", value);
                    print_usage(argv[0]);
                    return 0;
                }
                break;
            default:
                printf("Unknown option: %s\r\n", arg);
                print_usage(argv[0]);
                return 0;
        }
    }

    printf("Serial settings: port 0x%X (%lu baud)\r\n",
           g_serial_port, (unsigned long)g_serial_baud);
    return 1;
}

static int parse_baud(const char *value, uint32_t *out) {
    char *end = NULL;
    unsigned long rate;

    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    rate = strtoul(value, &end, 10);
    if (end == NULL || *end != '\0' || rate == 0UL) {
        return 0;
    }

    *out = (uint32_t)rate;
    return 1;
}

static int parse_com_port(const char *value, uint16_t *out) {
    static const uint16_t com_map[COM_MAX + 1] = {
        0, 0x3F8, 0x2F8, 0x3E8, 0x2E8
    };
    const char *digits = value;
    char *end = NULL;
    long number;

    if (value == NULL || value[0] == '\0') {
        return 0;
    }

    if ((value[0] == 'C' || value[0] == 'c') &&
        (value[1] == 'O' || value[1] == 'o') &&
        (value[2] == 'M' || value[2] == 'm')) {
        digits = &value[3];
    }

    number = strtol(digits, &end, 10);
    if (end == NULL || *end != '\0') {
        return 0;
    }

    if (number < 1 || number > COM_MAX) {
        return 0;
    }

    *out = com_map[number];
    return 1;
}

static void print_usage(const char *prog_name) {
    const char *name = (prog_name != NULL && prog_name[0] != '\0') ? prog_name : "DOSSRV";
    printf("Usage: %s [-B baud] [-C COMx]\r\n", name);
    printf("  -B baud   Serial speed in bits per second (default %lu)\r\n", (unsigned long)SERIAL_DEFAULT_BAUD);
    printf("  -C COMx   Serial port (COM1-COM4)\r\n");
}
