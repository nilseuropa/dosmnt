#define FUSE_USE_VERSION 35

#include <ctype.h>
#include <errno.h>
#include <fuse3/fuse.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>

#include "dosmnt/protocol.h"
#include "link.h"

struct cli_options {
    const char *device;
    const char *mountpoint;
    int baud;
    char drive;
    int debug;
};

struct dosmnt_context {
    struct dosmnt_client client;
    char drive_prefix[3];
    char volume_label[33];
    int debug;
};

static int parse_options(int argc, char **argv, struct cli_options *out,
                         int *fuse_argc, char ***fuse_argv);
static int perform_handshake(struct dosmnt_context *ctx);
static void build_remote_path(const struct dosmnt_context *ctx, const char *fuse_path, char *dst);
static mode_t attrs_to_mode(uint8_t attrs);
static time_t dos_time_to_unix(uint32_t packed);
static int status_to_errno(uint8_t status);
static void trace_msg(const struct dosmnt_context *ctx, const char *fmt, ...);

static int dosmnt_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi);
static int dosmnt_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi,
                          enum fuse_readdir_flags flags);
static int dosmnt_open(const char *path, struct fuse_file_info *fi);
static int dosmnt_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi);
static int dosmnt_statfs(const char *path, struct statvfs *stbuf);

static const struct fuse_operations dosmnt_ops = {
    .getattr = dosmnt_getattr,
    .readdir = dosmnt_readdir,
    .open = dosmnt_open,
    .read = dosmnt_read,
    .release = NULL,
    .statfs = dosmnt_statfs,
};

int main(int argc, char **argv) {
    struct cli_options opts = {
        .device = "/dev/ttyS0",
        .mountpoint = NULL,
        .baud = 115200,
        .drive = 0,
        .debug = 0
    };
    struct dosmnt_context ctx;
    int fuse_argc = 0;
    char **fuse_argv = NULL;
    int rc;

    rc = parse_options(argc, argv, &opts, &fuse_argc, &fuse_argv);
    if (rc != 0) {
        return rc;
    }

    memset(&ctx, 0, sizeof(ctx));
    if (opts.drive) {
        ctx.drive_prefix[0] = (char)toupper((unsigned char)opts.drive);
        ctx.drive_prefix[1] = ':';
        ctx.drive_prefix[2] = '\0';
    }
    ctx.debug = opts.debug;

    rc = dosmnt_client_open(&ctx.client, opts.device, opts.baud);
    if (rc != 0) {
        fprintf(stderr, "Failed to open %s: %s\n", opts.device, strerror(-rc));
        return 1;
    }

    dosmnt_client_set_debug(&ctx.client, ctx.debug);

    rc = perform_handshake(&ctx);
    if (rc != 0) {
        fprintf(stderr, "DOS handshake failed: %s\n", strerror(-rc));
        dosmnt_client_close(&ctx.client);
        return 1;
    }

    printf("Connected to DOS volume '%s'\n", ctx.volume_label);
    if (ctx.debug) {
        fprintf(stderr, "[dosmnt] debug trace enabled\n");
    }

    rc = fuse_main(fuse_argc, fuse_argv, &dosmnt_ops, &ctx);
    if (fuse_argv) {
        for (int i = 0; i < fuse_argc; ++i) {
            free(fuse_argv[i]);
        }
        free(fuse_argv);
    }
    dosmnt_client_close(&ctx.client);
    return rc;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [options] --mount PATH [-- FUSE options]\n"
            "  --device PATH       Serial TTY (default /dev/ttyS0)\n"
            "  --mount PATH        Mount point (required)\n"
            "  --baud RATE         Baud rate (default 115200)\n"
            "  --drive LETTER      DOS drive letter to pin requests\n"
            "  --debug             Enable verbose tracing\n"
            "Example: %s --device /dev/ttyUSB0 --mount /mnt/dos --drive C -- -f -o allow_other\n",
            prog, prog);
}

static int parse_options(int argc, char **argv, struct cli_options *out,
                         int *fuse_argc, char ***fuse_argv) {
    static const struct option long_opts[] = {
        {"device", required_argument, 0, 'd'},
        {"mount", required_argument, 0, 'm'},
        {"baud", required_argument, 0, 'b'},
        {"drive", required_argument, 0, 'r'},
        {"debug", no_argument, 0, 'g'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int idx = 0;
    int fuse_start = -1;
    char **args = calloc((size_t)argc + 3, sizeof(char *));
    if (!args) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }
    args[idx++] = strdup(argv[0]);

    while ((opt = getopt_long(argc, argv, "d:m:b:r:gh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'd':
                out->device = optarg;
                break;
            case 'm':
                out->mountpoint = optarg;
                break;
            case 'b':
                out->baud = atoi(optarg);
                break;
            case 'r':
                out->drive = optarg[0];
                break;
            case 'g':
                out->debug = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
                goto fail;
        }
    }

    if (optind < argc && strcmp(argv[optind], "--") == 0) {
        fuse_start = optind + 1;
    }

    if (!out->mountpoint) {
        usage(argv[0]);
        goto fail;
    }

    args[idx++] = strdup(out->mountpoint);

    if (fuse_start >= 0) {
        for (int i = fuse_start; i < argc; ++i) {
            args[idx++] = strdup(argv[i]);
        }
    } else {
        args[idx++] = strdup("-f");
    }

    args[idx] = NULL;
    *fuse_argc = idx;
    *fuse_argv = args;
    return 0;

fail:
    for (int i = 0; i < idx; ++i) {
        free(args[i]);
    }
    free(args);
    return -1;
}

static int perform_handshake(struct dosmnt_context *ctx) {
    uint8_t payload = 1;
    uint8_t status = 0;
    uint8_t response[DOSMNT_MAX_PAYLOAD];
    uint16_t resp_len = sizeof(response);
    int rc;

    rc = dosmnt_client_request(&ctx->client, DOSMNT_OP_HELLO, &payload, 1,
                               &status, response, &resp_len);
    if (rc != 0) {
        return rc;
    }

    if (status != DOSMNT_STATUS_OK || resp_len < 36) {
        return -EIO;
    }

    memcpy(ctx->volume_label, response + 4, 32);
    ctx->volume_label[32] = '\0';
    return 0;
}

static void build_remote_path(const struct dosmnt_context *ctx, const char *fuse_path, char *dst) {
    size_t pos = 0;
    const char *src = fuse_path;
    int has_drive = ctx->drive_prefix[0] != '\0';

    if (has_drive) {
        dst[pos++] = ctx->drive_prefix[0];
        dst[pos++] = ctx->drive_prefix[1];
    }

    if (*src == '/') {
        src++;
    }

    if (*src == '\0') {
        if (has_drive) {
            dst[pos++] = '\\';
        } else {
            dst[pos++] = '.';
            dst[pos++] = '\\';
        }
        dst[pos] = '\0';
        return;
    }

    if (has_drive) {
        dst[pos++] = '\\';
    }

    while (*src && pos < DOSMNT_MAX_PATH - 1) {
        char ch = *src++;
        if (ch == '/') {
            ch = '\\';
        }
        dst[pos++] = (char)toupper((unsigned char)ch);
    }

    dst[pos] = '\0';
}

static mode_t attrs_to_mode(uint8_t attrs) {
    if (attrs & DOS_ATTR_DIRECTORY) {
        return S_IFDIR | 0555;
    }
    return S_IFREG | 0444;
}

static time_t dos_time_to_unix(uint32_t packed) {
    struct tm tmv;
    uint16_t date = (uint16_t)(packed >> 16);
    uint16_t time = (uint16_t)(packed & 0xFFFF);

    if (date == 0) {
        return 0;
    }

    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_year = ((date >> 9) & 0x7F) + 80;
    tmv.tm_mon = ((date >> 5) & 0x0F) - 1;
    tmv.tm_mday = date & 0x1F;
    tmv.tm_hour = (time >> 11) & 0x1F;
    tmv.tm_min = (time >> 5) & 0x3F;
    tmv.tm_sec = (time & 0x1F) * 2;
    tmv.tm_isdst = -1;

    return mktime(&tmv);
}

static int status_to_errno(uint8_t status) {
    switch (status) {
        case DOSMNT_STATUS_OK:
            return 0;
        case DOSMNT_STATUS_NOT_FOUND:
            return -ENOENT;
        case DOSMNT_STATUS_MALFORMED:
            return -EBADMSG;
        case DOSMNT_STATUS_UNSUPPORTED:
            return -ENOTSUP;
        case DOSMNT_STATUS_IO_ERROR:
        case DOSMNT_STATUS_INTERNAL:
            return -EIO;
        case DOSMNT_STATUS_NO_SPACE:
            return -EOVERFLOW;
        case DOSMNT_STATUS_TOO_LARGE:
            return -EFBIG;
        default:
            return -EIO;
    }
}

static int dosmnt_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    struct dosmnt_context *ctx = (struct dosmnt_context *)fuse_get_context()->private_data;
    char remote[DOSMNT_MAX_PATH];
    uint8_t payload[DOSMNT_MAX_PATH];
    uint16_t payload_len;
    uint8_t status = 0;
    uint8_t response[DOSMNT_MAX_PAYLOAD];
    uint16_t resp_len = sizeof(response);
    struct dosmnt_stat st;
    int rc;

    (void)fi;

    trace_msg(ctx, "getattr %s", path);
    build_remote_path(ctx, path, remote);
    payload_len = (uint16_t)(strlen(remote) + 1);
    memcpy(payload, remote, payload_len);

    rc = dosmnt_client_request(&ctx->client, DOSMNT_OP_STAT, payload, payload_len,
                               &status, response, &resp_len);
    if (rc != 0) {
        return rc;
    }
    if (status != DOSMNT_STATUS_OK || resp_len < 1 + sizeof(struct dosmnt_stat)) {
        return status_to_errno(status);
    }

    memcpy(&st, response + 1, sizeof(st));
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_mode = attrs_to_mode(st.attributes);
    stbuf->st_nlink = 1;
    stbuf->st_size = st.size;
    stbuf->st_mtime = stbuf->st_atime = stbuf->st_ctime = dos_time_to_unix(st.write_time);

    trace_msg(ctx, "getattr %s -> size=%lu attrs=0x%02X", path, (unsigned long)st.size, st.attributes);

    if (S_ISDIR(stbuf->st_mode)) {
        stbuf->st_size = 4096;
    }

    return 0;
}

static int dosmnt_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi,
                          enum fuse_readdir_flags flags) {
    struct dosmnt_context *ctx = (struct dosmnt_context *)fuse_get_context()->private_data;
    char remote[DOSMNT_MAX_PATH];
    uint8_t payload[DOSMNT_MAX_PATH];
    uint8_t response[DOSMNT_MAX_PAYLOAD];
    uint8_t status = 0;
    uint16_t payload_len;
    uint16_t resp_len = sizeof(response);
    size_t pos;
    int rc;

    (void)offset;
    (void)fi;
    (void)flags;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    trace_msg(ctx, "readdir %s", path);
    build_remote_path(ctx, path, remote);
    payload_len = (uint16_t)(strlen(remote) + 1);
    memcpy(payload, remote, payload_len);

    rc = dosmnt_client_request(&ctx->client, DOSMNT_OP_LIST, payload, payload_len,
                               &status, response, &resp_len);
    if (rc != 0) {
        return rc;
    }
    if (status != DOSMNT_STATUS_OK) {
        return status_to_errno(status);
    }

    pos = 1;
    while (pos + sizeof(struct dosmnt_dirent) <= resp_len) {
        const struct dosmnt_dirent *entry = (const struct dosmnt_dirent *)(response + pos);
        char name[256];
        struct stat st;

        pos += sizeof(*entry);
        if (pos + entry->name_len > resp_len || entry->name_len >= sizeof(name)) {
            break;
        }

        memcpy(name, response + pos, entry->name_len);
        name[entry->name_len] = '\0';
        pos += entry->name_len;

        memset(&st, 0, sizeof(st));
        st.st_mode = (entry->type == DOSMNT_DIRENT_DIR) ? (S_IFDIR | 0555) : (S_IFREG | 0444);
        st.st_nlink = 1;
        st.st_size = entry->size;
        st.st_mtime = st.st_atime = st.st_ctime = dos_time_to_unix(entry->write_time);

        if (filler(buf, name, &st, 0, 0) != 0) {
            break;
        }
    }

    return 0;
}

static int dosmnt_open(const char *path, struct fuse_file_info *fi) {
    struct dosmnt_context *ctx = (struct dosmnt_context *)fuse_get_context()->private_data;
    struct stat st;
    int rc = dosmnt_getattr(path, &st, fi);
    if (rc != 0) {
        return rc;
    }

    trace_msg(ctx, "open %s", path);
    if (S_ISDIR(st.st_mode)) {
        return -EISDIR;
    }

    return 0;
}

static int dosmnt_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi) {
    struct dosmnt_context *ctx = (struct dosmnt_context *)fuse_get_context()->private_data;
    char remote[DOSMNT_MAX_PATH];
    uint8_t payload[6 + DOSMNT_MAX_PATH];
    uint8_t response[DOSMNT_MAX_PAYLOAD];
    uint8_t status;
    size_t remaining = size;
    size_t total_read = 0;
    int rc;

    (void)fi;

    trace_msg(ctx, "read %s off=%lld size=%zu", path, (long long)offset, size);
    if (offset < 0 || offset > 0xFFFFFFFFL) {
        return -EOVERFLOW;
    }

    build_remote_path(ctx, path, remote);

    while (remaining > 0) {
        size_t chunk = remaining;
        uint16_t payload_len;
        uint16_t resp_len = sizeof(response);

        if (chunk > DOSMNT_MAX_DATA) {
            chunk = DOSMNT_MAX_DATA;
        }

        payload[0] = (uint8_t)(offset & 0xFF);
        payload[1] = (uint8_t)(((uint64_t)offset >> 8) & 0xFF);
        payload[2] = (uint8_t)(((uint64_t)offset >> 16) & 0xFF);
        payload[3] = (uint8_t)(((uint64_t)offset >> 24) & 0xFF);
        payload[4] = (uint8_t)(chunk & 0xFF);
        payload[5] = (uint8_t)((chunk >> 8) & 0xFF);

        payload_len = (uint16_t)(6 + strlen(remote) + 1);
        memcpy(payload + 6, remote, payload_len - 6);

        rc = dosmnt_client_request(&ctx->client, DOSMNT_OP_READ, payload, payload_len,
                                   &status, response, &resp_len);
        if (rc != 0) {
            return (total_read > 0) ? (int)total_read : rc;
        }
        if (status != DOSMNT_STATUS_OK) {
            return (total_read > 0) ? (int)total_read : status_to_errno(status);
        }
        if (resp_len < 1) {
            return (total_read > 0) ? (int)total_read : -EIO;
        }

        resp_len--; /* skip status byte */
        if (resp_len > chunk) {
            resp_len = chunk;
        }

        memcpy(buf + total_read, response + 1, resp_len);
        total_read += resp_len;
        offset += resp_len;
        remaining -= resp_len;

        if (resp_len < chunk) {
            break; /* EOF */
        }
    }

    return (int)total_read;
}

static int dosmnt_statfs(const char *path, struct statvfs *stbuf) {
    (void)path;
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->f_bsize = 512;
    stbuf->f_frsize = 512;
    stbuf->f_blocks = 0;
    stbuf->f_bfree = 0;
    stbuf->f_bavail = 0;
    stbuf->f_files = 0;
    stbuf->f_ffree = 0;
    stbuf->f_favail = 0;
    stbuf->f_flag = ST_RDONLY | ST_NOSUID;
    stbuf->f_namemax = 12;
    return 0;
}

static void trace_msg(const struct dosmnt_context *ctx, const char *fmt, ...) {
    va_list ap;
    if (!ctx || !ctx->debug) {
        return;
    }
    fprintf(stderr, "[dosmnt] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
