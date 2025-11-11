#define _GNU_SOURCE

#include "link.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define SERIAL_DEFAULT_FLAGS (CLOCAL | CREAD | CS8)

static int configure_serial(int fd, int baud);
static speed_t baud_to_flag(int baud);
static uint8_t compute_checksum(uint8_t opcode, uint8_t seq, uint16_t length, const uint8_t *payload);
static int write_all(int fd, const uint8_t *buf, size_t len);
static int read_byte(int fd, uint8_t *byte);
static int read_frame_payload(int fd, uint8_t expected_opcode, uint8_t expected_seq,
                              uint8_t *status, uint8_t *reply_buf, uint16_t *reply_len);
static void tracef(const struct dosmnt_client *client, const char *label,
                   uint8_t opcode, uint16_t length);

int dosmnt_client_open(struct dosmnt_client *client, const char *device, int baud) {
    int fd;

    memset(client, 0, sizeof(*client));

    fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        return -errno;
    }

    if (configure_serial(fd, baud) != 0) {
        int err = -errno;
        close(fd);
        return err ? err : -EINVAL;
    }

    client->fd = fd;
    client->next_seq = 1;
    pthread_mutex_init(&client->lock, NULL);
    client->debug = 0;
    return 0;
}

void dosmnt_client_close(struct dosmnt_client *client) {
    if (client->fd > 0) {
        close(client->fd);
        client->fd = -1;
    }
    pthread_mutex_destroy(&client->lock);
}

void dosmnt_client_set_debug(struct dosmnt_client *client, int enable) {
    if (client == NULL) {
        return;
    }
    client->debug = enable ? 1 : 0;
}

int dosmnt_client_request(struct dosmnt_client *client,
                          uint8_t opcode,
                          const uint8_t *payload,
                          uint16_t payload_len,
                          uint8_t *status,
                          uint8_t *reply_buf,
                          uint16_t *reply_len) {
    uint8_t header[6];
    uint8_t seq;
    int rc;

    if (payload_len > DOSMNT_MAX_PAYLOAD) {
        return -EMSGSIZE;
    }

    pthread_mutex_lock(&client->lock);

    seq = client->next_seq++;
    if (client->next_seq == 0) {
        client->next_seq = 1;
    }

    header[0] = DOSMNT_PREAMBLE_A;
    header[1] = DOSMNT_PREAMBLE_B;
    header[2] = opcode;
    header[3] = seq;
    header[4] = (uint8_t)(payload_len & 0xFF);
    header[5] = (uint8_t)(payload_len >> 8);

    rc = write_all(client->fd, header, sizeof(header));
    if (rc != 0) {
        pthread_mutex_unlock(&client->lock);
        return rc;
    }

    if (payload_len > 0) {
        rc = write_all(client->fd, payload, payload_len);
        if (rc != 0) {
            pthread_mutex_unlock(&client->lock);
            return rc;
        }
    }

    {
        uint8_t checksum = compute_checksum(opcode, seq, payload_len, payload);
        rc = write_all(client->fd, &checksum, 1);
        if (rc != 0) {
            pthread_mutex_unlock(&client->lock);
            return rc;
        }
    }

    tracef(client, "TX", opcode, payload_len);
    rc = read_frame_payload(client->fd, dosmnt_response_opcode(opcode), seq,
                            status, reply_buf, reply_len);

    pthread_mutex_unlock(&client->lock);

    if (rc == 0) {
        uint16_t len = (reply_len != NULL) ? *reply_len : 0;
        tracef(client, "RX", dosmnt_response_opcode(opcode), len);
    }
    return rc;
}

static int configure_serial(int fd, int baud) {
    struct termios tio;
    speed_t speed_flag = baud_to_flag(baud);

    if (speed_flag == (speed_t)0) {
        errno = EINVAL;
        return -1;
    }

    if (tcgetattr(fd, &tio) != 0) {
        return -1;
    }

    cfmakeraw(&tio);
    tio.c_cflag = SERIAL_DEFAULT_FLAGS;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;

    cfsetispeed(&tio, speed_flag);
    cfsetospeed(&tio, speed_flag);

    if (tcsetattr(fd, TCSANOW, &tio) != 0) {
        return -1;
    }

    tcflush(fd, TCIOFLUSH);
    return 0;
}

static speed_t baud_to_flag(int baud) {
    switch (baud) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
        default:
            return (speed_t)0;
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

static int write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t written = write(fd, buf, len);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        buf += written;
        len -= (size_t)written;
    }
    return 0;
}

static int read_byte(int fd, uint8_t *byte) {
    ssize_t ret;

    do {
        ret = read(fd, byte, 1);
    } while (ret < 0 && errno == EINTR);

    if (ret <= 0) {
        return (ret == 0) ? -EIO : -errno;
    }

    return 0;
}

static int read_frame_payload(int fd, uint8_t expected_opcode, uint8_t expected_seq,
                              uint8_t *status, uint8_t *reply_buf, uint16_t *reply_len) {
    uint8_t header_byte;
    uint8_t opcode = 0;
    uint8_t seq = 0;
    uint16_t length = 0;
    uint8_t checksum;
    int rc;
    uint16_t i;

    for (;;) {
        rc = read_byte(fd, &header_byte);
        if (rc != 0) {
            return rc;
        }
        if (header_byte != DOSMNT_PREAMBLE_A) {
            continue;
        }

        rc = read_byte(fd, &header_byte);
        if (rc != 0) {
            return rc;
        }
        if (header_byte != DOSMNT_PREAMBLE_B) {
            continue;
        }

        rc = read_byte(fd, &opcode);
        if (rc != 0) {
            return rc;
        }

        rc = read_byte(fd, &seq);
        if (rc != 0) {
            return rc;
        }

        rc = read_byte(fd, &header_byte);
        if (rc != 0) {
            return rc;
        }
        length = header_byte;

        rc = read_byte(fd, &header_byte);
        if (rc != 0) {
            return rc;
        }
        length |= ((uint16_t)header_byte << 8);

        if (length > DOSMNT_MAX_PAYLOAD) {
            /* consume and discard */
            for (i = 0; i < length + 1; ++i) {
                rc = read_byte(fd, &header_byte);
                if (rc != 0) {
                    return rc;
                }
            }
            continue;
        }

        for (i = 0; i < length; ++i) {
            rc = read_byte(fd, &reply_buf[i]);
            if (rc != 0) {
                return rc;
            }
        }

        rc = read_byte(fd, &checksum);
        if (rc != 0) {
            return rc;
        }

        if (checksum != compute_checksum(opcode, seq, length, reply_buf)) {
            continue;
        }

        if (opcode != expected_opcode || seq != expected_seq) {
            /* not for us, continue scanning */
            continue;
        }

        if (reply_len != NULL) {
            *reply_len = length;
        }

        if (length == 0) {
            *status = DOSMNT_STATUS_INTERNAL;
        } else {
            *status = reply_buf[0];
        }
        return 0;
    }
}

static void tracef(const struct dosmnt_client *client, const char *label,
                   uint8_t opcode, uint16_t length) {
    if (!client || !client->debug) {
        return;
    }
    fprintf(stderr, "[dosmnt] %s opcode=0x%02X len=%u\n", label, opcode, length);
}
