#ifndef LINUX_LINK_H
#define LINUX_LINK_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "dosmnt/protocol.h"

struct dosmnt_client {
    int fd;
    uint8_t next_seq;
    pthread_mutex_t lock;
    int debug;
};

int dosmnt_client_open(struct dosmnt_client *client, const char *device, int baud);
void dosmnt_client_close(struct dosmnt_client *client);
void dosmnt_client_set_debug(struct dosmnt_client *client, int enable);
int dosmnt_client_request(struct dosmnt_client *client,
                          uint8_t opcode,
                          const uint8_t *payload,
                          uint16_t payload_len,
                          uint8_t *status,
                          uint8_t *reply_buf,
                          uint16_t *reply_len);

#endif /* LINUX_LINK_H */
