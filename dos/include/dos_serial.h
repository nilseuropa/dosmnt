#ifndef DOS_SERIAL_H
#define DOS_SERIAL_H

#include <stdint.h>

void serial_init(uint16_t base_port, uint32_t baud);
int serial_has_byte(void);
uint8_t serial_read_byte(void);
void serial_write_byte(uint8_t value);

#endif /* DOS_SERIAL_H */
