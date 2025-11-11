#include "dos_serial.h"

#include <dos.h>
#include <stdint.h>
#include <conio.h>

static uint16_t g_base_port = 0x3F8;

void serial_init(uint16_t base_port, uint32_t baud) {
    uint16_t divisor;

    if (baud == 0) {
        baud = 9600;
    }

    g_base_port = base_port ? base_port : 0x3F8;
    divisor = (uint16_t)(115200UL / baud);

    outp(g_base_port + 1, 0x00);           /* Disable interrupts */
    outp(g_base_port + 3, 0x80);           /* Enable DLAB */
    outp(g_base_port + 0, (uint8_t)(divisor & 0xFF));
    outp(g_base_port + 1, (uint8_t)(divisor >> 8));
    outp(g_base_port + 3, 0x03);           /* 8N1 */
    outp(g_base_port + 2, 0xC7);           /* Enable FIFO, clear, 14-byte threshold */
    outp(g_base_port + 4, 0x0B);           /* IRQs enabled, RTS/DSR set */
}

int serial_has_byte(void) {
    return (inp(g_base_port + 5) & 0x01) != 0;
}

uint8_t serial_read_byte(void) {
    while (!serial_has_byte()) {
        /* busy wait */
    }
    return (uint8_t)inp(g_base_port + 0);
}

void serial_write_byte(uint8_t value) {
    while ((inp(g_base_port + 5) & 0x20) == 0) {
        /* busy wait for THR empty */
    }
    outp(g_base_port + 0, value);
}
