#include "serial.h"
#include "io.h"
#include <stddef.h>

#define COM1 0x3F8

void serial_init() {
    outb(COM1 + 1, 0x00);    /* disable interrupts */
    outb(COM1 + 3, 0x80);    /* enable DLAB (set baud rate divisor) */
    outb(COM1 + 0, 0x03);    /* divisor low byte: 3 -> 38400 baud */
    outb(COM1 + 1, 0x00);    /* divisor high byte */
    outb(COM1 + 3, 0x03);    /* 8 bits, no parity, one stop bit */
    outb(COM1 + 2, 0xC7);    /* enable FIFO, clear, 14-byte threshold */
    outb(COM1 + 4, 0x0B);    /* IRQs enabled, RTS/DSR set */
}

static int serial_tx_empty() {
    return inb(COM1 + 5) & 0x20;
}

void serial_write_char(char c) {
    while (!serial_tx_empty());
    if (c == '\n') {
        while (!serial_tx_empty());
        outb(COM1, '\r');
    }
    outb(COM1, c);
}

void serial_write(const char* str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        serial_write_char(str[i]);
    }
}

static int serial_rx_ready() {
    return inb(COM1 + 5) & 0x01;
}

bool serial_poll(char* c) {
    if (!serial_rx_ready()) return false;
    char in = (char)inb(COM1);
    if (in == '\r') in = '\n';
    *c = in;
    return true;
}
