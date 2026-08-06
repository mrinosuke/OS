#include "vga.h"
#include "serial.h"

static const size_t VGA_WIDTH = 80;
static const size_t VGA_HEIGHT = 25;

Terminal term;

static inline uint8_t vgaEntryColor(VgaColor fg, VgaColor bg) {
    return (uint8_t)fg | (uint8_t)bg << 4;
}

static inline uint16_t vgaEntry(unsigned char c, uint8_t color) {
    return (uint16_t)c | (uint16_t)color << 8;
}

void Terminal::init() {
    row = 0;
    col = 0;
    color = vgaEntryColor(VGA_LGREEN, VGA_BLACK);
    clear();
}

void Terminal::clear() {
    for (size_t y = 0; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            buffer[y * VGA_WIDTH + x] = vgaEntry(' ', color);
        }
    }
    row = 0;
    col = 0;
}

void Terminal::setColor(VgaColor fg, VgaColor bg) {
    color = vgaEntryColor(fg, bg);
}

void Terminal::putEntryAt(char c, uint8_t col_, size_t x, size_t y) {
    buffer[y * VGA_WIDTH + x] = vgaEntry(c, col_);
}

void Terminal::scroll() {
    for (size_t y = 1; y < VGA_HEIGHT; y++) {
        for (size_t x = 0; x < VGA_WIDTH; x++) {
            buffer[(y - 1) * VGA_WIDTH + x] = buffer[y * VGA_WIDTH + x];
        }
    }
    for (size_t x = 0; x < VGA_WIDTH; x++) {
        buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + x] = vgaEntry(' ', color);
    }
    row = VGA_HEIGHT - 1;
}

void Terminal::backspace() {
    if (col == 0) {
        if (row == 0) return;
        row--;
        col = VGA_WIDTH - 1;
    } else {
        col--;
    }
    putEntryAt(' ', color, col, row);
}

void Terminal::putChar(char c) {
    serial_write_char(c);

    if (c == '\n') {
        col = 0;
        row++;
    } else if (c == '\b') {
        backspace();
        return;
    } else {
        putEntryAt(c, color, col, row);
        col++;
        if (col == VGA_WIDTH) {
            col = 0;
            row++;
        }
    }
    if (row == VGA_HEIGHT) {
        scroll();
    }
}

void Terminal::write(const char* str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        putChar(str[i]);
    }
}

void Terminal::writeLine(const char* str) {
    write(str);
    putChar('\n');
}
