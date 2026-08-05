#pragma once
#include <stdint.h>
#include <stddef.h>

enum VgaColor {
    VGA_BLACK = 0, VGA_BLUE = 1, VGA_GREEN = 2, VGA_CYAN = 3,
    VGA_RED = 4, VGA_MAGENTA = 5, VGA_BROWN = 6, VGA_LGRAY = 7,
    VGA_DGRAY = 8, VGA_LBLUE = 9, VGA_LGREEN = 10, VGA_LCYAN = 11,
    VGA_LRED = 12, VGA_LMAGENTA = 13, VGA_YELLOW = 14, VGA_WHITE = 15,
};

class Terminal {
public:
    void init();
    void clear();
    void putChar(char c);
    void write(const char* str);
    void writeLine(const char* str);
    void setColor(VgaColor fg, VgaColor bg);
    void backspace();
    void scroll();

private:
    uint16_t* buffer = (uint16_t*)0xB8000;
    size_t row = 0;
    size_t col = 0;
    uint8_t color;
    void putEntryAt(char c, uint8_t color, size_t x, size_t y);
};

extern Terminal term;
