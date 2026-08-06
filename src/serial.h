#pragma once
#include <stdint.h>

void serial_init();
void serial_write_char(char c);
void serial_write(const char* str);

/* Non-blocking: returns true and fills *c if a byte is ready */
bool serial_poll(char* c);
