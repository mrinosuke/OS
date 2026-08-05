#pragma once
#include <stdint.h>

void keyboard_init();

/* Returns next char from the ring buffer, blocks (busy-wait) until one is available */
char keyboard_getchar();

/* Non-blocking: returns true and fills *c if a char is ready */
bool keyboard_poll(char* c);
