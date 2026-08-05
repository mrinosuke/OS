#include "keyboard.h"
#include "idt.h"
#include "io.h"

#define KBD_BUF_SIZE 256
static char kbd_buffer[KBD_BUF_SIZE];
static volatile int kbd_head = 0;
static volatile int kbd_tail = 0;
static bool shift_pressed = false;

/* US QWERTY scancode set 1 -> ASCII (lowercase) */
static const char scancode_ascii[128] = {
    0, 27, '1','2','3','4','5','6','7','8','9','0','-','=','\b',
    '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n',
    0, 'a','s','d','f','g','h','j','k','l',';','\'','`',
    0, '\\','z','x','c','v','b','n','m',',','.','/', 0,
    '*', 0, ' ', 0,
};

static const char scancode_ascii_shift[128] = {
    0, 27, '!','@','#','$','%','^','&','*','(',')','_','+','\b',
    '\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n',
    0, 'A','S','D','F','G','H','J','K','L',':','"','~',
    0, '|','Z','X','C','V','B','N','M','<','>','?', 0,
    '*', 0, ' ', 0,
};

static void kbd_push(char c) {
    int next = (kbd_head + 1) % KBD_BUF_SIZE;
    if (next != kbd_tail) { /* drop char if buffer full */
        kbd_buffer[kbd_head] = c;
        kbd_head = next;
    }
}

static void keyboard_callback(Registers*) {
    uint8_t scancode = inb(0x60);

    if (scancode == 0x2A || scancode == 0x36) { shift_pressed = true; return; }
    if (scancode == 0xAA || scancode == 0xB6) { shift_pressed = false; return; }

    if (scancode & 0x80) return; /* key release, ignore otherwise */

    if (scancode < 128) {
        char c = shift_pressed ? scancode_ascii_shift[scancode] : scancode_ascii[scancode];
        if (c) kbd_push(c);
    }
}

void keyboard_init() {
    register_interrupt_handler(33, keyboard_callback); /* IRQ1 -> remapped to 33 */
}

bool keyboard_poll(char* c) {
    if (kbd_tail == kbd_head) return false;
    *c = kbd_buffer[kbd_tail];
    kbd_tail = (kbd_tail + 1) % KBD_BUF_SIZE;
    return true;
}

char keyboard_getchar() {
    char c;
    while (!keyboard_poll(&c)) {
        asm volatile ("hlt"); /* sleep until next interrupt */
    }
    return c;
}
