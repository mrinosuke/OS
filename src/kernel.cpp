#include "vga.h"
#include "gdt.h"
#include "idt.h"
#include "keyboard.h"
#include "kstring.h"
#include "serial.h"
#include <stdint.h>

#define CMD_BUF_SIZE 256

static void print_prompt() {
    term.setColor(VGA_LCYAN, VGA_BLACK);
    term.write("myos> ");
    term.setColor(VGA_LGREEN, VGA_BLACK);
}

static void cmd_help() {
    term.writeLine("Available commands:");
    term.writeLine("  help    - show this help message");
    term.writeLine("  clear   - clear the screen");
    term.writeLine("  echo X  - print X back to the screen");
    term.writeLine("  about   - about this OS");
    term.writeLine("  reboot  - reboot the machine");
}

static void cmd_about() {
    term.writeLine("MyOS - a tiny hobby x86 kernel written in C++.");
    term.writeLine("Boots via GRUB Multiboot, runs in 32-bit protected mode.");
}

static void reboot() {
    uint8_t good = 0x02;
    while (good & 0x02) {
        good = 0; /* placeholder read replaced below */
        asm volatile ("inb $0x64, %0" : "=a"(good));
    }
    asm volatile ("outb %0, $0x64" : : "a"((uint8_t)0xFE));
    for (;;) asm volatile ("hlt");
}

static void handle_command(char* cmd) {
    if (kstrlen(cmd) == 0) return;

    if (kstrcmp(cmd, "help") == 0) {
        cmd_help();
    } else if (kstrcmp(cmd, "clear") == 0) {
        term.clear();
    } else if (kstrcmp(cmd, "about") == 0) {
        cmd_about();
    } else if (kstrcmp(cmd, "reboot") == 0) {
        term.writeLine("Rebooting...");
        reboot();
    } else if (kstartswith(cmd, "echo ")) {
        term.writeLine(cmd + 5);
    } else if (kstrcmp(cmd, "echo") == 0) {
        term.writeLine("");
    } else {
        term.setColor(VGA_LRED, VGA_BLACK);
        term.write("Unknown command: ");
        term.writeLine(cmd);
        term.setColor(VGA_LGREEN, VGA_BLACK);
    }
}

static void shell_loop() {
    char buf[CMD_BUF_SIZE];
    size_t len;

    for (;;) {
        print_prompt();
        len = 0;
        buf[0] = '\0';

        for (;;) {
            char c = keyboard_getchar();

            if (c == '\n') {
                term.putChar('\n');
                buf[len] = '\0';
                break;
            } else if (c == '\b') {
                if (len > 0) {
                    len--;
                    term.putChar('\b');
                }
            } else if (len < CMD_BUF_SIZE - 1) {
                buf[len++] = c;
                term.putChar(c);
            }
        }

        handle_command(buf);
    }
}

extern "C" void kernel_main(uint32_t magic, uint32_t /*mb_info*/) {
    serial_init();
    gdt_init();
    idt_init();
    keyboard_init();
    asm volatile ("sti"); /* enable interrupts */

    term.init();
    term.setColor(VGA_YELLOW, VGA_BLACK);
    term.writeLine("=======================================");
    term.writeLine("   MyOS booted successfully! (C++ kernel)");
    term.writeLine("=======================================");
    term.setColor(VGA_LGREEN, VGA_BLACK);

    if (magic != 0x2BADB002) {
        term.setColor(VGA_LRED, VGA_BLACK);
        term.writeLine("Warning: not loaded by a Multiboot-compliant bootloader.");
        term.setColor(VGA_LGREEN, VGA_BLACK);
    }

    term.writeLine("Type 'help' for a list of commands.");
    term.writeLine("");

    shell_loop();
}
