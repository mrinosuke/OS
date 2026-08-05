/* boot.s - Multiboot header + entry point for our OS */

.set ALIGN,    1<<0
.set MEMINFO,  1<<1
.set FLAGS,    ALIGN | MEMINFO
.set MAGIC,    0x1BADB002
.set CHECKSUM, -(MAGIC + FLAGS)

.section .multiboot
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM

/* Stack: 16KB, 16-byte aligned as required by System V ABI */
.section .bss
.align 16
stack_bottom:
.skip 16384
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    mov $stack_top, %esp
    /* multiboot passes magic in eax, info ptr in ebx - push for kernel_main */
    push %ebx
    push %eax

    call kernel_main

    /* If kernel_main ever returns, halt forever */
    cli
1:  hlt
    jmp 1b

.size _start, . - _start
