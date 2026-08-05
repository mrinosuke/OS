#include "gdt.h"

struct GdtEntry {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t  base_mid;
    uint8_t  access;
    uint8_t  granularity;
    uint8_t  base_high;
} __attribute__((packed));

struct GdtPtr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

static GdtEntry gdt[5];
static GdtPtr gdtp;

static void gdt_set_gate(int num, uint32_t base, uint32_t limit, uint8_t access, uint8_t gran) {
    gdt[num].base_low    = base & 0xFFFF;
    gdt[num].base_mid    = (base >> 16) & 0xFF;
    gdt[num].base_high   = (base >> 24) & 0xFF;
    gdt[num].limit_low   = limit & 0xFFFF;
    gdt[num].granularity = (limit >> 16) & 0x0F;
    gdt[num].granularity |= gran & 0xF0;
    gdt[num].access      = access;
}

extern "C" void gdt_flush(uint32_t);

void gdt_init() {
    gdtp.limit = (sizeof(GdtEntry) * 5) - 1;
    gdtp.base = (uint32_t)&gdt;

    gdt_set_gate(0, 0, 0, 0, 0);                // null
    gdt_set_gate(1, 0, 0xFFFFFFFF, 0x9A, 0xCF);  // code
    gdt_set_gate(2, 0, 0xFFFFFFFF, 0x92, 0xCF);  // data
    gdt_set_gate(3, 0, 0xFFFFFFFF, 0xFA, 0xCF);  // user code
    gdt_set_gate(4, 0, 0xFFFFFFFF, 0xF2, 0xCF);  // user data

    gdt_flush((uint32_t)&gdtp);
}
