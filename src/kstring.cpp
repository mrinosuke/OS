#include "kstring.h"

size_t kstrlen(const char* s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

int kstrcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) { a++; b++; }
    return *(const unsigned char*)a - *(const unsigned char*)b;
}

void kstrcpy(char* dst, const char* src) {
    while ((*dst++ = *src++));
}

bool kstartswith(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s != *prefix) return false;
        s++; prefix++;
    }
    return true;
}
