#pragma once
#include <stddef.h>

size_t kstrlen(const char* s);
int kstrcmp(const char* a, const char* b);
void kstrcpy(char* dst, const char* src);
bool kstartswith(const char* s, const char* prefix);
