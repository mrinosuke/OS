#include "../src/crypto/sha256.h"
#include <cstdio>
#include <cstring>

static void to_hex(const uint8_t* d, size_t n, char* out) {
    static const char* h = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[i*2] = h[d[i]>>4]; out[i*2+1] = h[d[i]&0xf]; }
    out[n*2] = 0;
}

static int check(const char* label, const uint8_t* out, const char* expect) {
    char hex[65];
    to_hex(out, 32, hex);
    if (strcmp(hex, expect) != 0) {
        printf("FAIL %-10s got=%s\n              exp=%s\n", label, hex, expect);
        return 1;
    }
    printf("OK   %s\n", label);
    return 0;
}

int main() {
    int fails = 0;
    uint8_t out[32];

    SHA256::hash((const uint8_t*)"", 0, out);
    fails += check("empty", out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    SHA256::hash((const uint8_t*)"abc", 3, out);
    fails += check("abc", out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    {
        SHA256 s;
        uint8_t block[1000];
        memset(block, 'a', 1000);
        for (int i = 0; i < 1000; ++i) s.update(block, 1000);
        s.finish(out);
        fails += check("1M-a", out, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    printf(fails == 0 ? "\nALL PASS\n" : "\nSOME FAILED (%d)\n", fails);
    return fails;
}
