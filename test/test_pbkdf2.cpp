#include "../src/crypto/pbkdf2.h"
#include <cstdio>
#include <cstring>

static void to_hex(const uint8_t* d, size_t n, char* out) {
    static const char* h = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[i*2] = h[d[i]>>4]; out[i*2+1] = h[d[i]&0xf]; }
    out[n*2] = 0;
}

static int check(const char* label, const uint8_t* out, size_t n, const char* expect) {
    char hex[128];
    to_hex(out, n, hex);
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

    pbkdf2_hmac_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 1, out, 32);
    fails += check("iter1", out, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

    pbkdf2_hmac_sha256((const uint8_t*)"password", 8, (const uint8_t*)"salt", 4, 2, out, 32);
    fails += check("iter2", out, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");

    pbkdf2_hmac_sha256((const uint8_t*)"PenLockTest123", 14, (const uint8_t*)"somesalt16bytes!", 16, 1000, out, 32);
    fails += check("iter1000", out, 32, "e753e6d219eda78bdafd2559a4f43c929b7fbf975a03827a56d04cdae6ed533e");

    printf(fails == 0 ? "\nALL PASS\n" : "\nSOME FAILED (%d)\n", fails);
    return fails;
}
