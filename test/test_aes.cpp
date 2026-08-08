#include "../src/crypto/aes.h"
#include <cstdio>
#include <cstring>

static void to_hex(const uint8_t* d, size_t n, char* out) {
    static const char* h = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[i*2] = h[d[i]>>4]; out[i*2+1] = h[d[i]&0xf]; }
    out[n*2] = 0;
}
static void from_hex(const char* hex, uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        unsigned int b;
        sscanf(hex + i*2, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

int main() {
    uint8_t key[32], pt[16], ct[16], decrypted[16];
    from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 32);
    from_hex("00112233445566778899aabbccddeeff", pt, 16);

    AES256 aes(key);
    aes.encrypt_block(pt, ct);

    char hex[33];
    to_hex(ct, 16, hex);
    printf("ENCRYPT_RESULT:%s\n", hex);

    aes.decrypt_block(ct, decrypted);
    bool roundtrip_ok = memcmp(pt, decrypted, 16) == 0;
    printf("ROUNDTRIP:%s\n", roundtrip_ok ? "OK" : "FAIL");

    // Test CBC mode roundtrip with a longer, non-block-aligned message
    const char* msg = "PenLock secure vault test message, not block aligned!";
    uint8_t iv[16];
    for (int i = 0; i < 16; ++i) iv[i] = (uint8_t)(i * 7 + 3);
    auto enc = aes.cbc_encrypt((const uint8_t*)msg, strlen(msg), iv);
    auto dec = aes.cbc_decrypt(enc.data(), enc.size(), iv);
    bool cbc_ok = dec.size() == strlen(msg) && memcmp(dec.data(), msg, dec.size()) == 0;
    printf("CBC_ROUNDTRIP:%s\n", cbc_ok ? "OK" : "FAIL");

    // Test wrong-key CBC decrypt should fail (bad padding) most of the time
    uint8_t badkey[32];
    memcpy(badkey, key, 32);
    badkey[0] ^= 0xFF;
    AES256 aes_bad(badkey);
    bool threw = false;
    try {
        auto dec2 = aes_bad.cbc_decrypt(enc.data(), enc.size(), iv);
    } catch (const std::exception&) {
        threw = true;
    }
    printf("WRONGKEY_DETECTED:%s\n", threw ? "OK" : "MAYBE(not guaranteed)");

    return 0;
}
