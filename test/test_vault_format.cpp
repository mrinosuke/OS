#include "../src/vault/vault_format.h"
#include <cstdio>

int main() {
    VaultMetadata m;
    m.security_level = SecurityLevel::High;
    m.pbkdf2_iterations = 300000;
    m.pw_salt = std::vector<uint8_t>(16, 0xAB);
    m.pw_wrap_iv = std::vector<uint8_t>(16, 0xCD);
    m.pw_wrapped_key = std::vector<uint8_t>(48, 0xEF);
    m.rk_salt = std::vector<uint8_t>(16, 0x11);
    m.rk_wrap_iv = std::vector<uint8_t>(16, 0x22);
    m.rk_wrapped_key = std::vector<uint8_t>(48, 0x33);
    m.failed_attempts = 2;
    m.lockout_until_unix = 1234567890ULL;

    auto bytes = serialize_metadata(m);
    printf("serialized size: %zu bytes\n", bytes.size());

    if (!looks_like_vault(bytes)) { printf("FAIL: magic not detected\n"); return 1; }

    auto m2 = deserialize_metadata(bytes);
    bool ok = m2.security_level == m.security_level &&
              m2.pbkdf2_iterations == m.pbkdf2_iterations &&
              m2.pw_salt == m.pw_salt &&
              m2.pw_wrap_iv == m.pw_wrap_iv &&
              m2.pw_wrapped_key == m.pw_wrapped_key &&
              m2.rk_salt == m.rk_salt &&
              m2.rk_wrap_iv == m.rk_wrap_iv &&
              m2.rk_wrapped_key == m.rk_wrapped_key &&
              m2.failed_attempts == m.failed_attempts &&
              m2.lockout_until_unix == m.lockout_until_unix;

    printf(ok ? "ROUNDTRIP OK\n" : "ROUNDTRIP FAIL\n");

    // Test garbage data is rejected
    std::vector<uint8_t> garbage(300, 0x99);
    bool rejected = !looks_like_vault(garbage);
    printf(rejected ? "GARBAGE_REJECTED OK\n" : "GARBAGE_REJECTED FAIL\n");

    return ok && rejected ? 0 : 1;
}
