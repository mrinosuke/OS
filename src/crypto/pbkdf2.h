// pbkdf2.h - PBKDF2-HMAC-SHA256 password-based key derivation (RFC 8018)
// Part of PenLock. Deliberately slow (high iteration count) to resist
// offline brute-force attacks against a stolen/copied vault.
#pragma once
#include "sha256.h"
#include <cstdint>
#include <cstring>
#include <vector>

// PenLock's default iteration count. ~300k rounds costs a fraction of a
// second on modern hardware for a legitimate unlock, but meaningfully
// slows down an attacker trying many passwords against a stolen drive.
static const uint32_t PENLOCK_PBKDF2_ITERATIONS = 300000;

inline void pbkdf2_hmac_sha256(const uint8_t* password, size_t password_len,
                                const uint8_t* salt, size_t salt_len,
                                uint32_t iterations,
                                uint8_t* out, size_t out_len) {
    const size_t hlen = 32; // SHA256 output size
    size_t blocks_needed = (out_len + hlen - 1) / hlen;

    std::vector<uint8_t> salt_block(salt_len + 4);
    std::memcpy(salt_block.data(), salt, salt_len);

    size_t produced = 0;
    for (uint32_t block_index = 1; block_index <= blocks_needed; ++block_index) {
        salt_block[salt_len + 0] = static_cast<uint8_t>(block_index >> 24);
        salt_block[salt_len + 1] = static_cast<uint8_t>(block_index >> 16);
        salt_block[salt_len + 2] = static_cast<uint8_t>(block_index >> 8);
        salt_block[salt_len + 3] = static_cast<uint8_t>(block_index);

        uint8_t u[32];
        hmac_sha256(password, password_len, salt_block.data(), salt_block.size(), u);
        uint8_t t[32];
        std::memcpy(t, u, 32);

        for (uint32_t i = 1; i < iterations; ++i) {
            uint8_t u_next[32];
            hmac_sha256(password, password_len, u, 32, u_next);
            std::memcpy(u, u_next, 32);
            for (int j = 0; j < 32; ++j) t[j] ^= u[j];
        }

        size_t to_copy = std::min(hlen, out_len - produced);
        std::memcpy(out + produced, t, to_copy);
        produced += to_copy;
    }
}
