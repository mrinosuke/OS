// random.h - Cryptographically secure random bytes (Windows BCrypt).
// Part of PenLock. Windows-only (uses Windows CNG API).
#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

inline void secure_random_bytes(uint8_t* out, size_t len) {
    NTSTATUS status = BCryptGenRandom(
        NULL, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status != 0 /* STATUS_SUCCESS */) {
        throw std::runtime_error("secure_random_bytes: BCryptGenRandom failed");
    }
}
#else
// Non-Windows fallback (used only for local unit testing of higher-level
// logic on the dev machine; PenLock itself only ships for Windows).
#include <random>
inline void secure_random_bytes(uint8_t* out, size_t len) {
    static std::random_device rd;
    for (size_t i = 0; i < len; ++i) out[i] = static_cast<uint8_t>(rd());
}
#endif
