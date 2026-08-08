#include "../src/vault/key_wrap.h"
#include <cstdio>
#include <iostream>

int main() {
    int fails = 0;

    auto master = generate_master_key();
    printf("master key size: %zu\n", master.size());
    if (master.size() != 32) { printf("FAIL master key size\n"); fails++; }

    // Wrap with password, low iterations for test speed
    uint32_t iters = 500;
    std::string password = "MySecretP@ss123";
    auto w = wrap_master_key(master, password, iters);
    printf("wrapped size: %zu (salt=%zu iv=%zu)\n", w.wrapped.size(), w.salt.size(), w.iv.size());

    // Unwrap with correct password
    auto recovered = unwrap_master_key(w.salt, w.iv, w.wrapped, password, iters);
    bool ok1 = recovered == master;
    printf(ok1 ? "CORRECT_PASSWORD_UNWRAP OK\n" : "CORRECT_PASSWORD_UNWRAP FAIL\n");
    fails += !ok1;

    // Unwrap with wrong password should throw
    bool threw = false;
    try {
        auto bad = unwrap_master_key(w.salt, w.iv, w.wrapped, "WrongPassword!", iters);
    } catch (const std::exception& e) {
        threw = true;
        printf("wrong password correctly threw: %s\n", e.what());
    }
    printf(threw ? "WRONG_PASSWORD_REJECTED OK\n" : "WRONG_PASSWORD_REJECTED FAIL\n");
    fails += !threw;

    // Recovery key path: wrap same master key with a different secret
    std::string recovery = generate_recovery_key_string();
    printf("sample recovery key: %s (len=%zu)\n", recovery.c_str(), recovery.length());
    auto w2 = wrap_master_key(master, recovery, iters);
    auto recovered2 = unwrap_master_key(w2.salt, w2.iv, w2.wrapped, recovery, iters);
    bool ok2 = recovered2 == master;
    printf(ok2 ? "RECOVERY_KEY_UNWRAP OK\n" : "RECOVERY_KEY_UNWRAP FAIL\n");
    fails += !ok2;

    // Sanity: password wrap and recovery wrap are independent (different salt/iv/ciphertext)
    bool independent = (w.salt != w2.salt) && (w.wrapped != w2.wrapped);
    printf(independent ? "INDEPENDENT_WRAPS OK\n" : "INDEPENDENT_WRAPS FAIL\n");
    fails += !independent;

    // Generate a handful of recovery keys, check they look reasonable and unique
    bool all_unique = true;
    std::string prev;
    for (int i = 0; i < 5; ++i) {
        std::string rk = generate_recovery_key_string();
        printf("  recovery sample %d: %s\n", i, rk.c_str());
        if (rk == prev) all_unique = false;
        prev = rk;
    }
    printf(all_unique ? "RECOVERY_KEYS_LOOK_UNIQUE OK\n" : "RECOVERY_KEYS_LOOK_UNIQUE FAIL\n");

    printf(fails == 0 ? "\nALL PASS\n" : "\nSOME FAILED (%d)\n", fails);
    return fails;
}
