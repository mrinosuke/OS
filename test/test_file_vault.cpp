#include "../src/vault/file_vault.h"
#include "../src/vault/key_wrap.h"
#include <cstdio>
#include <iostream>
#include <map>

namespace fs = std::filesystem;

static void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << content;
}

int main() {
    int fails = 0;
    fs::path root = "/tmp/penlock_test_vault";
    fs::remove_all(root);
    fs::create_directories(root);

    std::map<std::string, std::string> original_contents = {
        {"doc.txt", "Hello, this is a test document.\nSecond line.\n"},
        {"empty.txt", ""},
        {"sub/nested.txt", "Nested file content here, testing subdirectories."},
        {"sub/deep/deeper.bin", std::string(500, '\x7f')},
        {"photo.jpg", "FAKE-JPEG-BYTES-1234567890"},
    };
    for (auto& [rel, content] : original_contents) {
        write_file(root / rel, content);
    }
    // A reserved marker that must NOT be touched
    write_file(root / ".penlock_marker", "PENLOCK-INSTALLED");

    auto master = generate_master_key();

    printf("--- Locking ---\n");
    lock_all_files(root, master, [](size_t done, size_t total, const std::string& f) {
        if (!f.empty()) printf("  [%zu/%zu] locking %s\n", done+1, total, f.c_str());
    });

    // Verify: all original plaintext files gone, .plk siblings exist
    bool lock_ok = true;
    for (auto& [rel, content] : original_contents) {
        fs::path plain = root / rel;
        fs::path enc = plain; enc += ".plk";
        if (fs::exists(plain)) { printf("FAIL: plaintext still exists after lock: %s\n", rel.c_str()); lock_ok = false; }
        if (!fs::exists(enc)) { printf("FAIL: encrypted file missing after lock: %s\n", rel.c_str()); lock_ok = false; }
    }
    // marker must be untouched
    if (!fs::exists(root / ".penlock_marker")) { printf("FAIL: reserved marker was touched!\n"); lock_ok = false; }
    if (fs::exists(fs::path(root / ".penlock_marker").string() + ".plk")) { printf("FAIL: reserved marker got encrypted!\n"); lock_ok = false; }
    printf(lock_ok ? "LOCK_TRANSFORM OK\n" : "LOCK_TRANSFORM FAIL\n");
    fails += !lock_ok;

    printf("--- Unlocking ---\n");
    unlock_all_files(root, master, [](size_t done, size_t total, const std::string& f) {
        if (!f.empty()) printf("  [%zu/%zu] unlocking %s\n", done+1, total, f.c_str());
    });

    bool unlock_ok = true;
    for (auto& [rel, content] : original_contents) {
        fs::path plain = root / rel;
        fs::path enc = plain; enc += ".plk";
        if (fs::exists(enc)) { printf("FAIL: .plk still exists after unlock: %s\n", rel.c_str()); unlock_ok = false; }
        if (!fs::exists(plain)) { printf("FAIL: plaintext missing after unlock: %s\n", rel.c_str()); unlock_ok = false; continue; }
        std::ifstream f(plain, std::ios::binary);
        std::string got((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (got != content) {
            printf("FAIL: content mismatch for %s (got %zu bytes, expected %zu)\n", rel.c_str(), got.size(), content.size());
            unlock_ok = false;
        }
    }
    printf(unlock_ok ? "UNLOCK_ROUNDTRIP OK\n" : "UNLOCK_ROUNDTRIP FAIL\n");
    fails += !unlock_ok;

    // Now test wrong master key: re-lock, then try to unlock with a different key
    lock_all_files(root, master);
    auto wrong_key = generate_master_key();
    bool threw = false;
    try {
        unlock_all_files(root, wrong_key);
    } catch (const std::exception& e) {
        threw = true;
        printf("wrong key correctly threw: %s\n", e.what());
    }
    printf(threw ? "WRONG_KEY_REJECTED OK\n" : "WRONG_KEY_REJECTED FAIL\n");
    fails += !threw;

    // Clean unlock with correct key should still work after the failed attempt
    unlock_all_files(root, master);
    bool recovered_ok = fs::exists(root / "doc.txt");
    printf(recovered_ok ? "RECOVER_AFTER_WRONG_ATTEMPT OK\n" : "RECOVER_AFTER_WRONG_ATTEMPT FAIL\n");
    fails += !recovered_ok;

    fs::remove_all(root);
    printf(fails == 0 ? "\nALL PASS\n" : "\nSOME FAILED (%d)\n", fails);
    return fails;
}
