// file_vault.h - Locks/unlocks the visible data partition by transforming
// each real file into an encrypted sibling (same name + ".plk") and back.
//
// Design choice: PenLock encrypts files IN PLACE rather than mounting a
// virtual encrypted volume. This avoids needing a kernel-mode driver
// (which would need Microsoft driver signing and far more engineering),
// at the cost of two things worth knowing:
//   1) While unlocked, files sit as normal plaintext on the partition —
//      anyone with physical access to an already-unlocked drive can read
//      them, same as any unlocked folder. The protection is against the
//      drive being read while LOCKED (lost, stolen, or plugged into
//      another PC without the password).
//   2) Locking/unlocking touches every file, so it takes time proportional
//      to how much data is on the drive (a progress callback is provided
//      so the GUI can show a progress bar for large drives).
#pragma once
#include "../crypto/aes.h"
#include "../crypto/random.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <functional>
#include <stdexcept>

namespace fs = std::filesystem;

static const char* PLK_EXTENSION = ".plk";
// Files/folders PenLock must never touch even though they live on the
// same visible partition (its own marker file, recycle bin, etc).
inline bool is_reserved_path(const fs::path& p) {
    std::string name = p.filename().string();
    if (name == "System Volume Information") return true;
    if (name == "$RECYCLE.BIN") return true;
    if (name == ".penlock_marker") return true;
    return false;
}

using ProgressCallback = std::function<void(size_t done, size_t total, const std::string& current_file)>;

inline std::vector<uint8_t> read_whole_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open file: " + p.string());
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (size > 0 && !f.read(reinterpret_cast<char*>(buf.data()), size))
        throw std::runtime_error("failed reading file: " + p.string());
    return buf;
}

inline void write_whole_file(const fs::path& p, const uint8_t* data, size_t len) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot create file: " + p.string());
    if (len > 0) f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
}

// Encrypts one file: <name> -> <name>.plk (format: 16-byte IV followed by
// AES-256-CBC ciphertext). The original plaintext file is deleted after
// the encrypted copy is confirmed written.
inline void encrypt_file_in_place(const fs::path& plain_path, const AES256& aes) {
    auto data = read_whole_file(plain_path);
    uint8_t iv[16];
    secure_random_bytes(iv, 16);
    auto ct = aes.cbc_encrypt(data.data(), data.size(), iv);

    fs::path enc_path = plain_path;
    enc_path += PLK_EXTENSION;

    std::ofstream out(enc_path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot create encrypted file: " + enc_path.string());
    out.write(reinterpret_cast<const char*>(iv), 16);
    out.write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
    out.close();

    fs::remove(plain_path);
}

// Decrypts one file: <name>.plk -> <name>. Throws on wrong key / corrupt data,
// in which case the .plk file is left untouched (nothing is lost).
inline void decrypt_file_in_place(const fs::path& enc_path, const AES256& aes) {
    auto blob = read_whole_file(enc_path);
    if (blob.size() < 16) throw std::runtime_error("corrupt vault file (too small): " + enc_path.string());
    uint8_t iv[16];
    std::memcpy(iv, blob.data(), 16);
    auto plain = aes.cbc_decrypt(blob.data() + 16, blob.size() - 16, iv);

    fs::path plain_path = enc_path;
    plain_path.replace_extension(); // drops ".plk" — but replace_extension only
                                     // strips the LAST extension, so "photo.jpg.plk"
                                     // correctly becomes "photo.jpg".

    write_whole_file(plain_path, plain.data(), plain.size());
    fs::remove(enc_path);
}

// Walks a directory recursively, encrypting every plaintext file (anything
// without a .plk extension, excluding reserved paths) in place.
inline void lock_all_files(const fs::path& root, const std::vector<uint8_t>& master_key,
                            const ProgressCallback& on_progress = nullptr) {
    AES256 aes(master_key.data());
    std::vector<fs::path> targets;
    for (auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        if (is_reserved_path(entry.path())) continue;
        if (entry.path().extension() == PLK_EXTENSION) continue; // already locked
        targets.push_back(entry.path());
    }
    size_t total = targets.size();
    for (size_t i = 0; i < total; ++i) {
        if (on_progress) on_progress(i, total, targets[i].filename().string());
        encrypt_file_in_place(targets[i], aes);
    }
    if (on_progress) on_progress(total, total, "");
}

// Walks a directory recursively, decrypting every .plk file back to its
// original plaintext form. If ANY file fails to decrypt (wrong master key,
// meaning wrong password got this far somehow, or corruption), the whole
// operation is aborted immediately and already-decrypted files in this
// call are left as-is — this should not normally happen since the caller
// only invokes this after the password has already been verified against
// the wrapped master key.
inline void unlock_all_files(const fs::path& root, const std::vector<uint8_t>& master_key,
                              const ProgressCallback& on_progress = nullptr) {
    AES256 aes(master_key.data());
    std::vector<fs::path> targets;
    for (auto& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        if (is_reserved_path(entry.path())) continue;
        if (entry.path().extension() != PLK_EXTENSION) continue;
        targets.push_back(entry.path());
    }
    size_t total = targets.size();
    for (size_t i = 0; i < total; ++i) {
        if (on_progress) on_progress(i, total, targets[i].filename().string());
        decrypt_file_in_place(targets[i], aes);
    }
    if (on_progress) on_progress(total, total, "");
}
