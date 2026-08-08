// key_wrap.h - Wraps/unwraps the vault's master encryption key using a
// password-derived key or a recovery-key-derived key. Pure logic, no
// file or disk I/O, so it is fully unit-testable without Windows.
#pragma once
#include "../crypto/aes.h"
#include "../crypto/pbkdf2.h"
#include "../crypto/random.h"
#include "vault_format.h"
#include <vector>
#include <string>
#include <stdexcept>

static const size_t MASTER_KEY_SIZE = 32;
static const size_t SALT_SIZE = 16;
static const size_t IV_SIZE = 16;

// Generates a brand-new random 32-byte master key. This is the key that
// actually protects the user's files; the password and recovery key only
// ever wrap (encrypt) a copy of it, never replace it. This means changing
// the password later does NOT require re-encrypting every file.
inline std::vector<uint8_t> generate_master_key() {
    std::vector<uint8_t> key(MASTER_KEY_SIZE);
    secure_random_bytes(key.data(), key.size());
    return key;
}

struct WrappedKey {
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> wrapped; // ciphertext
};

// Derives an AES key from a password/passphrase-like secret using PBKDF2,
// then encrypts (wraps) the master key with it.
inline WrappedKey wrap_master_key(const std::vector<uint8_t>& master_key,
                                   const std::string& secret,
                                   uint32_t iterations) {
    WrappedKey w;
    w.salt.resize(SALT_SIZE);
    secure_random_bytes(w.salt.data(), SALT_SIZE);

    uint8_t derived[32];
    pbkdf2_hmac_sha256(reinterpret_cast<const uint8_t*>(secret.data()), secret.size(),
                        w.salt.data(), w.salt.size(), iterations, derived, 32);

    w.iv.resize(IV_SIZE);
    secure_random_bytes(w.iv.data(), IV_SIZE);

    AES256 aes(derived);
    w.wrapped = aes.cbc_encrypt(master_key.data(), master_key.size(), w.iv.data());

    // Best-effort zero of the derived key material from the stack.
    std::memset(derived, 0, sizeof(derived));
    return w;
}

// Attempts to recover the master key from a wrapped copy using the given
// secret (password or recovery key). Throws std::runtime_error if the
// secret is wrong (detected via PKCS7 padding failure) or data is corrupt.
inline std::vector<uint8_t> unwrap_master_key(const std::vector<uint8_t>& salt,
                                               const std::vector<uint8_t>& iv,
                                               const std::vector<uint8_t>& wrapped,
                                               const std::string& secret,
                                               uint32_t iterations) {
    if (salt.size() != SALT_SIZE || iv.size() != IV_SIZE) {
        throw std::runtime_error("unwrap_master_key: invalid salt/iv size");
    }
    uint8_t derived[32];
    pbkdf2_hmac_sha256(reinterpret_cast<const uint8_t*>(secret.data()), secret.size(),
                        salt.data(), salt.size(), iterations, derived, 32);

    AES256 aes(derived);
    std::memset(derived, 0, sizeof(derived));

    // cbc_decrypt throws on bad padding, which is our "wrong password" signal.
    auto plain = aes.cbc_decrypt(wrapped.data(), wrapped.size(), iv.data());
    if (plain.size() != MASTER_KEY_SIZE) {
        throw std::runtime_error("unwrap_master_key: unexpected key size after decrypt");
    }
    return plain;
}

// Generates a random recovery key and formats it as a human-friendly,
// easy-to-transcribe string: 8 groups of 5 uppercase base32 characters,
// e.g. "K7RTX-9MZPQ-4FHNC-..." Crockford-style alphabet avoids 0/O/1/I
// confusion.
inline std::string generate_recovery_key_string() {
    static const char* alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 32 chars, no 0/O/1/I
    uint8_t raw[20]; // 160 bits of entropy -> exactly 32 base32 chars, no remainder
    secure_random_bytes(raw, sizeof(raw));

    // Pack 5 bits at a time (base32-style) purely for display; this does
    // NOT need to be reversible byte-for-byte, since the recovery key is
    // fed straight back into PBKDF2 as a password-equivalent string.
    // Use a 64-bit unsigned buffer so left-shifting never overflows/loses
    // bits that are still pending extraction (a signed 32-bit buffer here
    // would silently corrupt characters once more than 32 bits of data had
    // passed through it).
    std::string chars;
    uint64_t bitbuf = 0;
    int bitcount = 0;
    for (size_t i = 0; i < sizeof(raw); ++i) {
        bitbuf = (bitbuf << 8) | raw[i];
        bitcount += 8;
        while (bitcount >= 5) {
            int val = static_cast<int>((bitbuf >> (bitcount - 5)) & 0x1F);
            chars += alphabet[val];
            bitcount -= 5;
        }
    }
    // 160 bits / 5 bits-per-char = exactly 32 characters, so bitcount is
    // guaranteed to be 0 here with nothing left over.

    std::string out;
    for (size_t i = 0; i < chars.size(); ++i) {
        if (i > 0 && i % 5 == 0) out += '-';
        out += chars[i];
    }
    return out; // always "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX" (38 chars)
}
