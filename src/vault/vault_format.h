// vault_format.h - PenLock vault metadata format.
//
// This structure is stored as a single file ("penlock.dat") on the hidden
// system partition (partition 2) created at install time. Its presence
// (with a valid magic number) is how PenLock decides a drive is already
// "installed" when selected from the drive list.
//
// The actual file-encryption key ("master key") is never stored directly.
// It is generated once at install time and then wrapped (encrypted) twice:
//   1) by a key derived from the user's password (normal unlock path)
//   2) by a key derived from the one-time recovery key (backup path)
// This mirrors how BitLocker/VeraCrypt support multiple independent
// "protectors" for the same underlying key.
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>

enum class SecurityLevel : uint32_t {
    Normal   = 0, // unlimited attempts, no penalty
    Standard = 1, // 5 wrong attempts -> 10 minute lockout
    High     = 2, // 3 wrong attempts -> full format/wipe of data partition
    Ultra    = 3  // 1 wrong attempt  -> wipe + anti-forensic free-space overwrite
};

inline const char* security_level_name(SecurityLevel lvl) {
    switch (lvl) {
        case SecurityLevel::Normal:   return "Normal";
        case SecurityLevel::Standard: return "Standard";
        case SecurityLevel::High:     return "High";
        case SecurityLevel::Ultra:    return "Ultra";
    }
    return "Unknown";
}

inline const char* security_level_description(SecurityLevel lvl) {
    switch (lvl) {
        case SecurityLevel::Normal:
            return "Unlimited password attempts. No lockout, no data loss risk "
                   "from mistyped passwords. Lowest protection against "
                   "someone repeatedly guessing your password.";
        case SecurityLevel::Standard:
            return "After 5 wrong passwords, PenLock locks out further "
                   "attempts for 10 minutes. Your files are safe; you just "
                   "have to wait if you mistype too many times.";
        case SecurityLevel::High:
            return "After 3 wrong passwords, the data partition is fully "
                   "formatted and ALL FILES ARE PERMANENTLY DELETED. "
                   "PenLock itself remains installed. Use only if you are "
                   "confident you (or an attacker) will not mistype the "
                   "password 3 times.";
        case SecurityLevel::Ultra:
            return "A SINGLE wrong password permanently deletes all files "
                   "AND overwrites the entire drive's free space with junk "
                   "data (anti-forensic wipe) so deleted files cannot be "
                   "recovered by data-recovery tools. There is no room for "
                   "typos. Use the Recovery Key if you are not 100% sure.";
    }
    return "";
}

#pragma pack(push, 1)
struct VaultMetadataRaw {
    char     magic[8];           // "PENLOCK1"
    uint32_t version;            // format version
    uint32_t security_level;     // SecurityLevel
    uint32_t pbkdf2_iterations;

    uint8_t  pw_salt[16];
    uint8_t  pw_wrap_iv[16];
    uint32_t pw_wrap_len;
    uint8_t  pw_wrapped_key[48]; // AES-256-CBC(master_key, key=PBKDF2(password)), PKCS7 padded

    uint8_t  rk_salt[16];
    uint8_t  rk_wrap_iv[16];
    uint32_t rk_wrap_len;
    uint8_t  rk_wrapped_key[48]; // same, wrapped by recovery key instead of password

    uint32_t failed_attempts;
    uint64_t lockout_until_unix; // 0 if not currently locked out (Standard level)
};
#pragma pack(pop)

static const char VAULT_MAGIC[8] = {'P','E','N','L','O','C','K','1'};
static const uint32_t VAULT_FORMAT_VERSION = 1;

struct VaultMetadata {
    SecurityLevel security_level = SecurityLevel::Normal;
    uint32_t pbkdf2_iterations = 0;

    std::vector<uint8_t> pw_salt;
    std::vector<uint8_t> pw_wrap_iv;
    std::vector<uint8_t> pw_wrapped_key;

    std::vector<uint8_t> rk_salt;
    std::vector<uint8_t> rk_wrap_iv;
    std::vector<uint8_t> rk_wrapped_key;

    uint32_t failed_attempts = 0;
    uint64_t lockout_until_unix = 0;
};

inline std::vector<uint8_t> serialize_metadata(const VaultMetadata& m) {
    VaultMetadataRaw raw{};
    std::memcpy(raw.magic, VAULT_MAGIC, 8);
    raw.version = VAULT_FORMAT_VERSION;
    raw.security_level = static_cast<uint32_t>(m.security_level);
    raw.pbkdf2_iterations = m.pbkdf2_iterations;

    if (m.pw_salt.size() != 16 || m.pw_wrap_iv.size() != 16 || m.pw_wrapped_key.size() > 48 ||
        m.rk_salt.size() != 16 || m.rk_wrap_iv.size() != 16 || m.rk_wrapped_key.size() > 48) {
        throw std::runtime_error("serialize_metadata: field size mismatch");
    }
    std::memcpy(raw.pw_salt, m.pw_salt.data(), 16);
    std::memcpy(raw.pw_wrap_iv, m.pw_wrap_iv.data(), 16);
    raw.pw_wrap_len = static_cast<uint32_t>(m.pw_wrapped_key.size());
    std::memcpy(raw.pw_wrapped_key, m.pw_wrapped_key.data(), m.pw_wrapped_key.size());

    std::memcpy(raw.rk_salt, m.rk_salt.data(), 16);
    std::memcpy(raw.rk_wrap_iv, m.rk_wrap_iv.data(), 16);
    raw.rk_wrap_len = static_cast<uint32_t>(m.rk_wrapped_key.size());
    std::memcpy(raw.rk_wrapped_key, m.rk_wrapped_key.data(), m.rk_wrapped_key.size());

    raw.failed_attempts = m.failed_attempts;
    raw.lockout_until_unix = m.lockout_until_unix;

    std::vector<uint8_t> out(sizeof(VaultMetadataRaw));
    std::memcpy(out.data(), &raw, sizeof(VaultMetadataRaw));
    return out;
}

inline bool looks_like_vault(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(VaultMetadataRaw)) return false;
    return std::memcmp(data.data(), VAULT_MAGIC, 8) == 0;
}

inline VaultMetadata deserialize_metadata(const std::vector<uint8_t>& data) {
    if (!looks_like_vault(data)) {
        throw std::runtime_error("deserialize_metadata: not a PenLock vault (bad magic)");
    }
    VaultMetadataRaw raw{};
    std::memcpy(&raw, data.data(), sizeof(VaultMetadataRaw));
    if (raw.version != VAULT_FORMAT_VERSION) {
        throw std::runtime_error("deserialize_metadata: unsupported format version");
    }

    VaultMetadata m;
    m.security_level = static_cast<SecurityLevel>(raw.security_level);
    m.pbkdf2_iterations = raw.pbkdf2_iterations;
    m.pw_salt.assign(raw.pw_salt, raw.pw_salt + 16);
    m.pw_wrap_iv.assign(raw.pw_wrap_iv, raw.pw_wrap_iv + 16);
    if (raw.pw_wrap_len > 48) throw std::runtime_error("corrupt vault metadata (pw_wrap_len)");
    m.pw_wrapped_key.assign(raw.pw_wrapped_key, raw.pw_wrapped_key + raw.pw_wrap_len);

    m.rk_salt.assign(raw.rk_salt, raw.rk_salt + 16);
    m.rk_wrap_iv.assign(raw.rk_wrap_iv, raw.rk_wrap_iv + 16);
    if (raw.rk_wrap_len > 48) throw std::runtime_error("corrupt vault metadata (rk_wrap_len)");
    m.rk_wrapped_key.assign(raw.rk_wrapped_key, raw.rk_wrapped_key + raw.rk_wrap_len);

    m.failed_attempts = raw.failed_attempts;
    m.lockout_until_unix = raw.lockout_until_unix;
    return m;
}
