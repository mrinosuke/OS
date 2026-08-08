// lock_manager.h - Decides what should happen after a password attempt,
// based on the vault's configured security level. Deliberately has NO
// disk/file I/O of its own — it only reads/updates VaultMetadata counters
// and returns a result enum. The caller (GUI layer, on Windows) is
// responsible for actually performing a wipe when told to, and for
// persisting the updated VaultMetadata back to the hidden partition.
// Keeping this logic free of I/O is what makes it possible to unit-test
// every security-level branch without needing Windows or real hardware.
#pragma once
#include "vault_format.h"
#include "key_wrap.h"
#include <string>
#include <vector>
#include <cstdint>

enum class UnlockResult {
    Success,        // password correct, master key recovered
    WrongPassword,  // password incorrect, no special action required
    LockedOut,      // Standard level: too many attempts, wait it out
    WipeTriggered   // High/Ultra level: caller MUST wipe the drive now
};

struct UnlockOutcome {
    UnlockResult result;
    std::vector<uint8_t> master_key;   // valid only if result == Success
    uint64_t lockout_seconds_left = 0; // valid only if result == LockedOut
};

// Standard-level lockout parameters.
static const uint32_t STANDARD_MAX_ATTEMPTS = 5;
static const uint64_t STANDARD_LOCKOUT_SECONDS = 10 * 60;
static const uint32_t HIGH_MAX_ATTEMPTS = 3;
static const uint32_t ULTRA_MAX_ATTEMPTS = 1;

// Attempts to unlock using a password. `meta` is updated in place
// (failed_attempts / lockout_until_unix) — the caller must persist it
// afterwards regardless of the outcome. `now` is injected (rather than
// read internally) so this function is deterministic and testable.
inline UnlockOutcome attempt_unlock(VaultMetadata& meta, const std::string& password, uint64_t now) {
    UnlockOutcome outcome;

    if (meta.security_level == SecurityLevel::Standard && meta.lockout_until_unix > now) {
        outcome.result = UnlockResult::LockedOut;
        outcome.lockout_seconds_left = meta.lockout_until_unix - now;
        return outcome;
    }

    try {
        auto key = unwrap_master_key(meta.pw_salt, meta.pw_wrap_iv, meta.pw_wrapped_key,
                                      password, meta.pbkdf2_iterations);
        meta.failed_attempts = 0;
        meta.lockout_until_unix = 0;
        outcome.result = UnlockResult::Success;
        outcome.master_key = std::move(key);
        return outcome;
    } catch (const std::exception&) {
        // fall through to failure handling below
    }

    meta.failed_attempts += 1;

    switch (meta.security_level) {
        case SecurityLevel::Normal:
            outcome.result = UnlockResult::WrongPassword;
            break;

        case SecurityLevel::Standard:
            if (meta.failed_attempts >= STANDARD_MAX_ATTEMPTS) {
                meta.lockout_until_unix = now + STANDARD_LOCKOUT_SECONDS;
                meta.failed_attempts = 0; // fresh count once the lockout expires
                outcome.result = UnlockResult::LockedOut;
                outcome.lockout_seconds_left = STANDARD_LOCKOUT_SECONDS;
            } else {
                outcome.result = UnlockResult::WrongPassword;
            }
            break;

        case SecurityLevel::High:
            if (meta.failed_attempts >= HIGH_MAX_ATTEMPTS) {
                outcome.result = UnlockResult::WipeTriggered;
            } else {
                outcome.result = UnlockResult::WrongPassword;
            }
            break;

        case SecurityLevel::Ultra:
            if (meta.failed_attempts >= ULTRA_MAX_ATTEMPTS) {
                outcome.result = UnlockResult::WipeTriggered;
            } else {
                outcome.result = UnlockResult::WrongPassword;
            }
            break;
    }
    return outcome;
}

// Attempts to unlock using the recovery key instead of the password. On
// success this does NOT reset failed_attempts for the password path (a
// lost/forgotten password should still be changed afterward), but it does
// clear any active Standard-level lockout since the user has now proven
// legitimate ownership.
inline UnlockOutcome attempt_unlock_with_recovery_key(VaultMetadata& meta, const std::string& recovery_key) {
    UnlockOutcome outcome;
    try {
        auto key = unwrap_master_key(meta.rk_salt, meta.rk_wrap_iv, meta.rk_wrapped_key,
                                      recovery_key, meta.pbkdf2_iterations);
        meta.lockout_until_unix = 0;
        outcome.result = UnlockResult::Success;
        outcome.master_key = std::move(key);
    } catch (const std::exception&) {
        outcome.result = UnlockResult::WrongPassword;
    }
    return outcome;
}
