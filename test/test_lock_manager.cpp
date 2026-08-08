#include "../src/vault/lock_manager.h"
#include <cstdio>

static VaultMetadata make_vault(SecurityLevel lvl, const std::string& password, std::string* recovery_out = nullptr) {
    VaultMetadata m;
    m.security_level = lvl;
    m.pbkdf2_iterations = 200; // low for test speed
    auto master = generate_master_key();
    auto pw = wrap_master_key(master, password, m.pbkdf2_iterations);
    m.pw_salt = pw.salt; m.pw_wrap_iv = pw.iv; m.pw_wrapped_key = pw.wrapped;

    std::string recovery = generate_recovery_key_string();
    if (recovery_out) *recovery_out = recovery;
    auto rk = wrap_master_key(master, recovery, m.pbkdf2_iterations);
    m.rk_salt = rk.salt; m.rk_wrap_iv = rk.iv; m.rk_wrapped_key = rk.wrapped;
    return m;
}

int main() {
    int fails = 0;
    const std::string PW = "CorrectHorse!42";
    uint64_t t = 1000000;

    // --- Normal: unlimited wrong attempts, never locks out ---
    {
        auto m = make_vault(SecurityLevel::Normal, PW);
        int wrong_count = 0;
        for (int i = 0; i < 20; ++i) {
            auto r = attempt_unlock(m, "wrong", t);
            if (r.result == UnlockResult::WrongPassword) wrong_count++;
            else { printf("FAIL Normal: unexpected result on attempt %d\n", i); fails++; }
        }
        auto ok = attempt_unlock(m, PW, t);
        bool pass = ok.result == UnlockResult::Success && wrong_count == 20;
        printf(pass ? "NORMAL_UNLIMITED_ATTEMPTS OK\n" : "NORMAL_UNLIMITED_ATTEMPTS FAIL\n");
        fails += !pass;
    }

    // --- Standard: 5 wrong -> 10 min lockout, then correct password after lockout still needed ---
    {
        auto m = make_vault(SecurityLevel::Standard, PW);
        UnlockOutcome last;
        for (int i = 0; i < 5; ++i) last = attempt_unlock(m, "wrong", t);
        bool locked = last.result == UnlockResult::LockedOut && last.lockout_seconds_left == STANDARD_LOCKOUT_SECONDS;
        printf(locked ? "STANDARD_LOCKS_AFTER_5 OK\n" : "STANDARD_LOCKS_AFTER_5 FAIL\n");
        fails += !locked;

        // Correct password attempt DURING lockout should still be rejected as LockedOut
        auto during = attempt_unlock(m, PW, t + 60);
        bool still_locked = during.result == UnlockResult::LockedOut && during.lockout_seconds_left == STANDARD_LOCKOUT_SECONDS - 60;
        printf(still_locked ? "STANDARD_BLOCKS_DURING_LOCKOUT OK\n" : "STANDARD_BLOCKS_DURING_LOCKOUT FAIL\n");
        fails += !still_locked;

        // After lockout window passes, correct password should work
        auto after = attempt_unlock(m, PW, t + STANDARD_LOCKOUT_SECONDS + 1);
        bool after_ok = after.result == UnlockResult::Success;
        printf(after_ok ? "STANDARD_UNLOCKS_AFTER_WINDOW OK\n" : "STANDARD_UNLOCKS_AFTER_WINDOW FAIL\n");
        fails += !after_ok;
    }

    // --- High: 3 wrong -> WipeTriggered, correct password on 1st/2nd attempt still fine ---
    {
        auto m = make_vault(SecurityLevel::High, PW);
        auto r1 = attempt_unlock(m, "wrong", t);
        auto r2 = attempt_unlock(m, "wrong", t);
        bool early_ok = r1.result == UnlockResult::WrongPassword && r2.result == UnlockResult::WrongPassword;
        auto r3 = attempt_unlock(m, "wrong", t);
        bool wiped = r3.result == UnlockResult::WipeTriggered;
        printf((early_ok && wiped) ? "HIGH_WIPES_AFTER_3 OK\n" : "HIGH_WIPES_AFTER_3 FAIL\n");
        fails += !(early_ok && wiped);

        // correct password on attempt 2 (before wipe threshold) should still succeed and NOT wipe
        auto m2 = make_vault(SecurityLevel::High, PW);
        attempt_unlock(m2, "wrong", t);
        auto ok = attempt_unlock(m2, PW, t);
        bool pass = ok.result == UnlockResult::Success;
        printf(pass ? "HIGH_RECOVERS_BEFORE_THRESHOLD OK\n" : "HIGH_RECOVERS_BEFORE_THRESHOLD FAIL\n");
        fails += !pass;
    }

    // --- Ultra: 1 wrong -> immediate WipeTriggered ---
    {
        auto m = make_vault(SecurityLevel::Ultra, PW);
        auto r = attempt_unlock(m, "wrong", t);
        bool pass = r.result == UnlockResult::WipeTriggered;
        printf(pass ? "ULTRA_WIPES_IMMEDIATELY OK\n" : "ULTRA_WIPES_IMMEDIATELY FAIL\n");
        fails += !pass;

        // correct password on the FIRST try should still succeed normally
        auto m2 = make_vault(SecurityLevel::Ultra, PW);
        auto ok = attempt_unlock(m2, PW, t);
        bool pass2 = ok.result == UnlockResult::Success;
        printf(pass2 ? "ULTRA_FIRST_TRY_CORRECT_OK OK\n" : "ULTRA_FIRST_TRY_CORRECT_OK FAIL\n");
        fails += !pass2;
    }

    // --- Recovery key path ---
    {
        std::string recovery;
        auto m = make_vault(SecurityLevel::Standard, PW, &recovery);
        // force a lockout
        for (int i = 0; i < 5; ++i) attempt_unlock(m, "wrong", t);
        // recovery key should bypass the lockout
        auto r = attempt_unlock_with_recovery_key(m, recovery);
        bool pass = r.result == UnlockResult::Success && m.lockout_until_unix == 0;
        printf(pass ? "RECOVERY_KEY_BYPASSES_LOCKOUT OK\n" : "RECOVERY_KEY_BYPASSES_LOCKOUT FAIL\n");
        fails += !pass;

        // wrong recovery key should just fail, not crash
        auto bad = attempt_unlock_with_recovery_key(m, "TOTALLY-WRONG-KEY-XX");
        bool pass2 = bad.result == UnlockResult::WrongPassword;
        printf(pass2 ? "WRONG_RECOVERY_KEY_REJECTED OK\n" : "WRONG_RECOVERY_KEY_REJECTED FAIL\n");
        fails += !pass2;
    }

    printf(fails == 0 ? "\nALL PASS\n" : "\nSOME FAILED (%d)\n", fails);
    return fails;
}
