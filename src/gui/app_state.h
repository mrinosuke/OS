// app_state.h - Shared in-memory state for the whole PenLock application.
// One instance lives for the lifetime of the program, attached to the
// main window via GWLP_USERDATA. Windows-only.
#pragma once
#ifndef _WIN32
#error "app_state.h is Windows-only"
#endif
#include <windows.h>
#include <string>
#include <vector>
#include "../usb/usb_detect.h"
#include "../vault/vault_format.h"

enum class AppState {
    SelectDrive,
    InstallSecurityLevel,
    InstallWarning,
    InstallPassword,
    InstallConfirm,
    InstallProgress,
    InstallRecoveryKey,
    Unlock,
    Unlocked,
    ChangePassword,
    ChangeSecurityLevel
};

// The Unlock screen doubles as a generic "working..." progress screen for
// three different background operations (unlocking, locking, wiping after
// a security-triggered failure). AppState alone can't tell those apart
// when the worker finishes, so we track intent separately.
enum class PendingAction {
    None,
    Unlocking,
    Locking,
    Wiping
};

struct AppData {
    AppState state = AppState::SelectDrive;

    std::vector<UsbDriveInfo> drives;   // last enumerated drive list
    int selected_drive_index = -1;

    // Chosen during the install wizard
    SecurityLevel chosen_level = SecurityLevel::Normal;
    std::wstring pending_password;
    std::wstring pending_recovery_key;

    // Loaded once a drive with an existing vault is selected
    VaultMetadata vault;
    uint32_t vault_disk_number = 0;
    char vault_data_letter = 0; // partition 1's drive letter

    // Live only between a successful unlock and the next lock
    std::vector<uint8_t> master_key;

    PendingAction pending_action = PendingAction::None;

    HWND main_window = nullptr;
    std::vector<HWND> current_controls; // controls belonging to the active screen
};
