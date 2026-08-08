// main_window.cpp - PenLock's GUI. One HWND, many "screens": each
// AppState shows/destroys a different set of child controls. This keeps
// window-handle bookkeeping in one place instead of juggling several
// top-level windows and dialogs.
//
// Windows-only. Cannot be compiled or run outside Windows/mingw-w64 — see
// README.md for the current "written but not yet hardware-tested" status.
#ifndef _WIN32
#error "main_window.cpp is Windows-only"
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <dbt.h>
#include <ctime>
#include <cstring>
#include <thread>
#include <sstream>
#include <iomanip>
#include <filesystem>

#include "main_window.h"
#include "app_state.h"
#include "theme.h"
#include "tray.h"
#include "../usb/usb_detect.h"
#include "../usb/partition.h"
#include "../usb/wipe.h"
#include "../vault/vault_format.h"
#include "../vault/key_wrap.h"
#include "../vault/lock_manager.h"
#include "../vault/file_vault.h"

const wchar_t* PENLOCK_WINDOW_CLASS = L"PenLockMainWindow";
const wchar_t* PENLOCK_VERSION_STRING = L"1.0.0";

// ---------------------------------------------------------------------
// Control IDs, grouped by screen to keep them easy to scan.
// ---------------------------------------------------------------------
enum ControlId : int {
    // Select Drive
    IDC_DRIVE_COMBO = 1001, IDC_REFRESH, IDC_ENTER_DRIVE, IDC_SELECT_STATUS,
    // Install: security level
    IDC_RADIO_NORMAL = 2001, IDC_RADIO_STANDARD, IDC_RADIO_HIGH, IDC_RADIO_ULTRA,
    IDC_LEVEL_DESC, IDC_LEVEL_NEXT,
    // Install: warning
    IDC_WARNING_TEXT = 2101, IDC_UNDERSTAND_CHECK, IDC_WARNING_OK,
    // Install: password
    IDC_PW1 = 2201, IDC_PW2, IDC_PW_STATUS, IDC_INSTALL_BTN,
    // Install: confirm
    IDC_CONFIRM_TEXT = 2301, IDC_CONFIRM_CANCEL, IDC_CONFIRM_GO,
    // Install: progress (also reused for wipe / lock / unlock progress)
    IDC_PROGRESS_BAR = 2401, IDC_PROGRESS_TEXT,
    // Install: recovery key
    IDC_RK_DISPLAY = 2501, IDC_RK_SAVED_CHECK, IDC_RK_CONTINUE,
    // Unlock
    IDC_UNLOCK_PW = 3001, IDC_UNLOCK_BTN, IDC_USE_RECOVERY, IDC_UNLOCK_STATUS,
    // Unlocked dashboard
    IDC_LOCK_NOW = 4001, IDC_CHANGE_PW, IDC_CHANGE_LEVEL, IDC_OPEN_FOLDER, IDC_STATUS_INFO,
    // Change password screen
    IDC_NEWPW1 = 4101, IDC_NEWPW2, IDC_NEWPW_STATUS, IDC_NEWPW_SAVE, IDC_NEWPW_CANCEL,
    // Change security level screen
    IDC_NEWLVL_NORMAL = 5001, IDC_NEWLVL_STANDARD, IDC_NEWLVL_HIGH, IDC_NEWLVL_ULTRA,
    IDC_NEWLVL_DESC, IDC_NEWLVL_SAVE, IDC_NEWLVL_CANCEL,
};

static bool g_using_recovery_mode = false;

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------
static AppData* get_app(HWND hwnd) {
    return reinterpret_cast<AppData*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

static HWND make_label(HWND parent, const wchar_t* text, int x, int y, int w, int h, bool title = false) {
    HWND h_ctrl = CreateWindowW(L"STATIC", text, WS_CHILD | WS_VISIBLE,
                                 x, y, w, h, parent, nullptr, nullptr, nullptr);
    SendMessageW(h_ctrl, WM_SETFONT, (WPARAM)(title ? theme::font_title() : theme::font_normal()), TRUE);
    return h_ctrl;
}

static HWND make_button(HWND parent, const wchar_t* text, int id, int x, int y, int w, int h) {
    HWND h_ctrl = CreateWindowW(L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                 x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    SendMessageW(h_ctrl, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    return h_ctrl;
}

static HWND make_edit(HWND parent, int id, int x, int y, int w, int h, bool password = false) {
    DWORD style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL;
    if (password) style |= ES_PASSWORD;
    HWND h_ctrl = CreateWindowW(L"EDIT", L"", style, x, y, w, h, parent, (HMENU)(INT_PTR)id, nullptr, nullptr);
    SendMessageW(h_ctrl, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    return h_ctrl;
}

static std::wstring get_text(HWND h) {
    int len = GetWindowTextLengthW(h);
    std::wstring s(len, L'\0');
    if (len > 0) GetWindowTextW(h, &s[0], len + 1);
    return s;
}

static uint64_t now_unix() { return static_cast<uint64_t>(time(nullptr)); }

// Proper UTF-16 -> UTF-8 conversion (as opposed to naively truncating each
// wchar_t to a char, which corrupts anything outside plain ASCII). This
// matters for passwords specifically: whatever bytes go into PBKDF2 at
// install time must come back byte-for-byte identical at unlock time, so
// a Bengali, accented, or emoji-containing password has to round-trip
// correctly rather than get silently mangled.
static std::string wstring_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &result[0], size_needed, nullptr, nullptr);
    return result;
}

static void track(AppData* app, HWND h) { app->current_controls.push_back(h); }

static void clear_screen(AppData* app) {
    for (HWND h : app->current_controls) DestroyWindow(h);
    app->current_controls.clear();
}

// Persists app->vault back to the hidden system partition. Called after
// any change (failed attempt counter, lockout timestamp, new password,
// new security level). Swallows errors into a message box rather than
// throwing, since this is usually called from places that can't easily
// propagate a failure (e.g. mid unlock-attempt UI feedback).
static void persist_vault(AppData* app) {
    try {
        auto bytes = serialize_metadata(app->vault);
        with_hidden_partition_writable(app->vault_disk_number, [&](const std::wstring& root) {
            std::wstring path = root + L"penlock.dat";
            HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot write penlock.dat");
            DWORD written = 0;
            WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
            CloseHandle(h);
        });
    } catch (const std::exception& e) {
        MessageBoxA(app->main_window, e.what(), "PenLock - failed to save vault state", MB_ICONWARNING);
    }
}

// Forward declarations for screen builders.
static void show_select_drive(AppData* app);
static void show_install_security_level(AppData* app);
static void show_install_warning(AppData* app);
static void show_install_password(AppData* app);
static void show_install_confirm(AppData* app);
static void show_install_progress(AppData* app);
static void show_install_recovery_key(AppData* app);
static void show_unlock(AppData* app);
static void show_unlocked(AppData* app);
static void show_change_password(AppData* app);
static void show_change_security_level(AppData* app);

// ---------------------------------------------------------------------
// Screen: Select Drive
// ---------------------------------------------------------------------
static void refresh_drive_list(AppData* app, HWND combo) {
    app->drives = enumerate_usb_drives();
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    for (auto& d : app->drives) {
        std::wstringstream ss;
        ss << d.letter << L": " << (d.label.empty() ? L"(no label)" : d.label)
           << L" - " << format_size(d.total_bytes);
        SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)ss.str().c_str());
    }
    if (!app->drives.empty()) SendMessageW(combo, CB_SETCURSEL, 0, 0);
}

static void show_select_drive(AppData* app) {
    clear_screen(app);
    app->state = AppState::SelectDrive;
    HWND w = app->main_window;

    track(app, make_label(w, L"PenLock", 30, 30, 300, 40, true));
    track(app, make_label(w, L"Select a USB drive:", 30, 90, 300, 24));

    HWND combo = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                                30, 120, 400, 200, w, (HMENU)IDC_DRIVE_COMBO, nullptr, nullptr);
    SendMessageW(combo, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    track(app, combo);
    refresh_drive_list(app, combo);

    track(app, make_button(w, L"Refresh", IDC_REFRESH, 30, 160, 100, 32));
    track(app, make_button(w, L"Enter", IDC_ENTER_DRIVE, 330, 160, 100, 32));

    HWND status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 30, 210, 420, 60, w,
                                 (HMENU)IDC_SELECT_STATUS, nullptr, nullptr);
    SendMessageW(status, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, status);
}

// ---------------------------------------------------------------------
// Screen: Install - security level
// ---------------------------------------------------------------------
static void update_level_description(HWND w, SecurityLevel lvl) {
    std::string desc = security_level_description(lvl);
    std::wstring wdesc(desc.begin(), desc.end());
    SetDlgItemTextW(w, IDC_LEVEL_DESC, wdesc.c_str());
}

static void show_install_security_level(AppData* app) {
    clear_screen(app);
    app->state = AppState::InstallSecurityLevel;
    HWND w = app->main_window;

    track(app, make_label(w, L"PenLock Installation", 30, 20, 400, 36, true));
    if (app->selected_drive_index >= 0) {
        auto& d = app->drives[app->selected_drive_index];
        std::wstringstream ss;
        ss << L"Drive " << d.letter << L":  " << (d.label.empty() ? L"(no label)" : d.label)
           << L"  -  " << format_size(d.total_bytes);
        track(app, make_label(w, ss.str().c_str(), 30, 60, 420, 24));
    }

    track(app, make_label(w, L"Choose a security level:", 30, 95, 300, 24));

    HWND r1 = CreateWindowW(L"BUTTON", L"Normal", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                             30, 125, 400, 22, w, (HMENU)IDC_RADIO_NORMAL, nullptr, nullptr);
    HWND r2 = CreateWindowW(L"BUTTON", L"Standard", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                             30, 150, 400, 22, w, (HMENU)IDC_RADIO_STANDARD, nullptr, nullptr);
    HWND r3 = CreateWindowW(L"BUTTON", L"High", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                             30, 175, 400, 22, w, (HMENU)IDC_RADIO_HIGH, nullptr, nullptr);
    HWND r4 = CreateWindowW(L"BUTTON", L"Ultra", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                             30, 200, 400, 22, w, (HMENU)IDC_RADIO_ULTRA, nullptr, nullptr);
    for (HWND r : {r1, r2, r3, r4}) { SendMessageW(r, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE); track(app, r); }
    SendMessageW(r1, BM_SETCHECK, BST_CHECKED, 0);

    HWND desc = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                               30, 235, 420, 90, w, (HMENU)IDC_LEVEL_DESC, nullptr, nullptr);
    SendMessageW(desc, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, desc);
    update_level_description(w, SecurityLevel::Normal);

    track(app, make_button(w, L"Next", IDC_LEVEL_NEXT, 330, 340, 100, 32));
}

// ---------------------------------------------------------------------
// Screen: Install - warning
// ---------------------------------------------------------------------
static void show_install_warning(AppData* app) {
    clear_screen(app);
    app->state = AppState::InstallWarning;
    HWND w = app->main_window;

    std::string level_name = security_level_name(app->chosen_level);
    std::wstring title = L"Security Level: " + std::wstring(level_name.begin(), level_name.end());
    track(app, make_label(w, title.c_str(), 30, 20, 420, 32, true));

    HWND text = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                               30, 65, 420, 160, w, (HMENU)IDC_WARNING_TEXT, nullptr, nullptr);
    SendMessageW(text, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    std::string desc = security_level_description(app->chosen_level);
    std::wstring wdesc(desc.begin(), desc.end());
    SetWindowTextW(text, wdesc.c_str());
    track(app, text);

    HWND chk = CreateWindowW(L"BUTTON", L"I have read and understand this.",
                              WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                              30, 240, 400, 24, w, (HMENU)IDC_UNDERSTAND_CHECK, nullptr, nullptr);
    SendMessageW(chk, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    track(app, chk);

    track(app, make_button(w, L"OK", IDC_WARNING_OK, 330, 280, 100, 32));
}

// ---------------------------------------------------------------------
// Screen: Install - password
// ---------------------------------------------------------------------
static void show_install_password(AppData* app) {
    clear_screen(app);
    app->state = AppState::InstallPassword;
    HWND w = app->main_window;

    track(app, make_label(w, L"Set a password", 30, 20, 300, 32, true));
    track(app, make_label(w, L"Password:", 30, 70, 150, 22));
    track(app, make_edit(w, IDC_PW1, 30, 95, 300, 26, true));
    track(app, make_label(w, L"Confirm password:", 30, 135, 150, 22));
    track(app, make_edit(w, IDC_PW2, 30, 160, 300, 26, true));

    HWND status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 30, 195, 400, 40, w,
                                 (HMENU)IDC_PW_STATUS, nullptr, nullptr);
    SendMessageW(status, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, status);

    track(app, make_button(w, L"Install", IDC_INSTALL_BTN, 30, 245, 120, 32));
}

// ---------------------------------------------------------------------
// Screen: Install - confirm (destructive action gate)
// ---------------------------------------------------------------------
static void show_install_confirm(AppData* app) {
    clear_screen(app);
    app->state = AppState::InstallConfirm;
    HWND w = app->main_window;

    auto& d = app->drives[app->selected_drive_index];
    std::wstringstream ss;
    ss << L"This will ERASE ALL DATA on drive " << d.letter << L": (" << format_size(d.total_bytes)
       << L").\r\n\r\nBack up anything you need BEFORE continuing.\r\n\r\nThis cannot be undone.";

    HWND text = CreateWindowW(L"STATIC", ss.str().c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT,
                               30, 30, 420, 140, w, (HMENU)IDC_CONFIRM_TEXT, nullptr, nullptr);
    SendMessageW(text, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    track(app, text);

    track(app, make_button(w, L"Cancel", IDC_CONFIRM_CANCEL, 30, 190, 120, 34));
    track(app, make_button(w, L"Confirm - Erase & Install", IDC_CONFIRM_GO, 170, 190, 220, 34));
}

// ---------------------------------------------------------------------
// Screen: Install - progress
// ---------------------------------------------------------------------
static void show_progress_screen(AppData* app, AppState state, const wchar_t* initial_text) {
    clear_screen(app);
    app->state = state;
    HWND w = app->main_window;

    track(app, make_label(w, initial_text, 30, 40, 420, 24, false));

    HWND bar = CreateWindowW(PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE,
                              30, 80, 420, 24, w, (HMENU)IDC_PROGRESS_BAR, nullptr, nullptr);
    SendMessageW(bar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    track(app, bar);

    HWND status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 30, 115, 420, 24, w,
                                 (HMENU)IDC_PROGRESS_TEXT, nullptr, nullptr);
    SendMessageW(status, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, status);
}

// Runs the actual install (partitioning + vault creation) on a worker
// thread, posting progress/completion back to the main window.
static void run_install_worker(HWND hwnd, uint32_t disk_number, SecurityLevel level,
                                std::wstring password) {
    std::thread([hwnd, disk_number, level, password]() {
        auto post_step = [&](const wchar_t* text) {
            wchar_t* copy = new wchar_t[wcslen(text) + 1];
            wcscpy(copy, text);
            PostMessageW(hwnd, WM_PENLOCK_STEP_TEXT, 0, (LPARAM)copy);
        };
        try {
            post_step(L"Partitioning drive...");
            PostMessageW(hwnd, WM_PENLOCK_PROGRESS, 10, 100);
            create_penlock_layout(disk_number);

            post_step(L"Locating new partition...");
            PostMessageW(hwnd, WM_PENLOCK_PROGRESS, 40, 100);
            Sleep(500);
            char data_letter = find_drive_letter_for_disk(disk_number);
            if (data_letter == 0) throw std::runtime_error("could not find newly created partition");

            post_step(L"Generating encryption keys...");
            PostMessageW(hwnd, WM_PENLOCK_PROGRESS, 55, 100);
            auto master = generate_master_key();
            std::string pw_utf8 = wstring_to_utf8(password); // full Unicode-safe conversion
            std::string recovery = generate_recovery_key_string();

            VaultMetadata meta;
            meta.security_level = level;
            meta.pbkdf2_iterations = PENLOCK_PBKDF2_ITERATIONS;
            auto pw_wrap = wrap_master_key(master, pw_utf8, meta.pbkdf2_iterations);
            meta.pw_salt = pw_wrap.salt; meta.pw_wrap_iv = pw_wrap.iv; meta.pw_wrapped_key = pw_wrap.wrapped;
            auto rk_wrap = wrap_master_key(master, recovery, meta.pbkdf2_iterations);
            meta.rk_salt = rk_wrap.salt; meta.rk_wrap_iv = rk_wrap.iv; meta.rk_wrapped_key = rk_wrap.wrapped;

            post_step(L"Writing vault metadata...");
            PostMessageW(hwnd, WM_PENLOCK_PROGRESS, 75, 100);
            auto bytes = serialize_metadata(meta);
            with_hidden_partition_writable(disk_number, [&](const std::wstring& root) {
                std::wstring path = root + L"penlock.dat";
                HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot write penlock.dat");
                DWORD written = 0;
                WriteFile(h, bytes.data(), (DWORD)bytes.size(), &written, nullptr);
                CloseHandle(h);

                // Best-effort: copy this running exe onto the hidden
                // partition too, so PenLock is fully self-contained on
                // the USB stick (can be launched from another PC without
                // needing a separate install of PenLock there). Not
                // fatal if it fails.
                wchar_t self_path[MAX_PATH];
                if (GetModuleFileNameW(nullptr, self_path, MAX_PATH) > 0) {
                    std::wstring dest = root + L"PenLock.exe";
                    CopyFileW(self_path, dest.c_str(), FALSE);
                }
            });

            PostMessageW(hwnd, WM_PENLOCK_PROGRESS, 100, 100);

            // Hand results back via heap-allocated struct-ish trick: we
            // reuse two globals-free approach by posting the recovery key
            // and disk info through a small heap block.
            struct InstallResult { std::wstring recovery; std::vector<uint8_t> master; char letter; SecurityLevel level; };
            auto* result = new InstallResult{ std::wstring(recovery.begin(), recovery.end()), master, data_letter, level };
            PostMessageW(hwnd, WM_PENLOCK_DONE, 1, (LPARAM)result);
        } catch (const std::exception& e) {
            std::string msg = e.what();
            std::wstring wmsg(msg.begin(), msg.end());
            wchar_t* copy = new wchar_t[wmsg.size() + 1];
            wcscpy(copy, wmsg.c_str());
            PostMessageW(hwnd, WM_PENLOCK_ERROR_TEXT, 0, (LPARAM)copy);
            PostMessageW(hwnd, WM_PENLOCK_DONE, 0, 0);
        }
    }).detach();
}

static void show_install_progress(AppData* app) {
    show_progress_screen(app, AppState::InstallProgress, L"Installing PenLock...");
    auto& d = app->drives[app->selected_drive_index];
    run_install_worker(app->main_window, d.disk_number, app->chosen_level, app->pending_password);
}

// ---------------------------------------------------------------------
// Screen: Install - recovery key display
// ---------------------------------------------------------------------
static void show_install_recovery_key(AppData* app) {
    clear_screen(app);
    app->state = AppState::InstallRecoveryKey;
    HWND w = app->main_window;

    track(app, make_label(w, L"Save your Recovery Key", 30, 20, 400, 32, true));
    track(app, make_label(w,
        L"If you ever forget your password, this is the ONLY way to get your\r\n"
        L"files back. Write it down or save it somewhere safe - NOT on this\r\n"
        L"pendrive. It will not be shown again.",
        30, 60, 430, 60));

    HWND rk = CreateWindowW(L"EDIT", app->pending_recovery_key.c_str(),
                             WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_CENTER,
                             30, 130, 420, 30, w, (HMENU)IDC_RK_DISPLAY, nullptr, nullptr);
    SendMessageW(rk, WM_SETFONT, (WPARAM)theme::make_font(12, true), TRUE);
    track(app, rk);

    HWND chk = CreateWindowW(L"BUTTON", L"I have saved this recovery key.",
                              WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                              30, 180, 400, 24, w, (HMENU)IDC_RK_SAVED_CHECK, nullptr, nullptr);
    SendMessageW(chk, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    track(app, chk);

    track(app, make_button(w, L"Continue", IDC_RK_CONTINUE, 330, 220, 120, 32));
}

// ---------------------------------------------------------------------
// Screen: Unlock (installed, currently locked)
// ---------------------------------------------------------------------
static void show_unlock(AppData* app) {
    clear_screen(app);
    app->state = AppState::Unlock;
    g_using_recovery_mode = false;
    HWND w = app->main_window;

    auto& d = app->drives[app->selected_drive_index];
    std::wstringstream title;
    title << L"PenLock - Locked  (" << d.letter << L":)";
    track(app, make_label(w, title.str().c_str(), 30, 20, 420, 32, true));

    track(app, make_label(w, L"Password:", 30, 70, 150, 22));
    track(app, make_edit(w, IDC_UNLOCK_PW, 30, 95, 300, 26, true));

    track(app, make_button(w, L"Unlock", IDC_UNLOCK_BTN, 30, 135, 120, 32));

    HWND link = CreateWindowW(L"BUTTON", L"Forgot password? Use Recovery Key",
                               WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               160, 135, 260, 32, w, (HMENU)IDC_USE_RECOVERY, nullptr, nullptr);
    SendMessageW(link, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, link);

    HWND status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 30, 175, 420, 60, w,
                                 (HMENU)IDC_UNLOCK_STATUS, nullptr, nullptr);
    SendMessageW(status, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, status);
}

// ---------------------------------------------------------------------
// Screen: Unlocked dashboard
// ---------------------------------------------------------------------
static void show_unlocked(AppData* app) {
    clear_screen(app);
    app->state = AppState::Unlocked;
    HWND w = app->main_window;

    auto& d = app->drives[app->selected_drive_index];
    std::wstringstream title;
    title << L"PenLock - Unlocked  (" << d.letter << L":)";
    track(app, make_label(w, title.str().c_str(), 30, 20, 420, 32, true));

    std::string lvl_name = security_level_name(app->vault.security_level);
    std::wstringstream info;
    info << L"Status: Installed\r\n"
         << L"Version: " << PENLOCK_VERSION_STRING << L"\r\n"
         << L"Security level: " << std::wstring(lvl_name.begin(), lvl_name.end());
    HWND status = CreateWindowW(L"STATIC", info.str().c_str(), WS_CHILD | WS_VISIBLE, 30, 65, 400, 70, w,
                                 (HMENU)IDC_STATUS_INFO, nullptr, nullptr);
    SendMessageW(status, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE);
    track(app, status);

    track(app, make_button(w, L"Lock Now", IDC_LOCK_NOW, 30, 150, 140, 34));
    track(app, make_button(w, L"Open Folder", IDC_OPEN_FOLDER, 180, 150, 140, 34));
    track(app, make_button(w, L"Change Password", IDC_CHANGE_PW, 30, 195, 160, 32));
    track(app, make_button(w, L"Change Security Level", IDC_CHANGE_LEVEL, 200, 195, 200, 32));
}

// ---------------------------------------------------------------------
// Screen: Change password (reachable from the Unlocked dashboard; the
// user is already authenticated at this point via the master key held in
// memory, so this simply re-wraps that same key under a new password —
// no file re-encryption needed, since the master key itself never
// changes, only how it's protected).
// ---------------------------------------------------------------------
static void show_change_password(AppData* app) {
    clear_screen(app);
    app->state = AppState::ChangePassword;
    HWND w = app->main_window;

    track(app, make_label(w, L"Change Password", 30, 20, 300, 32, true));
    track(app, make_label(w, L"New password:", 30, 70, 200, 22));
    track(app, make_edit(w, IDC_NEWPW1, 30, 95, 300, 26, true));
    track(app, make_label(w, L"Confirm new password:", 30, 135, 200, 22));
    track(app, make_edit(w, IDC_NEWPW2, 30, 160, 300, 26, true));

    HWND status = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE, 30, 195, 400, 40, w,
                                 (HMENU)IDC_NEWPW_STATUS, nullptr, nullptr);
    SendMessageW(status, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, status);

    track(app, make_button(w, L"Save", IDC_NEWPW_SAVE, 30, 245, 120, 32));
    track(app, make_button(w, L"Cancel", IDC_NEWPW_CANCEL, 160, 245, 120, 32));
}

// ---------------------------------------------------------------------
// Screen: Change security level (also reachable from the dashboard;
// updates only the policy metadata, no file re-encryption needed).
// ---------------------------------------------------------------------
static SecurityLevel selected_new_level_from_radios(HWND w) {
    if (SendMessageW(GetDlgItem(w, IDC_NEWLVL_STANDARD), BM_GETCHECK, 0, 0) == BST_CHECKED) return SecurityLevel::Standard;
    if (SendMessageW(GetDlgItem(w, IDC_NEWLVL_HIGH), BM_GETCHECK, 0, 0) == BST_CHECKED) return SecurityLevel::High;
    if (SendMessageW(GetDlgItem(w, IDC_NEWLVL_ULTRA), BM_GETCHECK, 0, 0) == BST_CHECKED) return SecurityLevel::Ultra;
    return SecurityLevel::Normal;
}

static void show_change_security_level(AppData* app) {
    clear_screen(app);
    app->state = AppState::ChangeSecurityLevel;
    HWND w = app->main_window;

    track(app, make_label(w, L"Change Security Level", 30, 20, 400, 32, true));

    HWND r1 = CreateWindowW(L"BUTTON", L"Normal", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                             30, 65, 400, 22, w, (HMENU)IDC_NEWLVL_NORMAL, nullptr, nullptr);
    HWND r2 = CreateWindowW(L"BUTTON", L"Standard", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                             30, 90, 400, 22, w, (HMENU)IDC_NEWLVL_STANDARD, nullptr, nullptr);
    HWND r3 = CreateWindowW(L"BUTTON", L"High", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                             30, 115, 400, 22, w, (HMENU)IDC_NEWLVL_HIGH, nullptr, nullptr);
    HWND r4 = CreateWindowW(L"BUTTON", L"Ultra", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                             30, 140, 400, 22, w, (HMENU)IDC_NEWLVL_ULTRA, nullptr, nullptr);
    for (HWND r : {r1, r2, r3, r4}) { SendMessageW(r, WM_SETFONT, (WPARAM)theme::font_normal(), TRUE); track(app, r); }
    switch (app->vault.security_level) {
        case SecurityLevel::Normal:   SendMessageW(r1, BM_SETCHECK, BST_CHECKED, 0); break;
        case SecurityLevel::Standard: SendMessageW(r2, BM_SETCHECK, BST_CHECKED, 0); break;
        case SecurityLevel::High:     SendMessageW(r3, BM_SETCHECK, BST_CHECKED, 0); break;
        case SecurityLevel::Ultra:    SendMessageW(r4, BM_SETCHECK, BST_CHECKED, 0); break;
    }

    HWND desc = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT,
                               30, 175, 420, 90, w, (HMENU)IDC_NEWLVL_DESC, nullptr, nullptr);
    SendMessageW(desc, WM_SETFONT, (WPARAM)theme::font_small(), TRUE);
    track(app, desc);
    {
        std::string desc_text = security_level_description(app->vault.security_level);
        std::wstring wdesc(desc_text.begin(), desc_text.end());
        SetWindowTextW(desc, wdesc.c_str());
    }

    track(app, make_button(w, L"Save", IDC_NEWLVL_SAVE, 30, 280, 120, 32));
    track(app, make_button(w, L"Cancel", IDC_NEWLVL_CANCEL, 160, 280, 120, 32));
}

// ---------------------------------------------------------------------
// Worker launchers for Lock / Unlock file transforms and wipes
// ---------------------------------------------------------------------
static void run_lock_worker(HWND hwnd, std::wstring data_root, std::vector<uint8_t> master_key) {
    std::thread([hwnd, data_root, master_key]() {
        try {
            std::filesystem::path root(data_root);
            lock_all_files(root, master_key, [&](size_t done, size_t total, const std::string&) {
                int pct = total ? (int)(done * 100 / total) : 100;
                PostMessageW(hwnd, WM_PENLOCK_PROGRESS, pct, 100);
            });
            PostMessageW(hwnd, WM_PENLOCK_DONE, 1, 0);
        } catch (const std::exception& e) {
            std::string msg = e.what();
            std::wstring wmsg(msg.begin(), msg.end());
            wchar_t* copy = new wchar_t[wmsg.size() + 1];
            wcscpy(copy, wmsg.c_str());
            PostMessageW(hwnd, WM_PENLOCK_ERROR_TEXT, 0, (LPARAM)copy);
            PostMessageW(hwnd, WM_PENLOCK_DONE, 0, 0);
        }
    }).detach();
}

static void run_unlock_worker(HWND hwnd, std::wstring data_root, std::vector<uint8_t> master_key) {
    std::thread([hwnd, data_root, master_key]() {
        try {
            std::filesystem::path root(data_root);
            unlock_all_files(root, master_key, [&](size_t done, size_t total, const std::string&) {
                int pct = total ? (int)(done * 100 / total) : 100;
                PostMessageW(hwnd, WM_PENLOCK_PROGRESS, pct, 100);
            });
            PostMessageW(hwnd, WM_PENLOCK_DONE, 1, 0);
        } catch (const std::exception& e) {
            std::string msg = e.what();
            std::wstring wmsg(msg.begin(), msg.end());
            wchar_t* copy = new wchar_t[wmsg.size() + 1];
            wcscpy(copy, wmsg.c_str());
            PostMessageW(hwnd, WM_PENLOCK_ERROR_TEXT, 0, (LPARAM)copy);
            PostMessageW(hwnd, WM_PENLOCK_DONE, 0, 0);
        }
    }).detach();
}

static void run_wipe_worker(HWND hwnd, char letter, SecurityLevel level) {
    std::thread([hwnd, letter, level]() {
        try {
            if (level == SecurityLevel::Ultra) {
                ultra_wipe(letter, [&](uint64_t written) {
                    PostMessageW(hwnd, WM_PENLOCK_PROGRESS, (WPARAM)(written / (1024*1024)), 0);
                });
            } else {
                quick_format_data_partition(letter);
            }
            PostMessageW(hwnd, WM_PENLOCK_DONE, 1, 0);
        } catch (const std::exception& e) {
            std::string msg = e.what();
            std::wstring wmsg(msg.begin(), msg.end());
            wchar_t* copy = new wchar_t[wmsg.size() + 1];
            wcscpy(copy, wmsg.c_str());
            PostMessageW(hwnd, WM_PENLOCK_ERROR_TEXT, 0, (LPARAM)copy);
            PostMessageW(hwnd, WM_PENLOCK_DONE, 0, 0);
        }
    }).detach();
}

// ---------------------------------------------------------------------
// WM_COMMAND handling, split by current screen for readability.
// ---------------------------------------------------------------------
static void handle_select_drive_command(AppData* app, HWND w, int id) {
    if (id == IDC_REFRESH) {
        refresh_drive_list(app, GetDlgItem(w, IDC_DRIVE_COMBO));
    } else if (id == IDC_ENTER_DRIVE) {
        int sel = (int)SendMessageW(GetDlgItem(w, IDC_DRIVE_COMBO), CB_GETCURSEL, 0, 0);
        if (sel < 0 || sel >= (int)app->drives.size()) return;
        app->selected_drive_index = sel;
        auto& d = app->drives[sel];

        // Check whether this drive already has PenLock installed by
        // looking for penlock.dat on its hidden system partition.
        bool installed = false;
        try {
            with_hidden_partition_writable(d.disk_number, [&](const std::wstring& root) {
                std::wstring path = root + L"penlock.dat";
                HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE) return; // no partition 2 / no file -> not installed
                DWORD size = GetFileSize(h, nullptr);
                std::vector<uint8_t> buf(size);
                DWORD read = 0;
                ReadFile(h, buf.data(), size, &read, nullptr);
                CloseHandle(h);
                if (looks_like_vault(buf)) {
                    app->vault = deserialize_metadata(buf);
                    app->vault_disk_number = d.disk_number;
                    app->vault_data_letter = d.letter;
                    installed = true;
                }
            });
        } catch (...) {
            // No hidden PenLock partition on this drive (a stock,
            // never-installed pendrive only has one partition) —
            // with_hidden_partition_writable's partition-count check
            // throws immediately in that case, which we treat as "not
            // installed" here.
        }

        if (installed) {
            show_unlock(app);
        } else {
            show_install_security_level(app);
        }
    }
}

static SecurityLevel selected_level_from_radios(HWND w) {
    if (SendMessageW(GetDlgItem(w, IDC_RADIO_STANDARD), BM_GETCHECK, 0, 0) == BST_CHECKED) return SecurityLevel::Standard;
    if (SendMessageW(GetDlgItem(w, IDC_RADIO_HIGH), BM_GETCHECK, 0, 0) == BST_CHECKED) return SecurityLevel::High;
    if (SendMessageW(GetDlgItem(w, IDC_RADIO_ULTRA), BM_GETCHECK, 0, 0) == BST_CHECKED) return SecurityLevel::Ultra;
    return SecurityLevel::Normal;
}

static void handle_install_security_command(AppData* app, HWND w, int id) {
    if (id >= IDC_RADIO_NORMAL && id <= IDC_RADIO_ULTRA) {
        update_level_description(w, selected_level_from_radios(w));
    } else if (id == IDC_LEVEL_NEXT) {
        app->chosen_level = selected_level_from_radios(w);
        show_install_warning(app);
    }
}

static void handle_install_warning_command(AppData* app, HWND w, int id) {
    if (id == IDC_WARNING_OK) {
        bool checked = SendMessageW(GetDlgItem(w, IDC_UNDERSTAND_CHECK), BM_GETCHECK, 0, 0) == BST_CHECKED;
        if (!checked) {
            MessageBoxW(w, L"Please check the box to confirm you've read this.", L"PenLock", MB_ICONINFORMATION);
            return;
        }
        show_install_password(app);
    }
}

static void handle_install_password_command(AppData* app, HWND w, int id) {
    if (id == IDC_INSTALL_BTN) {
        std::wstring pw1 = get_text(GetDlgItem(w, IDC_PW1));
        std::wstring pw2 = get_text(GetDlgItem(w, IDC_PW2));
        if (pw1.length() < 6) {
            SetDlgItemTextW(w, IDC_PW_STATUS, L"Password must be at least 6 characters.");
            return;
        }
        if (pw1 != pw2) {
            SetDlgItemTextW(w, IDC_PW_STATUS, L"Passwords do not match.");
            return;
        }
        app->pending_password = pw1;
        show_install_confirm(app);
    }
}

static void handle_install_confirm_command(AppData* app, HWND w, int id) {
    if (id == IDC_CONFIRM_CANCEL) {
        show_select_drive(app);
    } else if (id == IDC_CONFIRM_GO) {
        show_install_progress(app);
    }
}

static void handle_install_recovery_key_command(AppData* app, HWND w, int id) {
    if (id == IDC_RK_CONTINUE) {
        bool checked = SendMessageW(GetDlgItem(w, IDC_RK_SAVED_CHECK), BM_GETCHECK, 0, 0) == BST_CHECKED;
        if (!checked) {
            MessageBoxW(w, L"Please confirm you've saved the recovery key.", L"PenLock", MB_ICONINFORMATION);
            return;
        }
        // Fresh install, nothing to decrypt yet — go straight to the
        // unlocked dashboard using the master key we already have.
        show_unlocked(app);
    }
}

static void handle_unlock_command(AppData* app, HWND w, int id) {
    if (id == IDC_USE_RECOVERY) {
        g_using_recovery_mode = !g_using_recovery_mode;
        SetDlgItemTextW(w, IDC_UNLOCK_BTN, g_using_recovery_mode ? L"Unlock with Recovery Key" : L"Unlock");
        SetDlgItemTextW(w, IDC_USE_RECOVERY, g_using_recovery_mode ? L"Use password instead" : L"Forgot password? Use Recovery Key");
        return;
    }
    if (id != IDC_UNLOCK_BTN) return;

    std::wstring input = get_text(GetDlgItem(w, IDC_UNLOCK_PW));
    std::string input_utf8 = wstring_to_utf8(input);

    if (g_using_recovery_mode) {
        auto outcome = attempt_unlock_with_recovery_key(app->vault, input_utf8);
        persist_vault(app);
        if (outcome.result == UnlockResult::Success) {
            app->master_key = outcome.master_key;
            std::wstring root = std::wstring(1, (wchar_t)app->vault_data_letter) + L":\\";
            app->pending_action = PendingAction::Unlocking;
            show_progress_screen(app, AppState::Unlock, L"Unlocking...");
            run_unlock_worker(app->main_window, root, app->master_key);
        } else {
            SetDlgItemTextW(w, IDC_UNLOCK_STATUS, L"Recovery key not recognized.");
        }
        return;
    }

    auto outcome = attempt_unlock(app->vault, input_utf8, now_unix());
    persist_vault(app);

    switch (outcome.result) {
        case UnlockResult::Success: {
            app->master_key = outcome.master_key;
            std::wstring root = std::wstring(1, (wchar_t)app->vault_data_letter) + L":\\";
            app->pending_action = PendingAction::Unlocking;
            show_progress_screen(app, AppState::Unlock, L"Unlocking...");
            run_unlock_worker(app->main_window, root, app->master_key);
            break;
        }
        case UnlockResult::WrongPassword:
            SetDlgItemTextW(w, IDC_UNLOCK_STATUS, L"Wrong password. Please try again.");
            break;
        case UnlockResult::LockedOut: {
            std::wstringstream ss;
            ss << L"Too many wrong attempts. Try again in " << (outcome.lockout_seconds_left / 60) << L" minutes.";
            SetDlgItemTextW(w, IDC_UNLOCK_STATUS, ss.str().c_str());
            break;
        }
        case UnlockResult::WipeTriggered: {
            SetDlgItemTextW(w, IDC_UNLOCK_STATUS, L"Wrong password limit reached. Wiping data...");
            app->pending_action = PendingAction::Wiping;
            show_progress_screen(app, AppState::Unlock, L"Wiping data (security policy triggered)...");
            run_wipe_worker(app->main_window, app->vault_data_letter, app->vault.security_level);
            break;
        }
    }
}

static void handle_unlocked_command(AppData* app, HWND w, int id) {
    if (id == IDC_LOCK_NOW) {
        std::wstring root = std::wstring(1, (wchar_t)app->vault_data_letter) + L":\\";
        app->pending_action = PendingAction::Locking;
        show_progress_screen(app, AppState::Unlocked, L"Locking...");
        run_lock_worker(app->main_window, root, app->master_key);
    } else if (id == IDC_OPEN_FOLDER) {
        std::wstring root = std::wstring(1, (wchar_t)app->vault_data_letter) + L":\\";
        ShellExecuteW(nullptr, L"open", root.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    } else if (id == IDC_CHANGE_PW) {
        show_change_password(app);
    } else if (id == IDC_CHANGE_LEVEL) {
        show_change_security_level(app);
    }
}

static void handle_change_password_command(AppData* app, HWND w, int id) {
    if (id == IDC_NEWPW_CANCEL) {
        show_unlocked(app);
        return;
    }
    if (id != IDC_NEWPW_SAVE) return;

    std::wstring pw1 = get_text(GetDlgItem(w, IDC_NEWPW1));
    std::wstring pw2 = get_text(GetDlgItem(w, IDC_NEWPW2));
    if (pw1.length() < 6) {
        SetDlgItemTextW(w, IDC_NEWPW_STATUS, L"Password must be at least 6 characters.");
        return;
    }
    if (pw1 != pw2) {
        SetDlgItemTextW(w, IDC_NEWPW_STATUS, L"Passwords do not match.");
        return;
    }
    if (app->master_key.empty()) {
        // Shouldn't happen (this screen is only reachable while
        // unlocked), but guard against it rather than wrap garbage.
        SetDlgItemTextW(w, IDC_NEWPW_STATUS, L"Internal error: no key in memory. Please lock and unlock again.");
        return;
    }

    std::string pw_utf8 = wstring_to_utf8(pw1);
    auto wrap = wrap_master_key(app->master_key, pw_utf8, app->vault.pbkdf2_iterations);
    app->vault.pw_salt = wrap.salt;
    app->vault.pw_wrap_iv = wrap.iv;
    app->vault.pw_wrapped_key = wrap.wrapped;
    app->vault.failed_attempts = 0;
    app->vault.lockout_until_unix = 0;
    persist_vault(app);

    MessageBoxW(w, L"Password changed. Your recovery key from installation still works "
                    L"unless you change it too (recovery key rotation isn't available yet).",
                L"PenLock", MB_ICONINFORMATION);
    show_unlocked(app);
}

static void handle_change_security_level_command(AppData* app, HWND w, int id) {
    if (id >= IDC_NEWLVL_NORMAL && id <= IDC_NEWLVL_ULTRA) {
        std::string desc_text = security_level_description(selected_new_level_from_radios(w));
        std::wstring wdesc(desc_text.begin(), desc_text.end());
        SetDlgItemTextW(w, IDC_NEWLVL_DESC, wdesc.c_str());
        return;
    }
    if (id == IDC_NEWLVL_CANCEL) {
        show_unlocked(app);
        return;
    }
    if (id != IDC_NEWLVL_SAVE) return;

    SecurityLevel new_level = selected_new_level_from_radios(w);
    if (new_level == SecurityLevel::High || new_level == SecurityLevel::Ultra) {
        std::string desc_text = security_level_description(new_level);
        std::wstring wdesc(desc_text.begin(), desc_text.end());
        std::wstring prompt = L"You're switching to a level where wrong passwords DELETE your files:\n\n" +
                               wdesc + L"\n\nContinue?";
        if (MessageBoxW(w, prompt.c_str(), L"PenLock - Confirm", MB_ICONWARNING | MB_YESNO) != IDYES) {
            return;
        }
    }
    app->vault.security_level = new_level;
    app->vault.failed_attempts = 0;
    app->vault.lockout_until_unix = 0;
    persist_vault(app);
    show_unlocked(app);
}

// ---------------------------------------------------------------------
// Progress-screen completion handling (shared by install/lock/unlock/wipe)
// ---------------------------------------------------------------------
static void handle_progress_done(AppData* app, bool success) {
    switch (app->pending_action) {
        case PendingAction::Unlocking:
            app->pending_action = PendingAction::None;
            if (success) show_unlocked(app);
            else show_unlock(app); // decrypt failed after a supposedly-correct password: treat as failure, stay locked
            return;
        case PendingAction::Locking:
            app->pending_action = PendingAction::None;
            if (success) {
                if (!app->master_key.empty()) std::memset(app->master_key.data(), 0, app->master_key.size());
                app->master_key.clear();
                show_unlock(app);
            } else {
                show_unlocked(app);
            }
            return;
        case PendingAction::Wiping:
            app->pending_action = PendingAction::None;
            // Whether the wipe succeeded or failed, the user never
            // authenticated — always return to the (still locked) Unlock
            // screen, never to the Unlocked dashboard. Reset the attempt
            // counter now that the punitive wipe has run its course.
            app->vault.failed_attempts = 0;
            persist_vault(app);
            show_unlock(app);
            if (success) SetDlgItemTextW(app->main_window, IDC_UNLOCK_STATUS, L"Data wiped due to too many wrong attempts. Vault is still installed.");
            return;
        case PendingAction::None:
        default:
            // Only the install flow reaches here (handled directly in the
            // WM_PENLOCK_DONE case in the WndProc, not through this path).
            if (app->state == AppState::InstallProgress && !success) show_install_security_level(app);
            return;
    }
}

// ---------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------
LRESULT CALLBACK main_window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    AppData* app = get_app(hwnd);

    switch (msg) {
        case WM_CREATE: {
            auto* new_app = new AppData();
            new_app->main_window = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)new_app);
            add_tray_icon(hwnd);
            show_select_drive(new_app);
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = (HDC)wparam;
            SetTextColor(dc, theme::TEXT_PRIMARY);
            SetBkColor(dc, theme::BG_DARK);
            return (LRESULT)theme::bg_brush();
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = (HDC)wparam;
            SetTextColor(dc, theme::TEXT_PRIMARY);
            SetBkColor(dc, theme::BG_PANEL);
            return (LRESULT)theme::panel_brush();
        }
        case WM_ERASEBKGND: {
            HDC dc = (HDC)wparam;
            RECT rc; GetClientRect(hwnd, &rc);
            FillRect(dc, &rc, theme::bg_brush());
            return 1;
        }
        case WM_COMMAND: {
            if (!app) break;
            int id = LOWORD(wparam);
            switch (app->state) {
                case AppState::SelectDrive: handle_select_drive_command(app, hwnd, id); break;
                case AppState::InstallSecurityLevel: handle_install_security_command(app, hwnd, id); break;
                case AppState::InstallWarning: handle_install_warning_command(app, hwnd, id); break;
                case AppState::InstallPassword: handle_install_password_command(app, hwnd, id); break;
                case AppState::InstallConfirm: handle_install_confirm_command(app, hwnd, id); break;
                case AppState::InstallRecoveryKey: handle_install_recovery_key_command(app, hwnd, id); break;
                case AppState::Unlock: handle_unlock_command(app, hwnd, id); break;
                case AppState::Unlocked: handle_unlocked_command(app, hwnd, id); break;
                case AppState::ChangePassword: handle_change_password_command(app, hwnd, id); break;
                case AppState::ChangeSecurityLevel: handle_change_security_level_command(app, hwnd, id); break;
                default: break;
            }
            // Tray menu commands can arrive as WM_COMMAND too (from TrackPopupMenu).
            if (id == ID_TRAY_EXIT) DestroyWindow(hwnd);
            else if (id == ID_TRAY_OPEN) { ShowWindow(hwnd, SW_RESTORE); SetForegroundWindow(hwnd); }
            else if (id == ID_TRAY_LOCK_NOW && app->state == AppState::Unlocked) handle_unlocked_command(app, hwnd, IDC_LOCK_NOW);
            return 0;
        }
        case WM_PENLOCK_PROGRESS: {
            HWND bar = GetDlgItem(hwnd, IDC_PROGRESS_BAR);
            if (bar) SendMessageW(bar, PBM_SETPOS, wparam, 0);
            return 0;
        }
        case WM_PENLOCK_STEP_TEXT: {
            wchar_t* text = (wchar_t*)lparam;
            SetDlgItemTextW(hwnd, IDC_PROGRESS_TEXT, text);
            delete[] text;
            return 0;
        }
        case WM_PENLOCK_ERROR_TEXT: {
            wchar_t* text = (wchar_t*)lparam;
            MessageBoxW(hwnd, text, L"PenLock - Error", MB_ICONERROR);
            delete[] text;
            return 0;
        }
        case WM_PENLOCK_DONE: {
            if (!app) return 0;
            bool success = wparam != 0;
            if (app->state == AppState::InstallProgress && success && lparam) {
                struct InstallResult { std::wstring recovery; std::vector<uint8_t> master; char letter; SecurityLevel level; };
                auto* result = (InstallResult*)lparam;
                app->pending_recovery_key = result->recovery;
                app->master_key = result->master;
                app->vault_data_letter = result->letter;
                app->vault_disk_number = app->drives[app->selected_drive_index].disk_number;
                app->vault.security_level = result->level;
                delete result;
                show_install_recovery_key(app);
            } else {
                handle_progress_done(app, success);
            }
            return 0;
        }
        case WM_PENLOCK_TRAY: {
            if (lparam == WM_RBUTTONUP || lparam == WM_LBUTTONUP) show_tray_context_menu(hwnd);
            return 0;
        }
        case WM_DEVICECHANGE: {
            // Best-effort only: this fires AFTER the drive has already
            // disconnected (DBT_DEVICEREMOVECOMPLETE), so PenLock cannot
            // write a re-encrypted copy back to a drive that is no longer
            // there. What this CAN do is notice an unsafe removal while
            // unlocked and warn the user, and clear the master key from
            // memory. A true "lock before the drive is allowed to
            // disconnect" would need DBT_DEVICEQUERYREMOVE via
            // RegisterDeviceNotification on the volume handle, which is
            // not implemented in this first pass — see README.md
            // "Known gaps". The safe workflow in the meantime is to use
            // "Lock Now" before physically removing the drive.
            if (!app) break;
            if (wparam == DBT_DEVICEREMOVECOMPLETE && app->state == AppState::Unlocked) {
                auto* hdr = (DEV_BROADCAST_HDR*)lparam;
                if (hdr && hdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                    auto* vol = (DEV_BROADCAST_VOLUME*)hdr;
                    bool our_drive = app->vault_data_letter >= 'A' &&
                                      (vol->dbcv_unitmask & (1u << (app->vault_data_letter - 'A'))) != 0;
                    if (our_drive) {
                        if (!app->master_key.empty()) std::memset(app->master_key.data(), 0, app->master_key.size());
                        app->master_key.clear();
                        show_select_drive(app);
                        MessageBoxW(hwnd,
                            L"The drive was removed while unlocked. If it wasn't safely "
                            L"ejected first, files may still be in plaintext on it. "
                            L"Re-insert it and use \"Lock Now\" to re-encrypt them.",
                            L"PenLock", MB_ICONWARNING);
                    }
                }
            }
            break;
        }
        case WM_SIZE: {
            if (wparam == SIZE_MINIMIZED) { ShowWindow(hwnd, SW_HIDE); return 0; }
            break;
        }
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE); // minimize to tray instead of quitting
            return 0;
        case WM_DESTROY: {
            remove_tray_icon(hwnd);
            if (app) delete app;
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

ATOM register_main_window_class(HINSTANCE instance) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = main_window_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = theme::bg_brush();
    wc.lpszClassName = PENLOCK_WINDOW_CLASS;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1)); // IDI_APPICON, see resource.rc
    return RegisterClassExW(&wc);
}

HWND create_main_window(HINSTANCE instance) {
    return CreateWindowExW(0, PENLOCK_WINDOW_CLASS, L"PenLock",
                            WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
                            CW_USEDEFAULT, CW_USEDEFAULT, 500, 460,
                            nullptr, nullptr, instance, nullptr);
}
