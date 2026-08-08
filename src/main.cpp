// main.cpp - PenLock entry point.
//
// Handles:
//   - Requesting Administrator elevation (required for diskpart/raw disk
//     operations) by relaunching itself via ShellExecute "runas" if not
//     already elevated.
//   - Registering the main window class and message loop.
//
// Device-removal handling (for auto-lock-on-eject) lives in
// main_window.cpp's WM_DEVICECHANGE case, kept there for locality with
// AppState. See README.md "Known gaps" for its current limitations.
//
// Windows-only. Cannot be compiled or run outside Windows/mingw-w64.
#ifndef _WIN32
#error "main.cpp is Windows-only"
#endif
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include "gui/main_window.h"

static bool is_running_elevated() {
    BOOL is_elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(elevation);
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            is_elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return is_elevated;
}

static void relaunch_elevated() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (!ShellExecuteExW(&sei)) {
        // User declined the UAC prompt or it failed outright — PenLock
        // cannot do partition/disk operations without elevation, so it
        // has to exit rather than run in a half-working state.
        MessageBoxW(nullptr,
                    L"PenLock needs Administrator access to manage USB partitions and "
                    L"encryption. Please allow the permission prompt to continue.",
                    L"PenLock", MB_ICONWARNING);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_cmd) {
    if (!is_running_elevated()) {
        relaunch_elevated();
        return 0; // this (non-elevated) instance exits; the elevated one takes over
    }

    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    register_main_window_class(instance);
    HWND hwnd = create_main_window(instance);
    if (!hwnd) return 1;

    ShowWindow(hwnd, show_cmd);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
