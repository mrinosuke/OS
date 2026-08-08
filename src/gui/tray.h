// tray.h - System tray icon with a small right-click menu (Open, Lock Now,
// Exit). Windows-only.
#pragma once
#ifndef _WIN32
#error "tray.h is Windows-only"
#endif
#include <windows.h>
#include "main_window.h"

#define TRAY_ICON_UID 1
#define ID_TRAY_OPEN     40001
#define ID_TRAY_LOCK_NOW 40002
#define ID_TRAY_EXIT     40003

inline void add_tray_icon(HWND hwnd) {
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_UID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_PENLOCK_TRAY;
    nid.hIcon = LoadIconW(nullptr, IDI_SHIELD); // placeholder; replace with app.ico via LoadIcon(hinstance, ...)
    wcscpy_s(nid.szTip, L"PenLock");
    Shell_NotifyIconW(NIM_ADD, &nid);
}

inline void remove_tray_icon(HWND hwnd) {
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_UID;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

inline void show_tray_context_menu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, L"Open PenLock");
    AppendMenuW(menu, MF_STRING, ID_TRAY_LOCK_NOW, L"Lock Now");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Exit");

    // Required so the popup menu closes properly if the user clicks away.
    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    PostMessage(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}
