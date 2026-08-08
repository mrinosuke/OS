// main_window.h - PenLock's single main window (all screens are child
// controls swapped in/out based on AppState). Windows-only.
#pragma once
#ifndef _WIN32
#error "main_window.h is Windows-only"
#endif
#include <windows.h>

extern const wchar_t* PENLOCK_WINDOW_CLASS;
extern const wchar_t* PENLOCK_VERSION_STRING;

// Custom messages posted from worker threads back to the main window.
#define WM_PENLOCK_PROGRESS   (WM_APP + 1) // wParam=done, lParam=total
#define WM_PENLOCK_STEP_TEXT  (WM_APP + 2) // lParam = heap wchar_t* (owned by receiver, must delete[])
#define WM_PENLOCK_DONE       (WM_APP + 3) // wParam = 1 success / 0 failure
#define WM_PENLOCK_ERROR_TEXT (WM_APP + 4) // lParam = heap wchar_t* (owned by receiver, must delete[])
#define WM_PENLOCK_TRAY       (WM_APP + 10) // tray icon callback

ATOM register_main_window_class(HINSTANCE instance);
HWND create_main_window(HINSTANCE instance);
LRESULT CALLBACK main_window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
