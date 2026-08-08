// theme.h - Color palette and small GDI helpers for PenLock's dark UI.
// Windows-only.
#pragma once
#ifndef _WIN32
#error "theme.h is Windows-only"
#endif
#include <windows.h>

namespace theme {
    constexpr COLORREF BG_DARK      = RGB(24, 26, 32);
    constexpr COLORREF BG_PANEL     = RGB(32, 35, 43);
    constexpr COLORREF ACCENT       = RGB(88, 141, 255);   // primary blue
    constexpr COLORREF ACCENT_HOVER = RGB(110, 158, 255);
    constexpr COLORREF DANGER       = RGB(230, 76, 76);    // High/Ultra warnings
    constexpr COLORREF WARNING      = RGB(230, 170, 60);   // Standard warnings
    constexpr COLORREF SUCCESS      = RGB(76, 200, 130);
    constexpr COLORREF TEXT_PRIMARY = RGB(235, 237, 240);
    constexpr COLORREF TEXT_MUTED   = RGB(150, 155, 165);
    constexpr COLORREF BORDER       = RGB(55, 59, 70);

    inline HBRUSH brush(COLORREF c) { return CreateSolidBrush(c); }

    // Cached brushes for WM_CTLCOLOR* handlers (created once, never freed —
    // acceptable for the lifetime of this single-window application).
    inline HBRUSH bg_brush()    { static HBRUSH b = brush(BG_DARK);  return b; }
    inline HBRUSH panel_brush() { static HBRUSH b = brush(BG_PANEL); return b; }

    inline HFONT make_font(int point_size, bool bold = false) {
        HDC dc = GetDC(nullptr);
        int height = -MulDiv(point_size, GetDeviceCaps(dc, LOGPIXELSY), 72);
        ReleaseDC(nullptr, dc);
        return CreateFontW(height, 0, 0, 0, bold ? FW_BOLD : FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    }

    inline HFONT font_normal() { static HFONT f = make_font(10); return f; }
    inline HFONT font_title()  { static HFONT f = make_font(16, true); return f; }
    inline HFONT font_small()  { static HFONT f = make_font(9); return f; }
}
