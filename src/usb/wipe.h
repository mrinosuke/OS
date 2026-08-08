// wipe.h - Destructive data-wipe operations triggered by High/Ultra
// security levels after too many wrong passwords (see lock_manager.h).
//
// *** THIS CODE IS IRREVERSIBLE BY DESIGN. TEST ONLY ON A SPARE/SCRATCH
// USB DRIVE WITH NO IMPORTANT DATA BEFORE RELYING ON IT. ***
//
// Windows-only. Cannot be compiled/tested outside Windows/mingw-w64.
#pragma once
#ifndef _WIN32
#error "wipe.h is Windows-only"
#endif

#include <windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>
#include <functional>
#include <algorithm>
#include "partition.h"

// High-level wipe: quick-formats the visible data partition. This is fast
// and makes files inaccessible through normal means (Explorer, most
// recovery-by-mistake scenarios), but does NOT overwrite the underlying
// bytes — a dedicated forensic tool could still potentially recover data
// after this step alone. That stronger guarantee is what Ultra adds via
// free_space_overwrite() below.
inline void quick_format_data_partition(char drive_letter) {
    std::wstringstream script;
    script << L"select volume " << static_cast<wchar_t>(drive_letter) << L"\r\n"
           << L"format fs=exfat quick label=\"PenLock\"\r\n"
           << L"exit\r\n";
    std::string output = run_diskpart_script(script.str());
    if (output.find("Virtual Disk Service error") != std::string::npos) {
        throw std::runtime_error("diskpart wipe/format failed:\n" + output);
    }
}

// Ultra-level anti-forensic step: after the quick format above, fills all
// remaining free space with junk data (via a growing "rm.txt" file) so
// that the raw bytes formerly belonging to deleted files are overwritten
// and cannot be recovered with data-recovery tools, then deletes the
// filler file. Writes in fixed-size chunks and simply stops when the
// filesystem reports "disk full" — that is the expected, successful
// termination condition, not an error.
inline void free_space_overwrite(char drive_letter, std::function<void(uint64_t written_bytes)> on_progress = nullptr) {
    std::wstring path = std::wstring(1, static_cast<wchar_t>(drive_letter)) + L":\\rm.txt";

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("free_space_overwrite: could not create rm.txt");
    }

    const DWORD CHUNK = 4 * 1024 * 1024; // 4 MB chunks
    std::vector<uint8_t> buffer(CHUNK);
    // Content doesn't need to be cryptographically random for this purpose
    // (we're overwriting old plaintext remnants, not creating new secrets);
    // a fixed non-zero pattern is fine and avoids relying on RNG throughput
    // for what may be gigabytes of data.
    std::fill(buffer.begin(), buffer.end(), static_cast<uint8_t>(0x00));

    uint64_t total_written = 0;
    for (;;) {
        DWORD written = 0;
        BOOL ok = WriteFile(h, buffer.data(), CHUNK, &written, nullptr);
        if (!ok || written == 0) {
            DWORD err = GetLastError();
            // ERROR_DISK_FULL (112) is the expected way this loop ends.
            if (err != ERROR_DISK_FULL && err != ERROR_HANDLE_DISK_FULL) {
                CloseHandle(h);
                DeleteFileW(path.c_str());
                throw std::runtime_error("free_space_overwrite: unexpected write error " + std::to_string(err));
            }
            break;
        }
        total_written += written;
        if (on_progress) on_progress(total_written);
    }

    CloseHandle(h);
    DeleteFileW(path.c_str());
}

// Full Ultra-level wipe: format + overwrite free space in one call.
inline void ultra_wipe(char drive_letter, std::function<void(uint64_t)> on_progress = nullptr) {
    quick_format_data_partition(drive_letter);
    free_space_overwrite(drive_letter, on_progress);
}
