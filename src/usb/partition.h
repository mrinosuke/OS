// partition.h - Creates and manages PenLock's 2-partition USB layout using
// Windows' own `diskpart` tool (scripted via a temp file), rather than
// hand-rolling MBR/GPT byte manipulation. This is deliberately the
// "boring and reliable" choice: diskpart is what Windows itself uses
// internally, so it handles partition table format correctly, and any
// bug is far more likely to be in our script logic (easy to read/fix)
// than in low-level disk structure handling.
//
// Layout created at install time:
//   Partition 1 ("PenLock")   - exFAT, most of the capacity, holds the
//                               user's files (as encrypted .plk blobs
//                               while locked, real files while unlocked).
//   Partition 2 ("PLSYS")     - NTFS, ~64 MB, holds PenLock's own program
//                               copy + vault metadata. Never assigned a
//                               drive letter except briefly when PenLock
//                               itself needs to read/write it, so Windows
//                               Explorer does not show it. This mirrors
//                               how Ventoy hides its own system partition.
//
// IMPORTANT CAVEAT (documented honestly, not hidden): "hidden" here means
// "no drive letter, so File Explorer will not show it by casual browsing".
// It is still fully visible to Disk Management, `diskpart list volume`,
// and any forensic/recovery tool. This is NOT the same guarantee as a
// dedicated hardware-encrypted USB device. See README.md.
//
// Windows-only. Cannot be compiled/tested outside Windows/mingw-w64.
#pragma once
#ifndef _WIN32
#error "partition.h is Windows-only"
#endif

#include <windows.h>
#include <string>
#include <sstream>
#include <fstream>
#include <functional>
#include <stdexcept>
#include <cctype>
#include "usb_detect.h"

// Runs a diskpart script (a sequence of diskpart commands) and returns its
// combined stdout/stderr text. Throws if diskpart itself fails to launch.
// Requires the calling process to already be elevated (Administrator) —
// diskpart will refuse destructive commands otherwise and this function
// will surface that failure in the returned output text.
inline std::string run_diskpart_script(const std::wstring& script) {
    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);
    wchar_t script_path[MAX_PATH];
    GetTempFileNameW(temp_dir, L"plk", 0, script_path);

    {
        std::wofstream f(script_path);
        f << script;
    }

    wchar_t out_path[MAX_PATH];
    GetTempFileNameW(temp_dir, L"plo", 0, out_path);

    std::wstring cmd = L"diskpart.exe /s \"" + std::wstring(script_path) + L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE out_handle = CreateFileW(out_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    si.hStdOutput = out_handle;
    si.hStdError = out_handle;

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(0);

    BOOL ok = CreateProcessW(nullptr, cmd_buf.data(), nullptr, nullptr, TRUE,
                              CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (out_handle) CloseHandle(out_handle);

    if (!ok) {
        DeleteFileW(script_path);
        DeleteFileW(out_path);
        throw std::runtime_error("failed to launch diskpart.exe (are we elevated?)");
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::wifstream result_file(out_path);
    std::wstringstream ss;
    ss << result_file.rdbuf();
    std::wstring wout = ss.str();

    DeleteFileW(script_path);
    DeleteFileW(out_path);

    // crude wide->narrow for logging/error messages (script output is ASCII)
    std::string out(wout.begin(), wout.end());
    return out;
}

// Wipes the disk and creates PenLock's 2-partition layout. hidden_size_mb
// controls how much space is reserved for the system partition; the
// visible data partition gets the remainder.
inline void create_penlock_layout(uint32_t disk_number, uint32_t hidden_size_mb = 64) {
    std::wstringstream script;
    script << L"select disk " << disk_number << L"\r\n"
           << L"clean\r\n"
           << L"convert mbr\r\n"
           << L"create partition primary\r\n"
           << L"shrink desired=" << hidden_size_mb << L"\r\n"
           << L"format fs=exfat quick label=\"PenLock\"\r\n"
           << L"assign\r\n"
           << L"create partition primary\r\n"
           << L"format fs=ntfs quick label=\"PLSYS\"\r\n"
           << L"exit\r\n";

    std::string output = run_diskpart_script(script.str());
    // diskpart prints "DiskPart successfully..." on success for each step;
    // a simple heuristic check for common failure phrases. The full output
    // is included in the exception so the GUI can show it for debugging.
    if (output.find("Virtual Disk Service error") != std::string::npos ||
        output.find("The parameter is incorrect") != std::string::npos ||
        output.find("cannot find") != std::string::npos) {
        throw std::runtime_error("diskpart reported an error:\n" + output);
    }
}

inline char find_drive_letter_for_disk(uint32_t disk_number) {
    DWORD drive_mask = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(drive_mask & (1u << i))) continue;
        char letter = static_cast<char>('A' + i);
        uint32_t dn;
        if (get_physical_disk_number(letter, dn) && dn == disk_number) return letter;
    }
    return 0;
}

// Returns how many partitions diskpart reports on the given disk. Used as
// a safety pre-check before selecting/assigning partition 2: diskpart's
// scripted mode does NOT reliably abort when a "select" command fails
// (it logs an error and carries on to the next line), so blindly running
// "select partition 2" + "assign" against a disk that only has one
// partition could otherwise do something undefined rather than cleanly
// fail. Checking the partition count first avoids that.
inline int count_partitions_on_disk(uint32_t disk_number) {
    std::wstringstream script;
    script << L"select disk " << disk_number << L"\r\n"
           << L"list partition\r\n"
           << L"exit\r\n";
    std::string output = run_diskpart_script(script.str());
    int count = 0;
    size_t pos = 0;
    while ((pos = output.find("Partition ", pos)) != std::string::npos) {
        // Real rows look like "  Partition 1    Primary  ...". The report's
        // header row is "  Partition ###  Type ..." — its next token is
        // literal "###", not a digit, so checking for a digit right after
        // "Partition " filters the header out without needing full parsing.
        size_t after = pos + 10;
        if (after < output.size() && isdigit(static_cast<unsigned char>(output[after]))) {
            ++count;
        }
        pos = after;
    }
    return count;
}

// Temporarily assigns a drive letter to the hidden system partition
// (partition 2), runs `action(path)` with the resulting root path (e.g.
// "X:\\"), then removes the letter again so the partition goes back to
// being hidden from Explorer. The letter is removed even if `action`
// throws, so a bug in the caller can't accidentally leave partition 2
// permanently visible.
inline void with_hidden_partition_writable(uint32_t disk_number,
                                            const std::function<void(const std::wstring& root_path)>& action) {
    if (count_partitions_on_disk(disk_number) < 2) {
        throw std::runtime_error("no PenLock hidden partition on this drive (not installed)");
    }

    // Snapshot which drive letters exist BEFORE assigning partition 2, so
    // we can identify the letter diskpart picks by diffing before/after —
    // this avoids ambiguity with partition 1 (on the same disk_number),
    // which already has its own, different letter from install time.
    DWORD letters_before = GetLogicalDrives();

    std::wstringstream assign_script;
    assign_script << L"select disk " << disk_number << L"\r\n"
                  << L"select partition 2\r\n"
                  << L"assign\r\n"
                  << L"exit\r\n";
    run_diskpart_script(assign_script.str());

    Sleep(500); // give Windows a moment to mount the volume before we probe it
    DWORD letters_after = GetLogicalDrives();
    DWORD new_letters = letters_after & ~letters_before;

    char letter = 0;
    for (int i = 0; i < 26; ++i) {
        if (new_letters & (1u << i)) { letter = static_cast<char>('A' + i); break; }
    }

    std::wstring cleanup_script;
    {
        std::wstringstream ss;
        ss << L"select disk " << disk_number << L"\r\n"
           << L"select partition 2\r\n"
           << L"remove\r\n"
           << L"exit\r\n";
        cleanup_script = ss.str();
    }

    try {
        if (letter == 0) throw std::runtime_error("could not locate newly assigned hidden partition letter");
        std::wstring root = std::wstring(1, static_cast<wchar_t>(letter)) + L":\\";
        action(root);
    } catch (...) {
        run_diskpart_script(cleanup_script);
        throw;
    }
    run_diskpart_script(cleanup_script);
}
