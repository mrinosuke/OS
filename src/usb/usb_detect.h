// usb_detect.h - Enumerates removable USB drives only (never fixed disks,
// system drives, or NVMe). Windows-only.
//
// NOTE: this file uses the Windows SDK and cannot be compiled or tested
// outside Windows/mingw-w64. It was written carefully against documented
// WinAPI behavior but has NOT been run on real hardware yet — treat the
// first build as a debugging pass, not a finished feature. See README.md.
#pragma once
#ifndef _WIN32
#error "usb_detect.h is Windows-only"
#endif

#include <windows.h>
#include <winioctl.h>
#include <string>
#include <vector>
#include <cstdint>

struct UsbDriveInfo {
    char     letter;        // 'G', 'H', ...
    std::wstring label;     // volume label, e.g. "ADATA UV150" or "" if none
    uint64_t total_bytes;   // capacity
    uint32_t disk_number;   // physical disk index, needed later for diskpart
};

// Maps a drive letter (e.g. "G:") to its underlying physical disk number,
// which diskpart needs ("select disk N"). A removable USB drive normally
// maps to exactly one physical disk with exactly one extent.
inline bool get_physical_disk_number(char letter, uint32_t& out_disk_number) {
    std::wstring path = L"\\\\.\\";
    path += static_cast<wchar_t>(letter);
    path += L":";

    HANDLE h = CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    VOLUME_DISK_EXTENTS extents{};
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                               nullptr, 0, &extents, sizeof(extents),
                               &bytes_returned, nullptr);
    CloseHandle(h);
    if (!ok || extents.NumberOfDiskExtents < 1) return false;

    out_disk_number = extents.Extents[0].DiskNumber;
    return true;
}

// Returns true if the physical disk at the given drive letter is USB /
// removable media (as opposed to an internal SSD/NVMe/HDD). Uses
// IOCTL_STORAGE_QUERY_PROPERTY on the physical drive rather than trusting
// GetDriveType() alone, since some external HDDs report DRIVE_FIXED even
// over USB and we want to be conservative either way (PenLock should only
// ever touch drives the user clearly intends: actual USB flash drives).
inline bool is_usb_removable_disk(uint32_t disk_number) {
    wchar_t path[64];
    swprintf(path, 64, L"\\\\.\\PhysicalDrive%u", disk_number);

    HANDLE h = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    BYTE buffer[1024];
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                               &query, sizeof(query), buffer, sizeof(buffer),
                               &bytes_returned, nullptr);
    CloseHandle(h);
    if (!ok) return false;

    auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);
    // BusTypeUsb == 0x07 in the STORAGE_BUS_TYPE enum.
    return desc->BusType == BusTypeUsb;
}

// Enumerates all currently-connected USB removable drives with an
// assigned drive letter. NVMe, SATA/internal SSD/HDD, and network drives
// are excluded on two levels: GetDriveType() must report DRIVE_REMOVABLE,
// AND the underlying physical disk must report BusTypeUsb.
inline std::vector<UsbDriveInfo> enumerate_usb_drives() {
    std::vector<UsbDriveInfo> result;
    DWORD drive_mask = GetLogicalDrives();

    for (int i = 0; i < 26; ++i) {
        if (!(drive_mask & (1u << i))) continue;
        char letter = static_cast<char>('A' + i);
        std::wstring root = std::wstring(1, static_cast<wchar_t>(letter)) + L":\\";

        UINT type = GetDriveTypeW(root.c_str());
        if (type != DRIVE_REMOVABLE) continue;

        uint32_t disk_number;
        if (!get_physical_disk_number(letter, disk_number)) continue;
        if (!is_usb_removable_disk(disk_number)) continue;

        wchar_t label[MAX_PATH + 1] = {0};
        GetVolumeInformationW(root.c_str(), label, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0);

        ULARGE_INTEGER total_bytes{};
        GetDiskFreeSpaceExW(root.c_str(), nullptr, &total_bytes, nullptr);

        UsbDriveInfo info;
        info.letter = letter;
        info.label = label;
        info.total_bytes = total_bytes.QuadPart;
        info.disk_number = disk_number;
        result.push_back(info);
    }
    return result;
}

inline std::wstring format_size(uint64_t bytes) {
    const double gb = 1024.0 * 1024.0 * 1024.0;
    wchar_t buf[64];
    swprintf(buf, 64, L"%.1f GB", bytes / gb);
    return buf;
}
