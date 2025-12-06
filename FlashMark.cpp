#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <iostream>
#include <vector>
#include <string>
#include <limits>
#include <cmath>
#include <cstdlib>
#include <cstring>

// check if we got admin
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// relaunch w/ admin privs
void RelaunchAsAdmin() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = path;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if (!ShellExecuteExW(&sei)) {
        std::cerr << "Failed to elevate. Please run as Administrator." << std::endl;
    }
}

// checks for partitions on disk
bool DiskHasPartitions(HANDLE hDrive) {
    DRIVE_LAYOUT_INFORMATION_EX layout;
    DWORD bytesReturned;

    if (DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0,
        &layout, sizeof(layout), &bytesReturned, NULL)) {
        return layout.PartitionCount > 0;
    }

    // might need bigger buffer for lots of partitions
    size_t bufSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 127 * sizeof(PARTITION_INFORMATION_EX);
    std::vector<char> buf(bufSize);

    if (DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, NULL, 0,
        buf.data(), static_cast<DWORD>(bufSize), &bytesReturned, NULL)) {
        auto* layoutEx = reinterpret_cast<DRIVE_LAYOUT_INFORMATION_EX*>(buf.data());
        for (DWORD i = 0; i < layoutEx->PartitionCount; i++) {
            if (layoutEx->PartitionEntry[i].PartitionLength.QuadPart > 0) {
                return true;
            }
        }
    }

    return false;
}

// wipes partition table
bool CleanDisk(HANDLE hDrive) {
    CREATE_DISK createDisk = { 0 };
    createDisk.PartitionStyle = PARTITION_STYLE_RAW;

    DWORD bytesReturned;
    if (!DeviceIoControl(hDrive, IOCTL_DISK_CREATE_DISK, &createDisk,
        sizeof(createDisk), NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "Failed to clean disk. Error: " << GetLastError() << std::endl;
        return false;
    }

    DeviceIoControl(hDrive, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &bytesReturned, NULL);
    return true;
}

void* aligned_alloc(size_t size, size_t alignment) {
    return _aligned_malloc(size, alignment);
}

void aligned_free(void* ptr) {
    _aligned_free(ptr);
}

// fills buffer w/ test pattern unique to position
void generatePattern(char* data, size_t blockSize, LONGLONG position) {
    // use position to seed pattern so each location has unique data
    unsigned char posBytes[8];
    memcpy(posBytes, &position, 8);

    for (size_t j = 0; j < blockSize; ++j) {
        // mix position into pattern - detects address aliasing
        data[j] = static_cast<char>((j * 7 + 13 + posBytes[j % 8]) % 256);
    }
}

// write then read back and verify
bool testPosition(HANDLE hDrive, LONGLONG position, char* data, char* readBuffer,
                  size_t blockSize, size_t sectorSize) {
    DWORD bytesWritten, bytesRead;
    LARGE_INTEGER pos;

    // align to sector
    pos.QuadPart = position - (position % sectorSize);

    // generate position-unique pattern
    generatePattern(data, blockSize, pos.QuadPart);

    SetFilePointerEx(hDrive, pos, NULL, FILE_BEGIN);
    if (!WriteFile(hDrive, data, static_cast<DWORD>(blockSize), &bytesWritten, NULL)) {
        return false;
    }
    FlushFileBuffers(hDrive);

    // readback
    SetFilePointerEx(hDrive, pos, NULL, FILE_BEGIN);
    if (!ReadFile(hDrive, readBuffer, static_cast<DWORD>(blockSize), &bytesRead, NULL)) {
        return false;
    }

    return memcmp(data, readBuffer, blockSize) == 0;
}

// rounds to common drive sizes (marketing sizes)
size_t roundToNearestLogicalSize(size_t sizeInMB) {
    static const std::vector<size_t> logicalSizes = {
        1024, 2048, 4096,
        8192, 16384, 32768, 65536,
        122880, 131072,
        245760, 262144,
        491520, 524288,
        983040, 1048576,
        1966080, 2097152,
        4194304, 8388608, 16777216
    };

    if (sizeInMB > logicalSizes.back()) return logicalSizes.back();
    if (sizeInMB <= logicalSizes[0]) return logicalSizes[0];

    for (size_t i = 1; i < logicalSizes.size(); ++i) {
        if (sizeInMB <= logicalSizes[i]) {
            size_t prev = logicalSizes[i - 1];
            size_t threshold = prev + (prev / 4);  // 25% threshold
            return (sizeInMB >= threshold) ? logicalSizes[i] : prev;
        }
    }

    return logicalSizes.back();
}

// binary search to find where drive starts failing
LONGLONG binarySearchFailure(HANDLE hDrive, LONGLONG low, LONGLONG high,
                              char* data, char* readBuffer, size_t blockSize,
                              size_t sectorSize, int& testsPerformed) {
    LONGLONG lastGood = low;

    while (high - low > static_cast<LONGLONG>(blockSize * 2)) {
        LONGLONG mid = low + (high - low) / 2;
        mid = mid - (mid % sectorSize);

        testsPerformed++;
        std::cout << "\rRunning Binary Search... " << (mid / (1024 * 1024)) << " MB    ";
        std::cout.flush();

        if (testPosition(hDrive, mid, data, readBuffer, blockSize, sectorSize)) {
            lastGood = mid;
            low = mid + blockSize;
        } else {
            high = mid;
        }
    }

    return lastGood + blockSize;
}

int main() {
    // need admin for raw disk access
    if (!IsRunningAsAdmin()) {
        std::wcout << L"Requesting administrator privileges..." << std::endl;
        RelaunchAsAdmin();
        return 0;
    }

    std::wcout << L"Welcome to Flashmark | v1.1.0 | Developed by Brent Wadleigh" << std::endl;
    std::wcout << L"-----------------------------------------------------------" << std::endl;

    int driveNumber;
    std::wcout << L"Enter disk number: ";
    if (!(std::wcin >> driveNumber) || driveNumber < 0) {
        std::cerr << "Invalid disk number." << std::endl;
        return 1;
    }

    int thoroughness;
    std::wcout << L"Select Accuracy  [1 - Low]  [2 - Medium]  [3 - High]: ";
    if (!(std::wcin >> thoroughness)) {
        std::cerr << "Invalid input." << std::endl;
        return 1;
    }

    int numTests;
    switch (thoroughness) {
    case 1: numTests = 25; break;
    case 2: numTests = 50; break;
    case 3: numTests = 100; break;
    default:
        std::cerr << "Invalid choice. Defaulting to Medium." << std::endl;
        numTests = 50;
        break;
    }

    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNumber);

    HANDLE hDrive = CreateFileW(drivePath.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, NULL);

    if (hDrive == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to access drive. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // gotta wipe partitions first or writes fail
    if (DiskHasPartitions(hDrive)) {
        std::wcout << L"Disk has partitions. Wipe them? (Y/N): ";
        wchar_t response;
        std::wcin >> response;

        if (response == L'Y' || response == L'y') {
            std::wcout << L"Cleaning disk..." << std::endl;
            if (!CleanDisk(hDrive)) {
                std::cerr << "Failed to clean disk. Try using diskpart manually." << std::endl;
                CloseHandle(hDrive);
                return 1;
            }
            std::wcout << L"Disk cleaned successfully." << std::endl;
        } else {
            std::cerr << "Cannot proceed with partitions on disk." << std::endl;
            CloseHandle(hDrive);
            return 1;
        }
    }

    GET_LENGTH_INFORMATION diskSizeInfo;
    DWORD returnedSize;
    if (!DeviceIoControl(hDrive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0,
        &diskSizeInfo, sizeof(diskSizeInfo), &returnedSize, NULL)) {
        std::cerr << "Failed to get disk size: " << GetLastError() << std::endl;
        CloseHandle(hDrive);
        return 1;
    }

    DISK_GEOMETRY dg;
    if (!DeviceIoControl(hDrive, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0,
        &dg, sizeof(dg), &returnedSize, NULL)) {
        std::cerr << "Failed to get disk geometry: " << GetLastError() << std::endl;
        CloseHandle(hDrive);
        return 1;
    }

    const size_t sectorSize = dg.BytesPerSector;
    const size_t blockSize = 5 * 1024 * 1024;  // 5mb blocks
    const LONGLONG totalSize = diskSizeInfo.Length.QuadPart;

    char* data = static_cast<char*>(aligned_alloc(blockSize, sectorSize));
    char* readBuffer = static_cast<char*>(aligned_alloc(blockSize, sectorSize));

    if (!data || !readBuffer) {
        std::cerr << "Failed to allocate memory." << std::endl;
        if (data) aligned_free(data);
        if (readBuffer) aligned_free(readBuffer);
        CloseHandle(hDrive);
        return 1;
    }

    // pattern now generated per-position in testPosition()

    // clear and show header
    system("cls");
    std::wcout << L"Welcome to Flashmark | v1.1.0 | Developed by Brent Wadleigh" << std::endl;
    std::wcout << L"-----------------------------------------------------------" << std::endl;
    std::wcout << L"Claimed Capacity: " << totalSize / (1024 * 1024) << L" MB ("
               << totalSize / (1024 * 1024 * 1024) << L" GB)" << std::endl;
    std::wcout << L"-----------------------------------------------------------" << std::endl;

    int testsPerformed = 0;
    LONGLONG estimatedTrueSize = 0;
    bool isFake = false;

    // quick check - test start/mid/end first
    std::cout << "Quick check: testing start, middle, end..." << std::endl;

    LONGLONG startPos = 0;
    LONGLONG midPos = (totalSize / 2) - ((totalSize / 2) % sectorSize);
    LONGLONG endPos = totalSize - blockSize - ((totalSize - blockSize) % sectorSize);

    testsPerformed = 3;
    bool startOk = testPosition(hDrive, startPos, data, readBuffer, blockSize, sectorSize);
    bool midOk = testPosition(hDrive, midPos, data, readBuffer, blockSize, sectorSize);
    bool endOk = testPosition(hDrive, endPos, data, readBuffer, blockSize, sectorSize);

    std::cout << "  Start (0 MB): " << (startOk ? "PASS" : "FAIL") << std::endl;
    std::cout << "  Middle (" << midPos / (1024 * 1024) << " MB): " << (midOk ? "PASS" : "FAIL") << std::endl;
    std::cout << "  End (" << endPos / (1024 * 1024) << " MB): " << (endOk ? "PASS" : "FAIL") << std::endl;

    if (!startOk) {
        // drive broken or locked
        std::cout << "\nError: Drive failed at position 0." << std::endl;
        std::cout << "  - Ensure no programs are accessing the drive" << std::endl;
        aligned_free(data);
        aligned_free(readBuffer);
        CloseHandle(hDrive);
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
        return 1;
    }

    if (startOk && midOk && endOk) {
        // passed quick check, do full scan
        std::cout << "\nQuick check passed. Running full verification..." << std::endl;

        const LONGLONG spacing = totalSize / numTests;
        int lastSuccessfulIndex = -1;

        std::cout << "[";
        for (int i = 0; i < 50; ++i) std::cout << " ";
        std::cout << "] 0%";
        std::cout.flush();

        for (int i = 0; i < numTests; ++i) {
            LONGLONG position = static_cast<LONGLONG>(i) * spacing;

            if (position + static_cast<LONGLONG>(blockSize) > totalSize) {
                continue;
            }

            testsPerformed++;
            if (testPosition(hDrive, position, data, readBuffer, blockSize, sectorSize)) {
                lastSuccessfulIndex = i;
            } else {
                // failed, narrow down w/ binary search
                std::cout << std::endl;
                LONGLONG prevPos = (i > 0) ? (static_cast<LONGLONG>(i - 1) * spacing) : 0;
                estimatedTrueSize = binarySearchFailure(hDrive, prevPos, position,
                                                         data, readBuffer, blockSize,
                                                         sectorSize, testsPerformed);
                isFake = true;
                break;
            }

            // progress bar
            int percent = (100 * (i + 1)) / numTests;
            int barPos = (50 * (i + 1)) / numTests;
            std::cout << "\r[";
            for (int k = 0; k < 50; ++k) {
                std::cout << (k < barPos ? "=" : " ");
            }
            std::cout << "] " << percent << "%";
            std::cout.flush();
        }

        if (!isFake) {
            estimatedTrueSize = totalSize;
        }

    } else if (startOk && !endOk) {
        // quick check failed, use binary search
        std::cout << std::endl;

        LONGLONG searchLow = midOk ? midPos : 0;
        LONGLONG searchHigh = midOk ? endPos : midPos;

        estimatedTrueSize = binarySearchFailure(hDrive, searchLow, searchHigh,
                                                 data, readBuffer, blockSize,
                                                 sectorSize, testsPerformed);
        isFake = true;
    }

    // clear screen and show final results
    system("cls");

    size_t roundedSize = roundToNearestLogicalSize(estimatedTrueSize / (1024 * 1024));
    double percentDiff = 100.0 * llabs(estimatedTrueSize - totalSize) / totalSize;
    bool isValid = (percentDiff <= 10.0 && !isFake);

    std::cout << "==============================================================" << std::endl;
    std::cout << "  Flashmark | v1.1.0 | Developed by Brent Wadleigh" << std::endl;
    std::cout << "==============================================================" << std::endl;
    std::cout << std::endl;

    if (isValid) {
        std::cout << "  [PASS] Drive is VALID" << std::endl;
    } else {
        std::cout << "  [FAIL] Drive is COUNTERFEIT" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "--------------------------------------------------------------" << std::endl;
    std::cout << "  Claimed Capacity:    " << totalSize / (1024 * 1024 * 1024) << " GB" << std::endl;
    std::cout << "  Actual Capacity:     " << roundedSize / 1024 << " GB" << std::endl;
    std::cout << "  Tests Performed:     " << testsPerformed << std::endl;
    std::cout << "--------------------------------------------------------------" << std::endl;

    if (!isValid) {
        std::cout << std::endl;
        std::cout << "  WARNING: This drive reports a false capacity." << std::endl;
        std::cout << "  Data written beyond " << roundedSize / 1024 << " GB may be lost or corrupted." << std::endl;
    }

    std::cout << std::endl;
    std::cout << "Press Enter to exit...";

    aligned_free(data);
    aligned_free(readBuffer);
    CloseHandle(hDrive);
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
    return 0;
}
