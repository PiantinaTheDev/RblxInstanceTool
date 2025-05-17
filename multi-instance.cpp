#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

typedef struct _MY_SYSTEM_HANDLE {
    DWORD       ProcessId;
    BYTE        ObjectTypeNumber;
    BYTE        Flags;
    WORD        Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} MY_SYSTEM_HANDLE;

typedef struct _MY_SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    MY_SYSTEM_HANDLE Handles[1];
} MY_SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(WINAPI* PNtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

typedef NTSTATUS(WINAPI* PNtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

std::vector<DWORD> GetAllRobloxPids() {
    std::vector<DWORD> pids;
    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Failed to create process snapshot.\n";
        return pids;
    }

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"RobloxPlayerBeta.exe") == 0) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return pids;
}

int main() {
    SetConsoleTitleW(L"Roblox Multi-Instance Tool | Coded from pizza");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    auto NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    auto NtDuplicateObject = (PNtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
    auto NtQueryObject = (PNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    if (!NtQuerySystemInformation || !NtDuplicateObject || !NtQueryObject) {
        std::cerr << "[!] Failed to load NT functions.\n";
        return 1;
    }

    while (true) {
        system("cls");

        std::vector<DWORD> robloxPids = GetAllRobloxPids();

        if (robloxPids.empty()) {
            std::cout << "[*] Waiting for a Roblox instance...\n" << std::flush;
        } else {
            bool closedAnyHandle = false;

            ULONG handleInfoSize = 0x10000;
            MY_SYSTEM_HANDLE_INFORMATION* handleInfo = (MY_SYSTEM_HANDLE_INFORMATION*)malloc(handleInfoSize);
            ULONG returnLength = 0;

            while (NtQuerySystemInformation(16, handleInfo, handleInfoSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH) {
                handleInfoSize *= 2;
                handleInfo = (MY_SYSTEM_HANDLE_INFORMATION*)realloc(handleInfo, handleInfoSize);
            }

            for (DWORD pid : robloxPids) {
                HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
                if (!hProcess) {
                    std::cerr << "[!] Failed to open Roblox instance " << pid << ". Have you run this as Administrator?\n";
                    continue;
                }

                for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
                    MY_SYSTEM_HANDLE handle = handleInfo->Handles[i];
                    if (handle.ProcessId != pid)
                        continue;

                    HANDLE dupHandle = NULL;
                    NTSTATUS status = NtDuplicateObject(
                        hProcess,
                        (HANDLE)(uintptr_t)handle.Handle,
                        GetCurrentProcess(),
                        &dupHandle,
                        0,
                        0,
                        DUPLICATE_SAME_ACCESS
                    );

                    if (!NT_SUCCESS(status))
                        continue;

                    BYTE nameBuffer[1024] = { 0 };
                    ULONG size = 0;
                    status = NtQueryObject(dupHandle, 1, nameBuffer, sizeof(nameBuffer), &size);

                    if (NT_SUCCESS(status)) {
                        UNICODE_STRING* objName = (UNICODE_STRING*)nameBuffer;

                        if (objName->Buffer && wcsstr(objName->Buffer, L"ROBLOX_singletonEvent")) {
                            HANDLE closeHandle = NULL;
                            NTSTATUS closeStatus = NtDuplicateObject(
                                hProcess,
                                (HANDLE)(uintptr_t)handle.Handle,
                                GetCurrentProcess(),
                                &closeHandle,
                                0,
                                0,
                                DUPLICATE_CLOSE_SOURCE
                            );

                            if (NT_SUCCESS(closeStatus)) {
                                std::wcout << L"[+] Closed handle in Roblox instance with PID: " << pid << ".\n";
                                CloseHandle(closeHandle);
                                closedAnyHandle = true;
                            } else {
                                std::cerr << "[!] Failed to close handle in PID: " << pid << ".\n";
                            }
                        }
                    }

                    CloseHandle(dupHandle);
                }

                CloseHandle(hProcess);
            }

            free(handleInfo);

            if (!closedAnyHandle) {
                std::cout << "[*] Waiting for a new Roblox instance...\n" << std::flush;
            }
        }

        Sleep(2000);
    }



    return 0;
}
