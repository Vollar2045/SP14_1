#include <windows.h>
#include <iostream>
#include <cstdio>
#include <locale.h>

typedef HANDLE(WINAPI* tCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
    );

HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    wprintf(L"[HOOK] CreateFileW вызвана для: %s\n", lpFileName);
    fflush(stdout);
    static tCreateFileW pRealCreateFile = nullptr;
    if (!pRealCreateFile) {
        HMODULE hBase = GetModuleHandleW(L"KernelBase.dll");
        if (hBase) {
            pRealCreateFile = (tCreateFileW)GetProcAddress(hBase, "CreateFileW");
        }
    }
    if (!pRealCreateFile) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return pRealCreateFile(
        lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
    );
}

void InstallHook() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return;
    void* pTargetFunc = GetProcAddress(hKernel32, "CreateFileW");
    if (!pTargetFunc) return;
    DWORD oldProtect;
    if (!VirtualProtect(pTargetFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Ошибка VirtualProtect.\n");
        return;
    }
    BYTE jmpCode[12];
    jmpCode[0] = 0x48;
    jmpCode[1] = 0xB8;
    *(DWORD64*)(jmpCode + 2) = (DWORD64)Hooked_CreateFileW;
    jmpCode[10] = 0xFF;
    jmpCode[11] = 0xE0;
    memcpy(pTargetFunc, jmpCode, 12);
    VirtualProtect(pTargetFunc, 12, oldProtect, &oldProtect);
    printf("[*] Hook успешно установлен на CreateFileW.\n");
}

int main() {
    setlocale(LC_ALL, "Russian");
    InstallHook();
    printf("\n--- Тест: создание файла ---\n");
    HANDLE hFile = CreateFileW(
        L"test_hook_log.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile != INVALID_HANDLE_VALUE) {
        wprintf(L"[TEST] Файл успешно создан (дескриптор: %p).\n", hFile);
        CloseHandle(hFile);
    }
    else {
        wprintf(L"[TEST] Ошибка создания файла: %lu\n", GetLastError());
    }
    system("pause");
    return 0;
}