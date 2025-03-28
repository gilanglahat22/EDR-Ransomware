#include <windows.h>
#include <stdio.h>

// Fungsi untuk memeriksa apakah fungsi ntdll.dll di-hook
BOOL IsNtdllFunctionHooked(LPCWSTR functionName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return FALSE;
    }

    PROC functionAddress = GetProcAddress(ntdll, (LPCSTR)functionName);
    if (!functionAddress) {
        return FALSE;
    }

    // Pola awal syscall stub untuk x64: mov r10, rcx; mov eax, <syscall_number>; syscall; ret
    BYTE expectedPattern[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    BYTE actualBytes[sizeof(expectedPattern)];
    ReadProcessMemory(GetCurrentProcess(), functionAddress, actualBytes, sizeof(actualBytes), NULL);

    if (memcmp(actualBytes, expectedPattern, sizeof(expectedPattern) - 1) != 0) {
        return TRUE; // Terindikasi adanya hook
    }

    return FALSE; // Tidak terindikasi adanya hook (mungkin)
}

int main() {
    LPCWSTR functionToCheck = L"NtAllocateVirtualMemory";
    if (IsNtdllFunctionHooked(functionToCheck)) {
        printf("%S terindikasi telah di-hook.\n", functionToCheck);
    } else {
        printf("%S tidak terindikasi telah di-hook (berdasarkan pemeriksaan pola awal).\n", functionToCheck);
    }

    functionToCheck = L"NtCreateFile";
    if (IsNtdllFunctionHooked(functionToCheck)) {
        printf("%S terindikasi telah di-hook.\n", functionToCheck);
    } else {
        printf("%S tidak terindikasi telah di-hook (berdasarkan pemeriksaan pola awal).\n", functionToCheck);
    }

    return 0;
}