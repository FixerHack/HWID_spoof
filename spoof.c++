#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

// Структура для збереження бекапу
struct BackupData {
    std::wstring originalGuid;
    std::wstring originalName;
};

// Функція для зміни значення в реєстрі
bool SetRegKey(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, std::wstring newValue) {
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) return false;
    
    LSTATUS status = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)newValue.c_str(), (newValue.length() + 1) * sizeof(wchar_t));
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS;
}

// Функція для читання значення (для бекапу)
std::wstring GetRegKey(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName) {
    wchar_t buffer[255];
    DWORD bufferSize = sizeof(buffer);
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) return L"";
    
    if (RegQueryValueExW(hKey, valueName, NULL, NULL, (LPBYTE)buffer, &bufferSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return L"";
    }
    RegCloseKey(hKey);
    return std::wstring(buffer);
}

void ApplySpoof(std::wstring newName, std::wstring newGuid) {
    // Зміна імені ПК
    SetRegKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", L"ComputerName", newName);
    // Зміна MachineGuid
    SetRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", newGuid);
    std::wcout << L"[+] Значення змінено на: " << newGuid << std::endl;
}

int main() {
    // Програма має запускатися від імені Адміна
    BackupData backup;
    int mode;

    std::cout << "Select Mode: 1. Stable 2. Temporary\n";
    std::cin >> mode;

    if (mode == 2) {
        // Робимо бекап
        backup.originalGuid = GetRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
        std::wcout << L"[*] Backup created: " << backup.originalGuid << std::endl;
    }

    // Приклад нових даних (в реальності тут має бути генератор рандомних строк)
    ApplySpoof(L"DESKTOP-NEW123", L"550e8400-e29b-41d4-a716-446655440000");

    if (mode == 2) {
        std::cout << "Press any key to restore original ID and exit...\n";
        system("pause");
        ApplySpoof(L"ORIGINAL-PC", backup.originalGuid);
        std::cout << "[*] Restored!\n";
    } else {
        std::cout << "[+] Permanent changes applied. Restart recommended.\n";
    }

    return 0;
}