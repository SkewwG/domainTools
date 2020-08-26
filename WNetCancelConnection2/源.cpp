#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "mpr.lib")			// Winnet所需要的动态链接库

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Winnetwk.h>					// 标头

// Need to link with Netapi32.lib and Mpr.lib

int wmain(int argc, wchar_t* argv[])
{

    DWORD dwRetVal;

    if (argc != 2) {
        wprintf(L"Usage: %s <lpName>\n",
            argv[0]);
        wprintf(L"       %s \\\\contoso\n",
            argv[0]);
        exit(1);
    }

    wprintf(L"Calling WNetCancelConnection2 with\n");
    wprintf(L"  lpName = %s\n", argv[1]);

    dwRetVal = WNetCancelConnection2(argv[1], 0, TRUE);
    //
    // If the call succeeds, inform the user; otherwise,
    //  print the error.
    //
    if (dwRetVal == NO_ERROR)
        wprintf(L"Connection cancel to %s\n", argv[1]);
    else
        wprintf(L"WNetCancelConnection2 failed with error: %u\n", dwRetVal);

    exit(1);
}