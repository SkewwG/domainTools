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

    NETRESOURCE nr;
    DWORD dwFlags;

    if (argc != 4) {
        wprintf(L"Usage: %s <remotename> <username> <password>\n",
            argv[0]);
        wprintf(L"       %s \\\\contoso\\public testuser testpasswd\n",
            argv[0]);
        exit(1);
    }

    wprintf(L"Calling WNetAddConnection2 with\n");
    wprintf(L"  lpLocalName = %s\n", L"");
    wprintf(L"  lpRemoteName = %s\n", argv[1]);
    wprintf(L"  lpUsername = %s\n", argv[2]);
    wprintf(L"  lpPassword = %s\n", argv[3]);

    // Zero out the NETRESOURCE struct
    memset(&nr, 0, sizeof(NETRESOURCE));

    // Assign our values to the NETRESOURCE structure.

    nr.dwType = RESOURCETYPE_ANY;
    nr.lpLocalName = NULL;					// F:  映射到本地的磁盘，比如：Z盘等. 如果字符串为空，或者lpLocalName为NULL，则该函数将建立与网络资源的连接，而不会重定向本地设备
    nr.lpRemoteName = argv[1];				// \\192.168.232.128\temp	目标机器开放共享的磁盘
    nr.lpProvider = NULL;

    // Assign a value to the connection options
    dwFlags = CONNECT_UPDATE_PROFILE;
    //
    // Call the WNetAddConnection2 function to assign
    //   a drive letter to the share.
    //
    dwRetVal = WNetAddConnection2(&nr, argv[3], argv[2], dwFlags);
    //
    // If the call succeeds, inform the user; otherwise,
    //  print the error.
    //
    if (dwRetVal == NO_ERROR)
        wprintf(L"Connection added to %s\n", nr.lpRemoteName);
    else
        wprintf(L"WNetAddConnection2 failed with error: %u\n", dwRetVal);

    exit(1);
}