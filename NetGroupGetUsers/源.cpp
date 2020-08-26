#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "Netapi32.lib")			// Winnet所需要的动态链接库

#include <Windows.h>
#include <stdio.h>
#include <lmaccess.h>

int wmain(int argc, wchar_t* argv[])
{
	if (argc != 3)
	{
		wprintf(L"Usage: %s <groupname> <servername>\n", argv[0]);
		wprintf(L"       %s \"domain admins\" \\\\192.168.232.128", argv[0]);
		exit(1);
	}

	wprintf(L"groupname: %s\n", argv[1]);
	wprintf(L"servername: %s\n", argv[2]);
	LPCWSTR servername = argv[2];
	LPCWSTR groupname = argv[1];
	DWORD dwLevel = 1;
	GROUP_USERS_INFO_1* bufptr;
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesread;
	DWORD dwTotalentries;
	DWORD dwRetVul;

	dwRetVul = NetGroupGetUsers(servername, groupname, dwLevel, (LPBYTE*)&bufptr, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);

	wprintf(L"num: %d\n", dwEntriesread);

	if (dwRetVul == NO_ERROR)
	{
		for (DWORD i = 0; i < dwEntriesread; i++)
		{
			wprintf(L"[%u] %s \n", i, bufptr[i].grui1_name);
		}
	}
	else
	{
		wprintf(L"error : %u\nhttps://docs.microsoft.com/en-us/windows/win32/netmgmt/network-management-error-codes", dwRetVul);
	}
}