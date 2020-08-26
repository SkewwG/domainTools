#include <stdio.h>
#include <Windows.h>
#include <lmaccess.h>

#pragma comment(lib, "Netapi32.lib")

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 3) {
		wprintf(L"Usage: %s <localgroupname> <servername>\n", argv[0]);
		wprintf(L"       %s administrators \\\\192.168.232.128\n", argv[0]);
		exit(1);
	}

	LPCWSTR servername = argv[2];				// 已经建立ipc连接的IP
	LPCWSTR TargetGroup = argv[1];				// 本地组名
	LOCALGROUP_MEMBERS_INFO_2* buff;			// LOCALGROUP_MEMBERS_INFO_2结构，变量buff存放获取到的信息
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;	// 指定返回数据的首选最大长度，以字节为单位。如果指定MAX_PREFERRED_LENGTH，该函数将分配数据所需的内存量。
	DWORD dwEntriesread;						// 指向一个值的指针，该值接收实际枚举的元素数。
	DWORD dwTotalentries;
	NetLocalGroupGetMembers(servername, TargetGroup, 2, (LPBYTE*)&buff, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	// wprintf(L"dwEntriesread: %d\ndwTotalentries: %d\n", dwEntriesread, dwTotalentries);
	for (DWORD i = 0; i < dwEntriesread; i++) {
		wprintf(L"%s\n", buff[i].lgrmi2_domainandname);
		// wprintf(L"SID:%d\n", buff[i].lgrmi2_sid);				// sid，不是很重要的数据
		// wprintf(L"SIDUSAGE:%d\n",buff[i].lgrmi2_sidusage);
	}
}