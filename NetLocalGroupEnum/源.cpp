#include <stdio.h>
#include <Windows.h>
#include <lmaccess.h>

#pragma comment(lib, "Netapi32.lib")

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 2) {
		wprintf(L"Usage: %s <servername>\n", argv[0]);
		wprintf(L"       %s 192.168.232.128\n", argv[0]);
		exit(1);
	}

	LPCWSTR servername = argv[1];				// 已经建立ipc连接的IP
	LOCALGROUP_INFO_1* buff;			// LOCALGROUP_MEMBERS_INFO_2结构，变量buff存放获取到的信息
	DWORD dwPrefmaxlen = MAX_PREFERRED_LENGTH;	// 指定返回数据的首选最大长度，以字节为单位。如果指定MAX_PREFERRED_LENGTH，该函数将分配数据所需的内存量。
	DWORD dwEntriesread;						// 指向一个值的指针，该值接收实际枚举的元素数。
	DWORD dwTotalentries;
	NetLocalGroupEnum(servername, 1, (LPBYTE*)&buff, dwPrefmaxlen, &dwEntriesread, &dwTotalentries, NULL);
	for (DWORD i = 0; i < dwEntriesread; i++)
	{
		wprintf(L"%s\n", buff[i].lgrpi1_name);
	}
}