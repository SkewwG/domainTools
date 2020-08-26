#ifndef UNICODE
#define UNICODE
#endif

#define _CRT_SECURE_NO_WARNINGS				// 忽略安全检查错误

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Winnetwk.h>					// WNetAddConnection2
#include <lmaccess.h>
#include <iostream>
#include <vector>
#include<errno.h>
#include <iphlpapi.h>
#include <strsafe.h>
#include <tchar.h>
#include <locale.h>						// 中文
#include <thread>
#include <mutex>
#include <time.h>
#include <string>			// std::

#pragma comment(lib,"iphlpapi.lib")		// 探测主机存活 sendarp
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mpr.lib")			// Winnet所需要的动态链接库	
#pragma comment(lib, "Netapi32.lib")			// Winnet所需要的动态链接库	
#pragma comment(lib, "Kernel32.lib")