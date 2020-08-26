// 针对于域环境下，无域用户权限，无需和域控（域机器不行）建立IPC连接即可枚举域用户名
#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#define _CRT_SECURE_NO_WARNINGS				// 忽略安全检查错误

#include <iostream>
#include <Windows.h>
#include <string>
#include <sddl.h>
#include <vector>
#include <thread>
#include <mutex>
#include <stdio.h>
#include <locale.h>						// 中文

#define BUFFSIZE 1024

std::mutex mtx;
int StartSid;

// 字符串分割
std::wstring splitString(std::wstring strSrc, std::wstring pattern)
{
	std::wstring result;
	// 添加在字符串最后，可以截取最后一段数据
	std::wstring strcom = strSrc.append(pattern);
	// wprintf(L"%s\n", strcom);
	auto pos = strSrc.find(pattern);
	auto len = strcom.size();

	// wprintf(L"%d", std::wstring::npos);
	while (pos != std::wstring::npos)
	{
		std::wstring coStr = strcom.substr(0, pos);

		strcom = strcom.substr(pos + pattern.size(), len);
		pos = strcom.find(pattern);

		if (pos == -1)
		{
			break;
		}
		result.append(coStr);
		result.append(L"-");
	}

	return result;
}

// 获取域管administrator的sid
BOOL user2sid(LPCTSTR lpSystemName, LPCTSTR lpAccountName, PSID Sid)
{
	// LPCTSTR lpSystemName = lpSystemName;			// 域机器或者域控 TEXT("192.168.52.2");
	// LPCTSTR lpAccountName = lpAccountName;		// 域用户名 TEXT("hack\\administrator");
	PSID pSid = Sid;
	DWORD cbSid = 1;			// 接收Sid缓冲区的大小

	WCHAR ReferencedDomainName[BUFFSIZE];
	ZeroMemory(ReferencedDomainName, BUFFSIZE);
	DWORD cchReferencedDomainName = 1;

	UCHAR buffer[4];
	PSID_NAME_USE peUse = (PSID_NAME_USE)buffer;		// 指向接收PSID_NAME_USE值（指示帐户类型）的变量的指针 

	BOOL bRtnBool = TRUE;

	// 第一次执行是为了获取cbSid和cchReferencedDomainName的值
	bRtnBool = LookupAccountName(
		lpSystemName,				// 域机器或者域控
		lpAccountName,				// 域用户名
		pSid,
		(LPDWORD)&cbSid,
		ReferencedDomainName,
		(LPDWORD)&cchReferencedDomainName,
		peUse);
	// wprintf(L"cbSid:%d\ncchReferencedDomainName:%d\n", cbSid, cchReferencedDomainName);

	// 第二次执行是获取pSid，因为需要第一步的cbSid和cchReferencedDomainName结果
	bRtnBool = LookupAccountName(
		lpSystemName,
		lpAccountName,
		pSid,
		(LPDWORD)&cbSid,
		ReferencedDomainName,
		(LPDWORD)&cchReferencedDomainName,
		peUse);

	if (bRtnBool == TRUE)
	{
		return TRUE;
	}
	else
	{
		printf("Error : %d\n", GetLastError());
	}
	return FALSE;
};

// 通过sid反查用户名
std::wstring sid2user(PSID Sid, LPCTSTR lpSystemName)
{
	// LPCTSTR lpSystemName = TEXT("192.168.3.142");		// 域机器或者域控
	PSID pSid = Sid;				// SID

	WCHAR Name[BUFFSIZE];			// 接收sid反查的用户名
	ZeroMemory(Name, BUFFSIZE);		// 清空内存
	DWORD cchName = 1;			// 接收Name所需的缓冲区大小

	WCHAR ReferencedDomainName[BUFFSIZE];
	ZeroMemory(ReferencedDomainName, BUFFSIZE);		// 清空内存
	DWORD cchReferencedDomainName = 1;					// 接收ReferencedDomainName所需的缓冲区大小

	UCHAR buffer[4];
	PSID_NAME_USE peUse = (PSID_NAME_USE)buffer;		// 指向接收PSID_NAME_USE值（指示帐户类型）的变量的指针 

	BOOL bRtnBool = TRUE;
	// 第一次执行是为了获取cchName和cchReferencedDomainName
	bRtnBool = LookupAccountSid(
		lpSystemName,         
		pSid,
		Name,
		(LPDWORD)&cchName,
		ReferencedDomainName,
		(LPDWORD)&cchReferencedDomainName,
		peUse);

	// wprintf(L"cchName:%d\cchReferencedDomainName:%d\n", cchName, cchReferencedDomainName);

	// 第二次执行是获取Name，因为需要第一步的cchName和cchReferencedDomainName结果
	bRtnBool = LookupAccountSid(
		lpSystemName,                          // name of local or remote computer
		pSid,                     // security identifier
		Name,                      // account name buffer
		(LPDWORD)&cchName,          // size of account name buffer 
		ReferencedDomainName,
		(LPDWORD)&cchReferencedDomainName,
		peUse);                        // SID type

	
	if (bRtnBool == TRUE)
	{
		std::wstring domainUser;
		domainUser = (std::wstring)ReferencedDomainName + L"\\" + (std::wstring)Name;
		// wprintf(L"%s\\%s\n", ReferencedDomainName, Name);
		return domainUser;
	}
	else
	{
		// printf("error: %d\n", GetLastError());
		return L"";
	}
	
	
};

// 开始枚举
void start(int i, std::wstring userSidPrefix, int iEndSid, LPCTSTR lpSystemName)
{

	while (StartSid <= iEndSid)
	{
		int num = 0;
		if (mtx.try_lock())			// 锁
		{
			num = StartSid;
			++StartSid;
			mtx.unlock();			// 解锁
		}

		std::wstring domainUser;
		PSID pSid2;
		std::wstring a = std::to_wstring(num);
		std::wstring userSid;
		userSid = userSidPrefix + a;				// 拼接成完整的sid
		// wprintf(L"%s\t", userSid.data());
		ConvertStringSidToSid((LPCWSTR)userSid.data(), &pSid2);			// 将字符串转换为Sid
		domainUser = sid2user(pSid2, lpSystemName);
		
		if (domainUser != L"")
		{
			wprintf(L"[%d] %s\n", num, domainUser.data());
		}
		delete pSid2;
		// Sleep(2000);
	}
	
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");							// 设置中文
	if (argc != 6) {
		wprintf(L"Usage: %s <DC-IP> <domainname\\username> <start Sid> <end Sid> <t_num>\n", argv[0]);
		wprintf(L"       %s \\\\192.168.52.2 hack\\administrator 1000 2000 100\n", argv[0]);
		wprintf(L"       %s \\\\域控IP 域名\\域用户名<默认administrator> 起始Sid 末尾Sid 多线程数目\n", argv[0]);
		exit(0);
	}

	LPCTSTR lpSystemName = argv[1];			// 域控IP
	LPCTSTR lpAccountName = argv[2];		// hack\\administrator
	std::wstring wszStartSid = argv[3];			// 起始Sid
	std::wstring wszEndSid = argv[4];			// 末尾Sid
	std::wstring wszThreadNum = argv[5];		// 线程数目
	int iStartSid = std::stoi(wszStartSid.data());
	int iEndSid = std::stoi(wszEndSid.data());
	int iThreadNum = std::stoi(wszThreadNum.data());
	wprintf(L"DC-IP: %s\n", lpSystemName);
	wprintf(L"domainname\\username: %s\n", lpAccountName);
	wprintf(L"start Sid: %d\n", iStartSid);
	wprintf(L"end Sid: %d\n", iEndSid);
	wprintf(L"t_num: %d\n", iThreadNum);
	wprintf(L"------------------------------------------------------\n");
	
	StartSid = iStartSid;			// 全局变量

	PSID Sid;
	UCHAR buffer1[2048];
	Sid = buffer1;

	if (!user2sid(lpSystemName, lpAccountName, Sid))
	{
		wprintf(L"user2sid error!");
		exit(0);
	};

	LPWSTR sid;
	ConvertSidToStringSid(Sid, &sid);				// 将Sid的内容转换为字符串
	wprintf(L"%s sid: %s\n", lpAccountName, sid);
	
	std::wstring userSidPrefix;				// sid的前缀 S-1-5-21-675012476-827261145-2327888524-
	userSidPrefix = splitString(sid, L"-");
	wprintf(L"sid Prefix: %s\n", userSidPrefix);
	
	wprintf(L"------------------------------------------------------\n");

	std::thread* Threads = new std::thread[iThreadNum];
	for (int i = 0; i < iThreadNum; i++)
		Threads[i] = std::thread(start, i, userSidPrefix, iEndSid, lpSystemName);
	for (int i = 0; i < iThreadNum; i++)
		Threads[i].join();
	delete[] Threads;
	
	wprintf(L"EnuDomainUser End!\n");
}
