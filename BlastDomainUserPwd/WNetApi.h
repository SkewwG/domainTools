#include "tou.h"
#include "CommonApi.h"
#pragma once
class WNetApi
{
public:
	// 建立ipc连接
	int WNetAddConnection2Api(LPWSTR lpRemoteName, LPWSTR lpDomainUserName, LPWSTR lpPassword);

	// 删除ipc连接
	int WNetCancelConnection2Api(LPWSTR lpRemoteName);

	// 获取域机器列表
	std::vector<std::wstring> NetGroupGetUsersApi(LPWSTR servername, LPWSTR groupname);

	// 列出本地管理组
	std::vector<std::wstring> NetLocalGroupGetMembersApi(LPWSTR aliveIp);

	// 探测主机存活
	BOOL detectAlive(int i, LPWSTR ip);

private:
	CommonApi theCommonApi;

};