#pragma once
#include <Windows.h>
#include <string>			// std::
#include "winldap.h"		// ldap
#include <sddl.h>			// ldap
#include <Dsgetdc.h>		// ldap
#include <algorithm>		// ldap
#include <vector>
#include <strsafe.h>		// StringCchPrintfW
#include <locale.h>						// 中文
#define BUFFSIZE 1024


class LdapApi
{
public:
	// 构造函数
	LdapApi(std::wstring Host, PWCHAR UserName, PWCHAR Password, HANDLE DelegFile);

	// ldap 连接
	int connect();

	// 委派漏洞（基于资源的约束委派）
	int delegationVul(PWSTR pMyFilter, PWCHAR pMyAttributes[]);

	// 基于资源的约束委派 Resource-based constrained delegation
	void RBCD();

	// 约束委派
	void CD();

	// 非约束委派 unconstrained delegation
	void ud();

private:
	std::wstring sHost;
	PWCHAR pUserName;
	PWCHAR pPassword;
	HANDLE hDelegFile;
	PWSTR pMyDN;
	LDAP* pLdapConnection;
	std::wstring wsHost;
};

