#include "LdapApi.h"

HANDLE CreateFileApi(LPCWSTR fileName)
{
	HANDLE hFile;		// 句柄
	hFile = CreateFile(fileName,                // name of the write
		GENERIC_WRITE,          // open for writing
		FILE_SHARE_READ,                      // do not share
		NULL,                   // default security
		OPEN_ALWAYS,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	return hFile;
}

// 字符串分割
std::vector<std::wstring> splitString2(std::wstring strSrc, std::wstring pattern)
{
	std::vector<std::wstring> resultstr;

	// 添加在字符串最后，可以截取最后一段数据
	std::wstring strcom = strSrc.append(pattern);
	// wprintf(L"%s\n", strcom);
	auto pos = strSrc.find(pattern);
	auto len = strcom.size();

	//
	while (pos != std::wstring::npos)
	{
		std::wstring coStr = strcom.substr(0, pos);
		// wprintf(L"%s ", coStr.c_str());
		resultstr.push_back(coStr);

		strcom = strcom.substr(pos + pattern.size(), len);
		pos = strcom.find(pattern);
	}

	return resultstr;
}


int wmain(int argc, wchar_t* argv[])
{

	setlocale(LC_ALL, "");							// 设置中文
	if (argc != 4) {
		wprintf(L"Usage: %s <DC> <domainname\\username> <password>\n", argv[0]);
		wprintf(L"       %s 域控名 域名\\域用户 域用户密码\n", argv[0]);
		wprintf(L"       %s hack.local hack\\username password\n", argv[0]);
		exit(1);
	}
	LPWSTR lpDCName = argv[1];							// hack.local
	LPWSTR lpDomainUserName = argv[2];					// hack\iis_user
	LPWSTR lpDomainUserPassword = argv[3];
	HANDLE hDelegFile = CreateFileApi(L"Deleg.txt");				// 委派漏洞

	std::vector<std::wstring> aaa;					// 必须创建vector容器的变量去接收splitString返回的值，不然取出的数据会乱码
	aaa = splitString2(lpDomainUserName, L"\\");
	LPCWSTR lpDomainName = aaa[0].c_str();			// 取出域名  eg:hack
	LPCWSTR lpUserName = aaa[1].c_str();			// 域用户名	eg:iis_user

	wprintf(L"DCName: %s\nUserName: %s\nPassword: %s\n", lpDCName, lpUserName, lpDomainUserPassword);
	// 检测委派漏洞（基于资源的约束委派）
	wprintf(L"------------------------------------check delegationVul...------------------------------------\n");
	LdapApi theLdapApi(lpDCName, (PWCHAR)lpUserName, (PWCHAR)lpDomainUserPassword, hDelegFile);
	int iConnRet = theLdapApi.connect();
	if (iConnRet != 1) {
		exit(0);
	}
	theLdapApi.RBCD();
	theLdapApi.CD();
	theLdapApi.ud();
}