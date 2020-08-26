#include "tou.h"
#pragma once
class CommonApi
{
public:
	// 将Unicode转换为ANSI
	char* UnicodeToAnsi(const wchar_t* szStr);

	// 将ANSI转换为Unicode
	wchar_t* AnsiToUnicode(const char* str);

	// 字符串分割
	std::vector<std::wstring> splitString(std::wstring strSrc, std::wstring pattern);

	// 创建文件
	HANDLE CreateFileApi(LPCWSTR fileName);

	// 文件写入内容
	VOID WriteFileApi(HANDLE hFile, LPWSTR content);

	// 保存成功建立IPC的结果
	void saveIPCok(HANDLE SuccessFile, LPWSTR lpUncComputerName, LPWSTR lpTotalAdministratorName, LPWSTR password);

};