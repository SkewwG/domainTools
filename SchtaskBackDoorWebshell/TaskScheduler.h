#pragma once
#define _CRT_SECURE_NO_WARNINGS				// ºöÂÔ°²È«¼ì²é´íÎó
#include <stdio.h>
#include <Windows.h>
#include <wincred.h>
#include <iostream>             // std::wstring
#include <string>
#include <vector>
#include <taskschd.h>			// ITaskService
#include "comdef.h"				// _bstr_t
#include "string.h"
#include <tchar.h>
#include  <stdlib.h>
#include  <io.h>
#include <fstream>              // src dst

#define _WIN32_DCOM

//  Include the task header file.
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")
using namespace std;
#define MAX_LEN_FILENAME 1024

class TaskSche
{
public:
	int TaskAdd(LPCWSTR wszTaskName, wstring wstrTaskTime, wstring wstrProgram, wstring args);
	void CopySelf();
	int isFileExist(LPSTR lpFilePath);
	void copyFile(string source, string dest);

private:

};

