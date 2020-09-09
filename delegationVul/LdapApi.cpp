#include "LdapApi.h"

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

// 字符串分割
std::vector<std::wstring> splitString(std::wstring strSrc, std::wstring pattern)
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

// 文件写入内容
VOID WriteFileApi(HANDLE hFile, LPWSTR content)
{
    LPSTR lpContent = UnicodeToAnsi(content);								// 写入文件的内容
    DWORD dwBytesToWrite = (DWORD)strlen(lpContent);		// 内容长度
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    bErrorFlag = WriteFile(
        hFile,           // open file handle	
        lpContent,      // start of data to write
        dwBytesToWrite,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);            // no overlapped structure

    if (FALSE == bErrorFlag)
    {
        printf("Terminal failure: Unable to write to file.\n");
    }
    else
    {
        if (dwBytesWritten != dwBytesToWrite)
        {
            // This is an error because a synchronous write that results in
            // success (WriteFile returns TRUE) should write all data as
            // requested. This would not necessarily be the case for
            // asynchronous writes.
            printf("Error: dwBytesWritten != dwBytesToWrite\n");
        }
        /*
        else
        {
            wprintf(TEXT("Wrote %d bytes to successfully.\n"), dwBytesWritten);
        }
        */
    }
}


// 初始化
LdapApi::LdapApi(std::wstring Host, PWCHAR UserName, PWCHAR Password, HANDLE DelegFile) {
    sHost = Host;
    pUserName = UserName;
    pPassword = Password;
    hDelegFile = DelegFile;
}


// 从ldap取出来的sid转换为字符串的sid
std::string ConvertToStringSid(const unsigned char* bsid, const int len)
{
    if (len < 8)  // at least 8 bytes
    {
        return "";
    }

    char buf[1024] = { 0 };
    std::string sid("S");

    // revision
    int revision = bsid[0];
    memset(buf, 0, sizeof(buf));
    sprintf_s(buf, "-%d", revision);
    sid.append(buf);

    // 6 types
    unsigned char temp[6] = { 0 };
    for (int i = 0; i < 6; ++i)
    {
        temp[6 - i - 1] = bsid[2 + i];
    }
    long long d3 = 0;
    memcpy(&d3, temp, 6);

    memset(buf, 0, sizeof(buf));
    sprintf_s(buf, "-%ld", d3);
    sid.append(buf);

    // 32bit (4bytes) dashes
    int dashes = (int)bsid[1];  // second byte determines dash number. dashes = total dashes - 2

    if (dashes * 4 != len - 8)
    {
        return "";  // wrong format
    }

    for (int i = 0; i < dashes; ++i)
    {
        unsigned int v = 0;
        memcpy(&v, bsid + 8 + i * 4, 4);

        memset(buf, 0, sizeof(buf));
        sprintf_s(buf, "-%u", v);
        sid.append(buf);
    }

    return sid;
}


// 通过sid反查用户名
std::wstring sid2user(PSID Sid, LPCTSTR lpSystemName)
{
    // LPCTSTR lpSystemName = TEXT("192.168.52.2");		// 域机器或者域控
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


// 保存委派漏洞
void saveDeleg(HANDLE hDelegFile, std::wstring sDelegRet)
{
    PWCHAR wstr = new WCHAR[MAX_PATH];
    StringCchPrintfW(wstr, MAX_PATH, L"%s", sDelegRet.data());
    WriteFileApi(hDelegFile, wstr);
    delete wstr;
}

// ldap 连接
int LdapApi::connect() {
    wsHost = sHost;
    PWSTR host = (PWSTR)sHost.data();   // ldap Host
    ULONG port = LDAP_PORT;  // 端口
    ULONG version = LDAP_VERSION3;  // 版本

    ULONG method = LDAP_AUTH_SIMPLE;  // 识别方法

    // 搜索结果
    LDAPMessage* res = NULL;

    // 查询节点
    std::vector<std::wstring> sVecMyDN = splitString(sHost, L".");
    std::wstring sMyDN = L"DC=" + sVecMyDN[0] + L",DC=" + sVecMyDN[1];

    pMyDN = (PWSTR)sMyDN.data();
    pLdapConnection = NULL;  // 连接的句柄
    ULONG rc = 0;  // 返回值

    // 初始化 LDAP
    pLdapConnection = ldap_init(host, port);
    if (pLdapConnection == NULL) {
        fprintf(stderr, "ldap_init failed");
        return -1;
    }
    // printf("ldap_init success\n");

    // 设置协议版本为 3.0（默认 2.0）
    rc = ldap_set_option(pLdapConnection, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_set_option: rc: %d\n", rc);
        return -1;
    }
    // printf("ldap_set_option success\n");

    // 连接 LDAP 服务器
    rc = ldap_connect(pLdapConnection, NULL);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_connect: rc: %d\n", rc);
        return -1;
    }
    // printf("ldap_connect success\n");

    // 向 LDAP 服务器认证客户端
    SEC_WINNT_AUTH_IDENTITY_W secIdent;


    secIdent.User = (unsigned short*)pUserName;
    secIdent.UserLength = lstrlenW(pUserName);
    secIdent.Password = (unsigned short*)pPassword;
    secIdent.PasswordLength = lstrlenW(pPassword);
    secIdent.Domain = (unsigned short*)host;
    secIdent.DomainLength = lstrlenW(host);
    secIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

    rc = ldap_bind_s(
        pLdapConnection,      // Session Handle
        pMyDN,                // Domain DN
        (PWCHAR)&secIdent,     // Credential structure
        LDAP_AUTH_NEGOTIATE); // Auth mode

    // rc = ldap_bind_s(pLdapConnection, dn, cred, method);
    if (rc != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_bind_s: rc: %d\n", rc);
        return -1;
    }
    // printf("ldap_bind_s success\n");
    return 1;
}

// 基于资源的约束委派 Resource-based constrained delegation
VOID LdapApi::RBCD() {
    PWSTR pMyFilter = (PWSTR)L"(&(ObjectClass=computer)(mS-DS-CreatorSID=*))";             // 过滤条件
    PWCHAR pMyAttributes[] = { (PWCHAR)L"mS-DS-CreatorSID", (PWCHAR)L"cn", NULL };      // 查询的属性
    delegationVul(pMyFilter, pMyAttributes);
}

// 约束委派
VOID LdapApi::CD() {
    PWSTR pMyFilter = (PWSTR)L"(&(samAccountType=805306368)(msds-allowedtodelegateto=*))";             // 过滤条件
    PWCHAR pMyAttributes[] = { (PWCHAR)L"msds-allowedtodelegateto", (PWCHAR)L"cn", NULL };      // 查询的属性
    delegationVul(pMyFilter, pMyAttributes);
}

// 非约束委派 unconstrained delegation
VOID LdapApi::ud() {
    PWSTR pMyFilter = (PWSTR)L"(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))";             // 过滤条件
    PWCHAR pMyAttributes[] = { (PWCHAR)L"userAccountControl", (PWCHAR)L"cn", NULL };      // 查询的属性
    delegationVul(pMyFilter, pMyAttributes);
}



// 委派漏洞（约束委派和基于资源的约束委派）
int LdapApi::delegationVul(PWSTR pMyFilter, PWCHAR pMyAttributes[]) {
    wprintf(L"pMyFilter: %s\n", pMyFilter);
    connect();
    ULONG errorCode = LDAP_SUCCESS;
    LDAPMessage* pSearchResult;
    //PWSTR pMyFilter = (PWSTR)L"(|(&(samAccountType=805306368)(msds-allowedtodelegateto=*))(&(ObjectClass=computer)(mS-DS-CreatorSID=*)))";             // 过滤条件
    //PWSTR pMyFilter = (PWSTR)L"(|(&(samAccountType=805306368)(msds-allowedtodelegateto=*))(&(ObjectClass=computer)(mS-DS-CreatorSID=*))(&(ObjectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)))";             // 过滤条件
    //PWCHAR pMyAttributes[] = { (PWCHAR)L"cn", (PWCHAR)L"msds-allowedtodelegateto", (PWCHAR)L"mS-DS-CreatorSID", NULL };      // 查询的属性

    errorCode = ldap_search_s(
        pLdapConnection,    // Session handle
        pMyDN,              // DN to start search
        LDAP_SCOPE_SUBTREE, // Scope
        pMyFilter,          // Filter
        pMyAttributes,      // Retrieve list of attributes
        0,                  // Get both attributes and values
        &pSearchResult);    // [out] Search results

    if (errorCode != LDAP_SUCCESS)
    {
        printf("ldap_search_s failed with 0x%0lx \n", errorCode);
        ldap_unbind_s(pLdapConnection);
        if (pSearchResult != NULL)
            ldap_msgfree(pSearchResult);
        return -1;
    }
    // printf("ldap_search succeeded \n");

    //----------------------------------------------------------
    // Get the number of entries returned.
    //----------------------------------------------------------
    ULONG numberOfEntries;

    numberOfEntries = ldap_count_entries(
        pLdapConnection,    // Session handle
        pSearchResult);     // Search result

    if (numberOfEntries == NULL)
    {
        printf("ldap_count_entries failed with 0x%0lx \n", errorCode);
        ldap_unbind_s(pLdapConnection);
        if (pSearchResult != NULL)
            ldap_msgfree(pSearchResult);
        return -1;
    }

    // printf("ldap_count_entries succeeded \n");

    printf("The number of entries is: %d \n", numberOfEntries);


    //----------------------------------------------------------
    // Loop through the search entries, get, and output the
    // requested list of attributes and values.
    //----------------------------------------------------------
    LDAPMessage* pEntry = NULL;
    PCHAR pEntryDN = NULL;
    ULONG iCnt = 0;
    char* sMsg;
    BerElement* pBer = NULL;
    PWCHAR pAttribute = NULL;
    PWCHAR* ppValue = NULL;
    ULONG iValue = 0;

    for (iCnt = 0; iCnt < numberOfEntries; iCnt++)
    {
        // Get the first/next entry.
        if (!iCnt)
            pEntry = ldap_first_entry(pLdapConnection, pSearchResult);
        else
            pEntry = ldap_next_entry(pLdapConnection, pEntry);

        // Output a status message.
        sMsg = (char*)(!iCnt ? "ldap_first_entry" : "ldap_next_entry");
        if (pEntry == NULL)
        {
            printf("%s failed with 0x%0lx \n", sMsg, LdapGetLastError());
            ldap_unbind_s(pLdapConnection);
            ldap_msgfree(pSearchResult);
            return -1;
        }
        /*
        else
            printf("%s succeeded\n", sMsg);
        */

        // Output the entry number.
        // printf("ENTRY NUMBER %i \n", iCnt);


        // Get the first attribute name.
        pAttribute = ldap_first_attributeW(
            pLdapConnection,   // Session handle
            pEntry,            // Current entry
            &pBer);            // [out] Current BerElement


        std::wstring sDelegRet = L"";

        while (pAttribute != NULL)
        {
            // Output the attribute name.
            // wprintf(L"%s:", pAttribute);

            // Get the string values.
            // 基于资源的约束委派漏洞
            if (CompareString(GetThreadLocale(), NORM_IGNORECASE, pAttribute, lstrlenW(pAttribute), L"mS-DS-CreatorSID", lstrlenW(L"mS-DS-CreatorSID")) == 2) {
                berval** attrList;
                std::wstring swSid;
                std::wstring domainUser;
                PSID pSid;

                // 转换成SID
                if (attrList = ldap_get_values_lenW(pLdapConnection, pEntry, pAttribute))
                {
                    for (int i = 0; attrList[i]; i++)
                    {
                        std::string sid = ConvertToStringSid((const unsigned char*)attrList[i]->bv_val, attrList[i]->bv_len);
                        swSid = std::wstring(sid.begin(), sid.end());
                        // wprintf(L"%s\t", ret.data());

                        ConvertStringSidToSid((LPCWSTR)swSid.data(), &pSid);			// 将字符串转换为Sid
                        domainUser = sid2user(pSid, wsHost.data());
                        // wprintf(L"domainUser:%s\n", domainUser.data());

                        sDelegRet = sDelegRet + domainUser + L"\t";
                        sDelegRet = sDelegRet + swSid + L"\t";
                        sDelegRet = sDelegRet + L"Resource-based constrained delegation\n";
                    }
                    ldap_value_free_len(attrList);
                }
            }
            // 约束委派
            else if (CompareString(GetThreadLocale(), NORM_IGNORECASE, pAttribute, lstrlenW(pAttribute), L"msds-allowedtodelegateto", lstrlenW(L"msds-allowedtodelegateto")) == 2)
            {
                // 获取属性的值
                ppValue = ldap_get_values(
                    pLdapConnection,  // Session Handle
                    pEntry,           // Current entry
                    pAttribute);      // Current attribute
                sDelegRet = sDelegRet + *ppValue + L"\t";
                sDelegRet = sDelegRet + L"Constrained delegation\n";
            }
            // 非约束委派
            else if (CompareString(GetThreadLocale(), NORM_IGNORECASE, pAttribute, lstrlenW(pAttribute), L"userAccountControl", lstrlenW(L"userAccountControl")) == 2)
            {
                // 获取属性的值
                ppValue = ldap_get_values(
                    pLdapConnection,  // Session Handle
                    pEntry,           // Current entry
                    pAttribute);      // Current attribute
                sDelegRet = sDelegRet + *ppValue + L"\t";
                sDelegRet = sDelegRet + L"unconstrained delegation\n";
            }
            else {
                // 获取属性的值
                ppValue = ldap_get_values(
                    pLdapConnection,  // Session Handle
                    pEntry,           // Current entry
                    pAttribute);      // Current attribute
                // wprintf(L"%s\t", *ppValue);
                sDelegRet = sDelegRet + *ppValue + L" --> ";
            }



            // Free memory.
            if (ppValue != NULL)
                ldap_value_free(ppValue);
            ppValue = NULL;
            ldap_memfree(pAttribute);

            // Get next attribute name.
            pAttribute = ldap_next_attribute(
                pLdapConnection,   // Session Handle
                pEntry,            // Current entry
                pBer);             // Current BerElement

        }


        wprintf(L"%s", sDelegRet.data());
        saveDeleg(hDelegFile, sDelegRet);       // 保存到文本



    }

    //----------------------------------------------------------
    // Normal cleanup and exit.
    //----------------------------------------------------------
    ldap_unbind(pLdapConnection);
    ldap_msgfree(pSearchResult);
    ldap_value_freeW(ppValue);
    wprintf(L"--------------------------------------------------------------------------------------------\n");
    return 1;
}



