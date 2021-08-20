// r3Consle.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include<Windows.h>


int main()
{
    HANDLE hDevice = NULL;
    CHAR readbuffer[50] = { 0 };
    DWORD dwRead = 0;
    DWORD dwWrite = 0;
    hDevice = CreateFile(L"\\\\\.\\MyFirstDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice==INVALID_HANDLE_VALUE) {
        std::cout << "Open Device Failed\n";
        system("pause");
        return 0;
    }

    std::cout << "Open Success!\n";
    system("pause");
    
    // ReadFile(hDevice, readbuffer, 50, &dwRead, NULL);

    // printf("--%p--%s--%d--\n",readbuffer, readbuffer, dwRead);
    // system("pause");

    // WriteFile(hDevice, "This Message Come From R3", strlen("This Message Come From R3"), &dwWrite,NULL);

    // printf("--%d--\n", dwWrite);
    CloseHandle(hDevice);
    system("pause");
       
    return 0;
}

