// r3Consle.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include<winioctl.h>

#define IOCTL_MUL (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9888,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_COPY (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9889,METHOD_BUFFERED,FILE_ANY_ACCESS)

typedef struct {
	WCHAR target[256];
	WCHAR source[256];
} FILEPATH;

int main()
{
	HANDLE hDevice = NULL;
	CHAR readbuffer[50] = { 0 };
	DWORD dwRead = 0;
	DWORD dwWrite = 0;
	hDevice = CreateFile(L"\\\\\.\\MyFirstDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "Open Device Failed\n";
		system("pause");
		return 0;
	}

	std::cout << "Open Success!\n";
	system("pause");

	ReadFile(hDevice, readbuffer, 50, &dwRead, NULL);

	printf("--%p--%s--%d--\n", readbuffer, readbuffer, dwRead);
	system("pause");

	WriteFile(hDevice, "this message come from r3", strlen("this message come from r3"), &dwWrite, NULL);

	printf("--%d--\n", dwWrite);


	//printf("DeviceIO---%d\n", IOCTL_MUL);

	////MDLAddress
	//DWORD dwA = 88888;
	//DWORD dwB = 0;

	//DeviceIoControl(hDevice, IOCTL_MUL, &dwA, 4, &dwB, 4, &dwWrite, NULL);

	////dwA　dwB =>SysTemBuffer,dwWrite->infomation
	//printf("--in %d --out %d --really info %d\n", dwA, dwB, dwWrite);

	system("pause");
	FILEPATH filepath = {L"C:\\123.exe", L"C:\\DbgView.exe" };

	DeviceIoControl(hDevice, IOCTL_COPY, (LPVOID)&filepath, sizeof(FILEPATH), NULL,NULL, &dwWrite, NULL);

	printf("--Copy %ws --To %ws --really info %d\n", filepath.source, filepath.target, dwWrite);

	CloseHandle(hDevice);

	system("pause");

	return 0;
}

