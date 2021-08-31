// r3Consle.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <iostream>
#include <Windows.h>
#include<winioctl.h>
#include<process.h>

#define IOCTL_MUL (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9888,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_COPY (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9889,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_PROC (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9890,METHOD_BUFFERED,FILE_ANY_ACCESS)

typedef struct {
	WCHAR target[256];
	WCHAR source[256];
} FILEPATH;

typedef struct {
	HANDLE hEvent1;
	HANDLE hEvent2;
} MyEvent, * PMyEvent;


MyEvent myevent = { 0 };

unsigned int __stdcall ThreadProc(PVOID pParam) {

	MyEvent myevent = *(MyEvent*)pParam;
	HKEY hkey = NULL;
	DWORD dwdisp = 0;
	DWORD dwRet = 0;


	const WCHAR* value = L"Number";
	const WCHAR* reg = L"SYSTEM\\ControlSet001\\Services\\AddNumber";
	DWORD dwData = 1;
	DWORD cbData = 4 ;
	DWORD dwType = 0;
	do {
		//HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\AddNumber"
	//打开创建注册表
		dwRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE, reg, 0,
			NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hkey, &dwdisp);
		if (dwRet != ERROR_SUCCESS) {
			printf("Reg Create Key Failed : %d\n", dwRet);
			break;
		}
		//写入注册表
		dwRet = RegSetValueEx(hkey, value, 0, REG_DWORD, (PBYTE)&dwData, cbData);
		if (dwRet != ERROR_SUCCESS) {
			printf("Reg Set Key Failed : %d\n", dwRet);
			break;
		}

		//关闭句柄
		RegCloseKey(hkey);
		hkey = NULL;

		while (1)
		{
			printf("Set Kernel Event Handle %x\n", myevent.hEvent1);
			printf("Set Kernel Event Handle %x\n", myevent.hEvent2);

			SetEvent(myevent.hEvent1);

			//WaitForSingleObject()
			//等待内核事件传递，再进行读取

			dwRet = WaitForSingleObject(myevent.hEvent2, INFINITE);
			if (dwRet == WAIT_FAILED) {
				printf("WaitForSingleObject Failed: %d\n", GetLastError());
				break;
			}


			//读取注册表值
			//dwRet = RegCreateKeyEx(HKEY_LOCAL_MACHINE, reg, 0,
			//	NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &dwdisp);
			//if (dwRet != ERROR_SUCCESS) {
			//	printf("Reg Open Key Failed : %d\n", dwRet);
			//	break;
			//}

			//dwRet = RegQueryValueEx(hkey, value, 0, &dwType, (PBYTE)&dwData, &cbData);

			//if (dwRet != ERROR_SUCCESS) {
			//	printf("Reg Query Key Failed : %d\n", dwRet);
			//	break;
			//}
			RegGetValue(HKEY_LOCAL_MACHINE, reg, value, REG_DWORD, &dwType, (PBYTE)&dwData, &cbData);

			if (dwRet != ERROR_SUCCESS) {
				printf("Reg Query Key Failed : %d\n", dwRet);
				break;
			}
			printf("Get Number = %d\n", dwData);

			RegCloseKey(hkey);

			Sleep(1500);
		}
	} while (0);

	_endthreadex(0);
	return 0;
}

int main()
{
	HANDLE hDevice = NULL;
	CHAR readbuffer[50] = { 0 };
	DWORD dwRead = 0;
	DWORD dwWrite = 0;
	HANDLE hThread = NULL;
	hDevice = CreateFile(L"\\\\\.\\MyFirstDevice", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "Open Device Failed\n";
		system("pause");
		return 0;
	}

	std::cout << "Open Success!\n";
	system("pause");
	/*
	ReadFile(hDevice, readbuffer, 50, &dwRead, NULL);

	printf("--%p--%s--%d--\n", readbuffer, readbuffer, dwRead);
	system("pause");

	WriteFile(hDevice, "this message come from r3", strlen("this message come from r3"), &dwWrite, NULL);

	printf("--%d--\n", dwWrite);


	printf("DeviceIO---%d\n", IOCTL_MUL);

	//MDLAddress
	DWORD dwA = 88888;
	DWORD dwB = 0;

	DeviceIoControl(hDevice, IOCTL_MUL, &dwA, 4, &dwB, 4, &dwWrite, NULL);

	//dwA　dwB =>SysTemBuffer,dwWrite->infomation
	printf("--in %d --out %d --really info %d\n", dwA, dwB, dwWrite);


	system("pause");

	FILEPATH filepath = {L"C:\\123.exe", L"C:\\DbgView.exe" };

	DeviceIoControl(hDevice, IOCTL_COPY, (LPVOID)&filepath, sizeof(FILEPATH), NULL,NULL, &dwWrite, NULL);

	printf("--Copy %ws --To %ws --really info %d\n", filepath.source, filepath.target, dwWrite);

	*/
	/*
	//读取创建的进程
	DWORD dwCount = 10;

	UCHAR buffer[67] = { 0 };

	DeviceIoControl(hDevice, IOCTL_PROC, &dwCount, sizeof(DWORD), buffer, sizeof(buffer), &dwWrite, NULL);

	printf("--Get %d ListEntries/ListEntry \n--out \n%s \n--really info %d\n", dwCount, buffer, dwWrite);

	system("pause");

	*/

	//参数决定是同步事件还是通知事件，FALSE为同步事件
	do
	{
		myevent.hEvent1 = CreateEvent(NULL, FALSE, FALSE, NULL);
		myevent.hEvent2 = CreateEvent(NULL, FALSE, FALSE, NULL);

		if (myevent.hEvent1 == INVALID_HANDLE_VALUE || myevent.hEvent2 == INVALID_HANDLE_VALUE) {
			printf("Create Event Failed\n");
			break;
		}

		DeviceIoControl(hDevice, IOCTL_MUL, &myevent, sizeof(MyEvent), &dwWrite, sizeof(DWORD), &dwRead, NULL);

		hThread = (HANDLE)_beginthreadex(NULL, 0, ThreadProc, &myevent, 0, NULL);

		WaitForSingleObject(hThread, INFINITE);
	} while (0);

	CloseHandle(hThread);
	CloseHandle(hDevice);
	
	//system("pause");

	return 0;
}

