#include<ntifs.h>
#include<windef.h>
#include<ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\MyFirstDevice"
//符号链接命名规则
#define SYM_NAME L"\\??\\MyFirstDevice"

#define IOCTL_MUL (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9888,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_COPY (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9889,METHOD_BUFFERED,FILE_ANY_ACCESS)

BYTE	PhyBuffer[] = { 0x11,0x22,0x33,0x44,0x55 };

BOOL bLock = FALSE;

KSPIN_LOCK spinlock = { 0 };

KDPC dpcobj = { 0 };

typedef struct {
	WCHAR target[256];
	WCHAR source[256];
} FILEPATH;

NTSTATUS KernelSmallCopyFile(PWCHAR pwDestPath, PWCHAR pwSourcePath);

void nothing(HANDLE hPpid, HANDLE hMypid, BOOLEAN bCreate) {
	DbgPrint("ProcessNotify\n");
}

//安全的卸载
void DrvierUnload(PDRIVER_OBJECT pDriverObject) {
	NTSTATUS NtStatus;
	DbgPrint("Unload\n");

	if (pDriverObject->DeviceObject) {
		UNICODE_STRING sysname = { 0 };
		RtlInitUnicodeString(&sysname, SYM_NAME);
		NtStatus = IoDeleteSymbolicLink(&sysname);

		//DbgPrint("DeleteSymbolicLink Return : %d\n", NtStatus);

		IoDeleteDevice(pDriverObject->DeviceObject);

	}
}

// 
//Dispatch
//

//分发函数原型
// NTSTATUS cwkDisptach（PDEVICE_OBJECT pDevice, PIRP pIRP）
// 
//使用设备对象，IRP函数
NTSTATUS MyCreate(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("My Device has be opened\n");

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = 0;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MyClose(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("My Device has be Closed\n");

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = 0;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MyClean(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("My Device has be Cleaned\n");

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = 0;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MyRead(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("My Device has be Readed\n");
	//请求的消息通过IRP保存。
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//获取长度
	ULONG readsize = pStack->Parameters.Read.Length;

	//缓冲区
	PCHAR readbuffer = pIRP->AssociatedIrp.SystemBuffer;

	KIRQL oldirql = 0;

	//RtlCopyMemory(readbuffer, "This Message Come From Kernel.", strlen("This Message Come From Kernel."));

	//只锁了一个
	//避免高中断级跑过多代码
	if (!bLock) { 
		//加锁
		KeAcquireSpinLock(&spinlock, &oldirql);

		bLock = TRUE;

		//解锁
		KeReleaseSpinLock(&spinlock, oldirql);

		//
		//遍历链表
		//

		DbgPrint("AAAAAAAAAAAAAAA\n");

		bLock = FALSE;
	}

	RtlCopyMemory(readbuffer, PhyBuffer, sizeof(PhyBuffer));

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = strlen("This Message Come From Kernel.");

	DbgPrint("Readlly Read Info Len is %d \n", strlen("This Message Come From Kernel."));

	DbgPrint("---Current Irql = %d---\n", KeGetCurrentIrql());


	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MyWrite(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("My Device has be Readed\n");
	//请求的消息通过IRP保存。
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//获取长度
	ULONG writesize = pStack->Parameters.Write.Length;

	//缓冲区
	PCHAR writebuffer = pIRP->AssociatedIrp.SystemBuffer;

	//RtlZeroMemory(pDevice->DeviceExtension, 200);

	RtlZeroMemory(writebuffer, writesize);

	//RtlCopyMemory(pDevice->DeviceExtension, writebuffer, writesize);

	RtlCopyMemory(PhyBuffer, writebuffer, sizeof(PhyBuffer));


	DbgPrint("--%p--%s\n", writebuffer, writebuffer);

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = 13;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MyControl(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;
	//请求的消息通过IRP保存。
	//获得缓冲区
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//获取功能号
	ULONG uIocode = pStack->Parameters.DeviceIoControl.IoControlCode;
	//获得输入缓冲区长度
	ULONG ulInlen = pStack->Parameters.DeviceIoControl.InputBufferLength;
	//获得输出缓冲区长度
	ULONG ulOutlen = pStack->Parameters.DeviceIoControl.OutputBufferLength;


	ULONG ulIoinfo = 0;

	DbgPrint("--Device IO %d--%d--\n", uIocode, IOCTL_COPY);

	switch (uIocode)
	{
	case IOCTL_MUL: {
		//获取缓冲区
		DWORD dwIndata = *(PDWORD)pIRP->AssociatedIrp.SystemBuffer;
		DbgPrint("--Kernel Indata %d--\n", dwIndata);

		dwIndata = dwIndata * 5;

		*(PDWORD)pIRP->AssociatedIrp.SystemBuffer = dwIndata;

		ulIoinfo = 777;
		break;
	}
	case IOCTL_COPY: {
		FILEPATH filepath = *(FILEPATH*)pIRP->AssociatedIrp.SystemBuffer;

		PWCHAR target = ExAllocatePool(NonPagedPool, 0x1000);
		PWCHAR source = ExAllocatePool(NonPagedPool, 0x1000);

		RtlZeroMemory(target, 0x1000);
		RtlZeroMemory(source, 0x1000);

		RtlStringCbCopyW(target, 0x1000, L"\\??\\");
		RtlStringCbCopyW(source, 0x1000, L"\\??\\");
		//__debugbreak();

		RtlStringCbCatW(target, 0x1000, filepath.target);
		RtlStringCbCatW(source, 0x1000, filepath.source);

		DbgPrint("copy File %ws To %ws\n", target, source);

		status = KernelSmallCopyFile(target, source);

		ulIoinfo = 666;

		break;
	}
	default:
		status = STATUS_UNSUCCESSFUL;

		ulIoinfo = 0;

		break;
	}

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = ulIoinfo;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

//删除文件
NTSTATUS KernelDeleteFile(PWCHAR file_path) {
	UNICODE_STRING uFilePath = { 0 };

	NTSTATUS status = STATUS_SUCCESS;

	OBJECT_ATTRIBUTES obja = { 0 };

	RtlInitUnicodeString(&uFilePath, file_path);

	InitializeObjectAttributes(&obja, &uFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwDeleteFile(&obja);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Delete File Failed:%x \n", status);
	}

	return status;
}

//大缓冲区一次性文件拷贝
NTSTATUS KernelCopyFile(PWCHAR pwDestPath, PWCHAR pwSourcePath) {
	HANDLE hFileS = NULL;

	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING uSourcePAth = { 0 };

	OBJECT_ATTRIBUTES  objaS = { 0 };

	IO_STATUS_BLOCK  iostackS = { 0 };

	RtlInitUnicodeString(&uSourcePAth, pwSourcePath);

	InitializeObjectAttributes(&objaS, &uSourcePAth, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwOpenFile(&hFileS, GENERIC_ALL, &objaS, &iostackS, FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Open Source Failed : %x\n", status);
		return status;
	}

	FILE_STANDARD_INFORMATION fbi = { 0 };

	status = ZwQueryInformationFile(hFileS, &iostackS, &fbi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	PVOID pFileBuffer = NULL;

	pFileBuffer = ExAllocatePool(NonPagedPool, fbi.EndOfFile.QuadPart);

	if (!pFileBuffer) {
		DbgPrint("AllocateBuffer Failed\n");
		ZwClose(hFileS);
		return status;
	}

	RtlZeroMemory(pFileBuffer, fbi.EndOfFile.QuadPart);

	LARGE_INTEGER readoffset = { 0 };

	readoffset.QuadPart = 0;

	status = ZwReadFile(hFileS, NULL, NULL, NULL, &iostackS, pFileBuffer, fbi.EndOfFile.QuadPart, &readoffset, 0);

	if (!NT_SUCCESS(status)) {
		DbgPrint("ReadFile Failed :%x\n", status);
		ZwClose(hFileS);
		ExFreePool(pFileBuffer);
		return status;
	}

	DbgPrint("----Info----%d\n", iostackS.Information);

	ZwClose(hFileS);


	//创建新文件

	HANDLE hFileD = NULL;

	UNICODE_STRING uDestPath = { 0 };

	OBJECT_ATTRIBUTES objaD = { 0 };

	IO_STATUS_BLOCK iostackD = { 0 };

	RtlInitUnicodeString(&uDestPath, pwDestPath);

	InitializeObjectAttributes(&objaD, &uDestPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(
		&hFileD,
		GENERIC_ALL,
		&objaD,
		&iostackD,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_SUPERSEDE,//文件不存在 则创建
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (!NT_SUCCESS(status)) {
		DbgPrint("CreateFile Failed: %x\n", status);

		ExFreePool(pFileBuffer);

		return status;
	}

	LARGE_INTEGER writeoffset = { 0 };

	writeoffset.QuadPart = 0;

	status = ZwWriteFile(hFileD, NULL, NULL, NULL, &iostackD, pFileBuffer, fbi.EndOfFile.QuadPart, &writeoffset, NULL);

	if (!NT_SUCCESS(status)) {
		DbgPrint("WriteFile Failed: %x\n", status);

		ExFreePool(pFileBuffer);

		ZwClose(hFileD);

		return status;
	}

	DbgPrint("----Write ----%d\n", iostackD.Information);

	ExFreePool(pFileBuffer);

	//如果不清理句柄，则可以锁文件
	ZwClose(hFileD);

	return status;
}

//小缓冲区多次文件拷贝
NTSTATUS KernelSmallCopyFile(PWCHAR pwDestPath, PWCHAR pwSourcePath) {
	UINT64 count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING target = { 0 };
	UNICODE_STRING source = { 0 };

	//初始化文件字符串
	RtlInitUnicodeString(&target, pwDestPath);
	RtlInitUnicodeString(&source, pwSourcePath);

	HANDLE htarget = NULL;
	HANDLE hsource = NULL;

	PVOID buffer = NULL;
	LARGE_INTEGER offset = { 0 };
	IO_STATUS_BLOCK io_stack = { 0 };

	do
	{
		buffer = ExAllocatePool(NonPagedPool, 1024 * 4);
		if (!buffer) {
			DbgPrint("AllocateBuffer Failed\n");
			break;
		}

		OBJECT_ATTRIBUTES obja_target = { 0 };
		OBJECT_ATTRIBUTES obja_source = { 0 };

		InitializeObjectAttributes(&obja_target, &target, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		InitializeObjectAttributes(&obja_source, &source, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwCreateFile(
			&hsource,
			GENERIC_READ,
			&obja_source,
			&io_stack,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,//文件存在才打开
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);


		if (!NT_SUCCESS(status)) {
			DbgPrint("CreateFile Source Failed: %x\n", status);
			break;
		}

		status = ZwCreateFile(
			&htarget,
			GENERIC_WRITE,
			&obja_target,
			&io_stack,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_WRITE,
			FILE_SUPERSEDE,//文件不存在 则创建
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);


		if (!NT_SUCCESS(status)) {
			DbgPrint("CreateFile target Failed: %x\n", status);
			break;
		}



		while (1) {
			UINT64 length = 4 * 1024;
			status = ZwReadFile(
				hsource, NULL, NULL, NULL,
				&io_stack, buffer, length, &offset, NULL
			);
			if (!NT_SUCCESS(status)) {
				if (status == STATUS_END_OF_FILE)
					status = STATUS_SUCCESS;
				else
					DbgPrint("ReadFile Failed: %x\n", status);
				break;
			}
			//获得实际读取的长度
			length = io_stack.Information;

			status = ZwWriteFile(
				htarget, NULL, NULL, NULL,
				&io_stack, buffer, length, &offset, NULL
			);
			if (!NT_SUCCESS(status)) {
				if (status == STATUS_END_OF_FILE)
					status = STATUS_SUCCESS;
				else
					DbgPrint("WriteFile Failed: %x\n", status);
				break;
			}
			offset.QuadPart += length;
			count += 1;
		}

	} while (0);

	if (htarget != NULL)
		ZwClose(htarget);
	if (hsource != NULL)
		ZwClose(hsource);
	if (buffer != NULL)
		ExFreePool(buffer);

	DbgPrint("Copy File %d 4kPage\n", count);
	return status;
}

//Dpc函数

	VOID DpcRoutine(PVOID context) {

		DbgPrint("---Dpc Run Current Irql=%d\n", KeGetCurrentIrql());

		return;
	}

// 使用驱动对象
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pDriverObject->DriverUnload = DrvierUnload;

	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING DeviceName = { 0 };

	UNICODE_STRING uTargetUnicode = { 0 };

	PDEVICE_OBJECT pDevice = NULL;
	//标准流程 初始化
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);

	DbgPrint("---%wZ---\n", pRegistryPath);

	KeInitializeSpinLock(&spinlock);

	KeInitializeDpc(&dpcobj, DpcRoutine, NULL);

	KeInsertQueueDpc(&dpcobj, NULL, NULL);

	//DbgPrint("---Current Irql = %d---\n", KeGetCurrentIrql());

	//KIRQL oldirql = 0;

	//oldirql = KeRaiseIrqlToDpcLevel();

	//DbgPrint("---Current Irql = %d---\n", KeGetCurrentIrql());

	//KeLowerIrql(oldirql);

	// 注册表操作

	/*
	//open reg

	HANDLE hKey = NULL;

	ULONG ulRetSize = 0;

	OBJECT_ATTRIBUTES objaReg = { 0 };

	PKEY_VALUE_PARTIAL_INFORMATION keyinfo = NULL;

	InitializeObjectAttributes(&objaReg,pRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	//Open Key
	//ZwCreateKey ZwOpenKey 
	
	//ZwCreateKey可以创建也可以打开
	//status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &objaReg, NULL, NULL, REG_OPTION_NON_VOLATILE, &ulDispostion);

	//if (NT_SUCCESS(status)) {
	//	if (ulDispostion == REG_CREATED_NEW_KEY) {
	//		DbgPrint("Key has be Created\n");
	//	}
	//	else if (ulDispostion == REG_OPENED_EXISTING_KEY)
	//	{
	//		DbgPrint("Key has be Opened\n");
	//	}
	//	else {
	//		DbgPrint("Error\n");
	//	}
	//}
	//else {
	//	DbgPrint("Create Key Failed: %x\n", status);
	//}
	

	//确定该注册表存在的时候使用

	status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objaReg);


	do {
		UNICODE_STRING name = { 0 };

		RtlInitUnicodeString(&name, L"ImagePath");

		if (!NT_SUCCESS(status))
			break;

		status = ZwQueryValueKey(hKey, &name, KeyValuePartialInformation, NULL, 0, &ulRetSize);

		if (status == STATUS_BUFFER_TOO_SMALL && ulRetSize != 0) {
			
			keyinfo = ExAllocatePool(NonPagedPool, ulRetSize);

			if (!keyinfo) {

				DbgPrint("ExAllocatePool Secondly Failed\n");

				break;
			}
			RtlZeroMemory(keyinfo, ulRetSize);
		}
		status = ZwQueryValueKey(hKey, &name, KeyValuePartialInformation, keyinfo, ulRetSize, &ulRetSize);

		if (!NT_SUCCESS(status))
			break;

		PWCHAR imagepath = (PWCHAR)(keyinfo->Data);

		DbgPrint("---ImagePath---%ws\n", imagepath);

		//C:\\Windows\System32\drivers \SystemRoot\System32\drivers\acpipmi.sys 更早的启动

		//课后作业 判断前缀是否是\\SystemRoot\\ 则已经拷贝

		UNICODE_STRING prefix = { 0 };
		UNICODE_STRING uImagePath = { 0 };

		RtlInitUnicodeString(&prefix, L"\\SystemRoot\\");
		RtlInitUnicodeString(&uImagePath, imagepath);


		if (RtlPrefixUnicodeString(&prefix, &uImagePath, TRUE)) {

			DbgPrint("Already Copied File\n");

			break;
		}
		
		status = KernelSmallCopyFile(L"\\??\\C:\\Windows\\System32\\drivers\\NewDriver.sys", imagepath);

		if (!NT_SUCCESS(status)) {
			DbgPrint("Copy File Failed :%x\n", status);
			break;
		}

		//change path
		PWCHAR  rootpath = L"\\SystemRoot\\system32\\drivers\\NewDriver.sys";
											//使用环境变量的UNICODE字符串
		status = ZwSetValueKey(hKey, &name, 0, REG_EXPAND_SZ,rootpath, wcslen(rootpath) * 2 + 2);

		if (!NT_SUCCESS(status)) {
			DbgPrint("SetValueKey Failed :%x\n", status);
			break;
		}

	}while (0);

	if (keyinfo != NULL)
		ExFreePool(keyinfo);
	if (hKey != NULL) {
		ZwClose(hKey);
		hKey = NULL;
	}


	//另一种方式 写入注册表
	ULONG tempstart = 1;

	//封装好的函数
	//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pRegistryPath->Buffer, L"Start", REG_DWORD, &tempstart, 4);

	//先删除子项 才能删除父项
	//ZwDeleteKey(hKey);

	//检测注册表是否存在
	//status = RtlCheckRegistryKey(RTL_REGISTRY_SERVICES, L"123456");

	//if (NT_SUCCESS(status)) {
	//	DbgPrint("Be Found\n");
	//}
	//else {
	//	DbgPrint("Not Found\n");

	//	RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, L"123456");
	//	
	//}
	
	*/

	//字符作相关
	/*
	PCHAR	tempbuffer = "C:\\ABc\\ccc\\bbb\\eee.txt";

	STRING	str = { 0 };

	RtlInitString(&str, tempbuffer);

	//转换成宽字符

	RtlAnsiStringToUnicodeString(&DeviceName, &str, TRUE);


	DbgPrint("--%wZ--\n", &DeviceName);

	uTargetUnicode.Buffer = ExAllocatePool(NonPagedPool, 0x1000);
	uTargetUnicode.MaximumLength = 0x1000;

	RtlZeroMemory(uTargetUnicode.Buffer,0x1000);

	RtlCopyUnicodeString(&uTargetUnicode, &DeviceName);

	DbgPrint("--%wZ--\n", &uTargetUnicode);

	//大小写

	RtlUpcaseUnicodeString(&DeviceName, &DeviceName, FALSE);
	DbgPrint("--%wZ--\n", &DeviceName);

	//释放之前申请的缓冲区
	RtlFreeUnicodeString(&DeviceName);
	RtlFreeUnicodeString(&uTargetUnicode);

	//
	//新
	//安全拷贝字符

	PWCHAR tempbuffer2 = ExAllocatePool(NonPagedPool, 0x1000);

	RtlZeroMemory(tempbuffer2, 0x1000);

	RtlStringCbCopyW(tempbuffer2, 0x1000, L"\\??\\");

	//追加字符

	RtlStringCbCatW(tempbuffer2, 0x1000, L"C:\\ABc\\ccc\\bbb\\eee.txt");

	//前缀判断
	UNICODE_STRING temp1 = { 0 }, temp2 = { 0 };

	RtlInitUnicodeString(&temp1, tempbuffer2);

	RtlInitUnicodeString(&temp2, L"\\??\\");

	if (RtlPrefixUnicodeString(&temp2, &temp1, FALSE)) {
		DbgPrint("Be Finded\n");
	}
	UNICODE_STRING temp3 = { 0 }, temp4 = { 0 };


	RtlInitUnicodeString(&temp3, L"C:\\ABc\\ccc\\bbb\\eee.txt");

	RtlInitUnicodeString(&temp4, L"C:\\ABc\\CCC\\bbb\\AVVeee123.txt");


	if  (RtlEqualString(&temp3, &temp4, TRUE)) {
		DbgPrint("temp3 = temp4 \n");
	}

	//字符查找
	UNICODE_STRING temp5 = { 0 };
	//一定要大写
	RtlInitUnicodeString(&temp5, L"*EEE*");//*EEE.TXT

	if (FsRtlIsNameInExpression(&temp5, &temp4, TRUE, NULL)) {
		DbgPrint("Searched\n");
	}

	DbgPrint("--%ws--\n", tempbuffer2);

	*/

	//创建设备对象 

	status = IoCreateDevice(pDriverObject, 200/*DeviceExtensionSize 设备扩展大小*/, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);
	
	if (!NT_SUCCESS(status)) {
		DbgPrint("Create Device Failed :%x\n", status);

		return status;
	}
	
	//设置驱动读写方式

	pDevice->Flags |= DO_BUFFERED_IO; // 0xc8 | 0x200 = 0x2c8

	// 创建设备成功 创建符号链接

	UNICODE_STRING symname = { 0 };

	RtlInitUnicodeString(&symname, SYM_NAME);

	//IoDeleteSymbolicLink(&symname);
	status = IoCreateSymbolicLink(&symname, &DeviceName);

	if (status == STATUS_OBJECT_NAME_COLLISION) {
		UNICODE_STRING symname = { 0 };
		RtlInitUnicodeString(&symname, SYM_NAME);
		IoDeleteSymbolicLink(&symname);
		status = IoCreateSymbolicLink(&symname, &DeviceName);
	}

	if (!NT_SUCCESS(status)) {

		DbgPrint("Create SymbolicLink Failed:%x\n", status);
		IoDeleteDevice(pDevice);
		return status;
	}

	//派遣函数

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;

	//关闭 清理操作
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;

	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyClean;

	pDriverObject->MajorFunction[IRP_MJ_READ] = MyRead;

	pDriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;

	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyControl;

	//KernelDeleteFile(L"\\??\\C:\\123.exe");

	//KernelSmallCopyFile(L"\\??\\C:\\789.exe", L"\\??\\C:\\567.exe");

	return status;
}