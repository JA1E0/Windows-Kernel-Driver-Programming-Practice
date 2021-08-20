#include<ntddk.h>

#define DEVICE_NAME L"\\Device\\MyFirstDevice"
//符号链接命名规则
#define SYM_NAME L"\\??\\MyFirstDevice"
void nothing(HANDLE hPpid, HANDLE hMypid, BOOLEAN bCreate) {
	DbgPrint("ProcessNotify\n");
}

//安全的卸载
void DrvierUnload(PDRIVER_OBJECT pDriverObject) {
	DbgPrint("Unload\n");
	
	if (pDriverObject->DeviceObject) {
		IoDeleteDevice(pDriverObject->DeviceObject);

		UNICODE_STRING sysname = { 0 };

		RtlInitUnicodeString(&sysname, SYM_NAME);
		IoDeleteSymbolicLink(&sysname);
	}
}

// 
//Dispatch
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

// 使用驱动对象
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pDriverObject->DriverUnload = DrvierUnload;
	NTSTATUS NtStatus = STATUS_SUCCESS;

	UNICODE_STRING DeviceName = { 0 };

	PDEVICE_OBJECT pDevice = NULL;
	//标准流程 初始化
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	//能不能用其他驱动对象创建device
	NtStatus = IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);

	//打开其他驱动对象
	//NtStatus = IoCreateDevice((PDRIVER_OBJECT)0xFFFFF80643A50000, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);

	if (!NT_SUCCESS(NtStatus)) {
		DbgPrint("Create Device Failed :%x\n", NtStatus);

		return NtStatus;
	}

	//
	// 创建设备成功 创建符号链接
	//
	UNICODE_STRING symname = { 0 };

	RtlInitUnicodeString(&symname, SYM_NAME);

	NtStatus = IoCreateSymbolicLink(&symname, &DeviceName);

	if (!NT_SUCCESS(NtStatus)) {

		DbgPrint("Create SymbolicLink Failed:%x\n", NtStatus);
		IoDeleteDevice(pDevice);
		return NtStatus;
	}

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;

	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyClean;

	return NtStatus;
}