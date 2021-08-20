#include<ntddk.h>

#define DEVICE_NAME L"\\Device\\MyFirstDevice_fiveopenopen"
//符号链接命名规则
#define SYM_NAME L"\\??\\MyFirstDevice_fiveopenopen"
//#define SYM_NAME L"\\DosDevices\\MyFirstDevice"

void nothing(HANDLE hPpid, HANDLE hMypid, BOOLEAN bCreate) {
	DbgPrint("ProcessNotify\n");
}

//安全的卸载
void DrvierUnload(PDRIVER_OBJECT pDriverObject) {
	NTSTATUS NtStatus;
	DbgPrint("Unload\n");

	if (pDriverObject->DeviceObject) {
		DbgPrint("Unload Device\n");
		UNICODE_STRING sysname = { 0 };
		RtlInitUnicodeString(&sysname, SYM_NAME);
		NtStatus = IoDeleteSymbolicLink(&sysname);

		DbgPrint("DeleteSymbolicLink Return : %d\n", NtStatus);

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

	RtlCopyMemory(readbuffer, "This Message Come From Kernel.", strlen("This Message Come From Kernel."));
	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = strlen("This Message Come From Kernel.");

	DbgPrint("Readlly Read Info Len is %d \n", strlen("This Message Come From Kernel."));
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

	RtlZeroMemory(pDevice->DeviceExtension, 200);

	RtlCopyMemory(pDevice->DeviceExtension, writebuffer, writesize);

	DbgPrint("--%p--%s\n", writebuffer, pDevice);

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = 13;

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
	//创建设备对象
	NtStatus = IoCreateDevice(pDriverObject, 200/*DeviceExtensionSize 设备扩展大小*/, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);

	if (!NT_SUCCESS(NtStatus)) {
		DbgPrint("Create Device Failed :%x\n", NtStatus);

		return NtStatus;
	}

	//设置驱动读写方式

	pDevice->Flags |= DO_BUFFERED_IO;

	//
	// 创建设备成功 创建符号链接
	//
	UNICODE_STRING symname = { 0 };

	RtlInitUnicodeString(&symname, SYM_NAME);

	//IoDeleteSymbolicLink(&symname);
	NtStatus = IoCreateSymbolicLink(&symname, &DeviceName);

	if (NtStatus == STATUS_OBJECT_NAME_COLLISION) {
		UNICODE_STRING symname = { 0 };
		RtlInitUnicodeString(&symname, SYM_NAME);
		IoDeleteSymbolicLink(&symname);
		NtStatus = IoCreateSymbolicLink(&symname, &DeviceName);
	}

	if (!NT_SUCCESS(NtStatus)) {

		DbgPrint("Create SymbolicLink Failed:%x\n", NtStatus);
		IoDeleteDevice(pDevice);
		return NtStatus;
	}

	//分发函数
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;


	//关闭 清理操作
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;

	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyClean;

	pDriverObject->MajorFunction[IRP_MJ_READ] = MyRead;

	pDriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;


	return NtStatus;
}