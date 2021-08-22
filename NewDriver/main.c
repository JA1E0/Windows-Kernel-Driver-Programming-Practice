#include<ntifs.h>
#include<windef.h>
#include<ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\MyFirstDevice_fiveopenopen"
//����������������
#define SYM_NAME L"\\DosDevices\\MyFirstDevice"

#define IOCTL_MUL (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9888,METHOD_BUFFERED,FILE_ANY_ACCESS)

void nothing(HANDLE hPpid, HANDLE hMypid, BOOLEAN bCreate) {
	DbgPrint("ProcessNotify\n");
}

//��ȫ��ж��
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

//�ַ�����ԭ��
// NTSTATUS cwkDisptach��PDEVICE_OBJECT pDevice, PIRP pIRP��
// 
//ʹ���豸����IRP����
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
	//�������Ϣͨ��IRP���档
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//��ȡ����
	ULONG readsize = pStack->Parameters.Read.Length;

	//������
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
	//�������Ϣͨ��IRP���档
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//��ȡ����
	ULONG writesize = pStack->Parameters.Write.Length;

	//������
	PCHAR writebuffer = pIRP->AssociatedIrp.SystemBuffer;

	RtlZeroMemory(pDevice->DeviceExtension, 200);

	RtlCopyMemory(pDevice->DeviceExtension, writebuffer, writesize);

	DbgPrint("--%p--%s\n", writebuffer, writebuffer);

	pIRP->IoStatus.Status = status;

	pIRP->IoStatus.Information = 13;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS MyControl(PDEVICE_OBJECT pDevice, PIRP pIRP) {
	NTSTATUS status = STATUS_SUCCESS;
	//�������Ϣͨ��IRP���档
	//��û�����
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//��ȡ���ܺ�
	ULONG uIocode = pStack->Parameters.DeviceIoControl.IoControlCode;
	//������뻺��������
	ULONG ulInlen = pStack->Parameters.DeviceIoControl.InputBufferLength;
	//����������������
	ULONG ulOutlen = pStack->Parameters.DeviceIoControl.OutputBufferLength;


	ULONG ulIoinfo = 0;

	DbgPrint("--Device IO %d--%d--\n", uIocode, IOCTL_MUL);

	switch (uIocode)
	{
	case IOCTL_MUL: {
		//��ȡ������
		DWORD dwIndata = *(PDWORD)pIRP->AssociatedIrp.SystemBuffer;
		DbgPrint("--Kernel Indata %d--\n", dwIndata);

		dwIndata  = dwIndata* 5;

		*(PDWORD)pIRP->AssociatedIrp.SystemBuffer = dwIndata;

		ulIoinfo = 777;
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
// ʹ����������
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pDriverObject->DriverUnload = DrvierUnload;
	NTSTATUS NtStatus = STATUS_SUCCESS;

	UNICODE_STRING DeviceName = { 0 };

	UNICODE_STRING uTargetUnicode = { 0 };

	PDEVICE_OBJECT pDevice = NULL;
	//��׼���� ��ʼ��
	//RtlInitUnicodeString(&DeviceName, DEVICE_NAME);

	PCHAR	tempbuffer = "C:\\ABc\\ccc\\bbb\\eee.txt";

	STRING	str = { 0 };

	RtlInitString(&str, tempbuffer);

	//ת���ɿ��ַ�

	RtlAnsiStringToUnicodeString(&DeviceName, &str, TRUE);


	DbgPrint("--%wZ--\n", &DeviceName);

	uTargetUnicode.Buffer = ExAllocatePool(NonPagedPool, 0x1000);
	uTargetUnicode.MaximumLength = 0x1000;

	RtlZeroMemory(uTargetUnicode.Buffer,0x1000);

	RtlCopyUnicodeString(&uTargetUnicode, &DeviceName);

	DbgPrint("--%wZ--\n", &uTargetUnicode);

	//��Сд

	RtlUpcaseUnicodeString(&DeviceName, &DeviceName, FALSE);
	DbgPrint("--%wZ--\n", &DeviceName);
	 
	//�ͷ�֮ǰ����Ļ�����
	RtlFreeUnicodeString(&DeviceName);
	RtlFreeUnicodeString(&uTargetUnicode);

	//
	//��
	//��ȫ�����ַ�

	PWCHAR tempbuffer2 = ExAllocatePool(NonPagedPool, 0x1000);

	RtlZeroMemory(tempbuffer2, 0x1000);

	RtlStringCbCopyW(tempbuffer2, 0x1000, L"\\??\\");

	//׷���ַ�

	RtlStringCbCatW(tempbuffer2, 0x1000, L"C:\\ABc\\ccc\\bbb\\eee.txt");

	//ǰ׺�ж�
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

	//�ַ�����
	UNICODE_STRING temp5 = { 0 };
	//һ��Ҫ��д	
	RtlInitUnicodeString(&temp5, L"*EEE*");//*EEE.TXT

	if (FsRtlIsNameInExpression(&temp5, &temp4, TRUE, NULL)) {
		DbgPrint("Searched\n");
	}

	DbgPrint("--%ws--\n", tempbuffer2);




	//�����豸���� /*
	//NtStatus = IoCreateDevice(pDriverObject, 200/*DeviceExtensionSize �豸��չ��С*/, &DeviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);

	//if (!NT_SUCCESS(NtStatus)) {
	//	DbgPrint("Create Device Failed :%x\n", NtStatus);

	//	return NtStatus;
	//}

	////����������д��ʽ

	////__debugbreak();
	//pDevice->Flags |= DO_BUFFERED_IO; // 0xc8 | 0x200 = 0x2c8

	////
	//// �����豸�ɹ� ������������
	////
	//UNICODE_STRING symname = { 0 };

	//RtlInitUnicodeString(&symname, SYM_NAME);

	////IoDeleteSymbolicLink(&symname);
	//NtStatus = IoCreateSymbolicLink(&symname, &DeviceName);

	//if (NtStatus == STATUS_OBJECT_NAME_COLLISION) {
	//	UNICODE_STRING symname = { 0 };
	//	RtlInitUnicodeString(&symname, SYM_NAME);
	//	IoDeleteSymbolicLink(&symname);
	//	NtStatus = IoCreateSymbolicLink(&symname, &DeviceName);
	//}

	//if (!NT_SUCCESS(NtStatus)) {

	//	DbgPrint("Create SymbolicLink Failed:%x\n", NtStatus);
	//	IoDeleteDevice(pDevice);
	//	return NtStatus;
	//}

	////�ַ�����
	//pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;


	////�ر� �������
	//pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;

	//pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyClean;

	//pDriverObject->MajorFunction[IRP_MJ_READ] = MyRead;

	//pDriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;

	//pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyControl;

	return NtStatus;
}