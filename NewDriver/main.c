#include<ntifs.h>
#include<windef.h>
#include<ntstrsafe.h>

#define DEVICE_NAME L"\\Device\\MyFirstDevice"
//����������������
#define SYM_NAME L"\\??\\MyFirstDevice"

#define IOCTL_MUL (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9888,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_COPY (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9889,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL_PROC (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN,0x9890,METHOD_BUFFERED,FILE_ANY_ACCESS)

KTIMER kerneltimer;
//������ſ�ʹ��
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

BOOL work = FALSE;

BYTE	PhyBuffer[] = { 0x11,0x22,0x33,0x44,0x55 };

BOOL bLock = FALSE;

KSPIN_LOCK spinlock = { 0 };

KDPC dpcobj = { 0 };

KEVENT gkevent = { 0 };

BYTE	mmcode[10] = { 0 };

PKEVENT pKernelEvent1 = NULL;
PKEVENT pKernelEvent2 = NULL;

typedef struct {
	WCHAR target[256];
	WCHAR source[256];
} FILEPATH;

//����ṹ��ʼ��
typedef struct _MyStruct {
	HANDLE pid;

	LIST_ENTRY list;

	PEPROCESS pEprocesspbj;

	BYTE processname[64];
}MyStruct, * PMyStruct;

typedef struct {
	HANDLE hEvent1;
	HANDLE hEvent2;
} MyEvent, * PMyEvent;

LIST_ENTRY listhead = { 0 };

NTSTATUS KernelSmallCopyFile(PWCHAR pwDestPath, PWCHAR pwSourcePath);

//��ȫ��ж��

VOID KernelThread3(PVOID context) {

	LARGE_INTEGER timeout, sleeptime = { 0 };

	timeout.QuadPart = -10 * 1000 * 1000 * 5;
	sleeptime.QuadPart = -10 * 1000 * 1000 * 1;

	//\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\AddNumber\\Number

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hkey = NULL;
	ULONG ulLen = 0;
	DWORD dwValue = 0;
	UNICODE_STRING uReg = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\AddNumber\\");
	UNICODE_STRING uValue = RTL_CONSTANT_STRING(L"Number");
	PKEY_VALUE_PARTIAL_INFORMATION keyinfo = ExAllocatePool(NonPagedPool, 0x1000);


	OBJECT_ATTRIBUTES objaReg = { 0 };
	InitializeObjectAttributes(&objaReg, &uReg, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	RtlZeroMemory(keyinfo, 0x1000);

	while (1)
	{
		//KeWaitForSingleObject(pKernelEvent, Executive, KernelMode, FALSE, &NULL);

		//���ó�ʱʱ��

		status = KeWaitForSingleObject(pKernelEvent1, Executive, KernelMode, FALSE, &timeout);

		if (status == STATUS_TIMEOUT) {
			DbgPrint("Time Out\n");
			break;
		}

		DbgPrint("This Requset com from R3 Routine\n");

		//ȡr3����,Ȼ���д���ٰ�����д��
		//��ע���
		status = ZwOpenKey(&hkey, KEY_ALL_ACCESS, &objaReg);
		if (!NT_SUCCESS(status)) {
			DbgPrint("Open Key Failed : %x", status);
			break;
		}
		//��ע���ֵ+2��д��ע���

		status = ZwQueryValueKey(hkey, &uValue, KeyValuePartialInformation, keyinfo, 0x1000, &ulLen);
		if (!NT_SUCCESS(status)) {
			DbgPrint("Query Key Failed : %x", status);
			break;
		}

		dwValue = *(PDWORD)(keyinfo->Data);
		DbgPrint("Read Value : %d\n", dwValue);

		dwValue += 1;

		status = ZwSetValueKey(hkey, &uValue, 0, REG_DWORD, &dwValue, sizeof(DWORD));

		if (!NT_SUCCESS(status)) {
			DbgPrint("Set Key Failed : %x", status);
			break;
		}

		ZwClose(hkey);
		RtlZeroMemory(keyinfo, 0x1000);

		KeSetEvent(pKernelEvent2, IO_NO_INCREMENT, FALSE);

		//KeDelayExecutionThread(KernelMode, FALSE, &sleeptime);
	}
	ExFreePool(keyinfo);
	ObDereferenceObject(pKernelEvent1);
	ObDereferenceObject(pKernelEvent2);
	PsTerminateSystemThread(0);
}

VOID KernelThread2(PVOID context) {
	LARGE_INTEGER sleeptime = { 0 };

	//����ת�����¼���ַ
	PKEVENT pevent = (PKEVENT)context;
	//��ֵ��ʾ���ʱ��
	//��ʾ����3��һ��
	sleeptime.QuadPart = -10 * 1000 * 1000 * 3;

	PVOID apiddr = NULL;

	UNICODE_STRING apiname = { 0 };

	RtlInitUnicodeString(&apiname, L"NtCreateFile");

	apiddr = MmGetSystemRoutineAddress(&apiname);

	while (1) {
		//����
		KeDelayExecutionThread(KernelMode, FALSE, &sleeptime);

		RtlZeroMemory(mmcode, 10);

		RtlCopyMemory(mmcode, apiddr, 10);

		DbgPrint("Set Event\n");
		//������������ʾ�Ƿ�������KeWaitXXX����
		KeSetEvent(&gkevent, IO_NO_INCREMENT, FALSE);
	}

	PsTerminateSystemThread(0);
}

VOID KernelThread1(PVOID context) {
	//KeInitializeEvent(&gkevent, NotificationEvent, FALSE);
	KeInitializeEvent(&gkevent, SynchronizationEvent, FALSE);

	HANDLE hthread = NULL;

	NTSTATUS status = PsCreateSystemThread(&hthread, 0, NULL, NULL, NULL, KernelThread2, &gkevent);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Create Thread Failed : %x", status);
		return;
	}

	ZwClose(hthread);

	while (1) {
		KeWaitForSingleObject(&gkevent, Executive, KernelMode, FALSE, NULL);

		//KeResetEvent(&gkevent);

		//DbgPrint("Event Has be seted\n");

		for (int i = 0; i < 10; i++) {
			DbgPrint("Mmcode <%x>\n", mmcode[i]);
		}
	}
	PsTerminateSystemThread(0);

}

VOID ProcessNotifyFun(HANDLE pid, HANDLE processid, BOOLEAN bcaref) {

	if (bcaref) {
		DbgPrint("process create, PID is %d\n", processid);

		//PEPROCESS tempep = PsGetCurrentProcess();
		PEPROCESS tempep = NULL;

		PsLookupProcessByProcessId(processid, &tempep);

		if (!tempep) {
			return;
		}

		PUCHAR processname = PsGetProcessImageFileName(tempep);

		DbgPrint("Process Name is  %s\n", processname);

		PMyStruct ptempptr = ExAllocatePool(NonPagedPool, sizeof(MyStruct));

		if (ptempptr) {

			KIRQL oldirql;

			PLIST_ENTRY templist = NULL;

			RtlZeroMemory(ptempptr, sizeof(MyStruct));

			//��Ա��ֵ

			ptempptr->pEprocesspbj = tempep;

			ptempptr->pid = processid;

			RtlCopyMemory(ptempptr->processname, processname, strlen(processname));

			//����
			KeAcquireSpinLock(&spinlock, &oldirql);

			//β����������
			InsertTailList(&listhead, &(ptempptr->list));

			//����
			KeReleaseSpinLock(&spinlock, oldirql);
		}
		//InsertHeadList ͷ������
		//RemoveEntryList(); �Ƴ��ض���
		//RemoveHeadList ͷ���Ƴ�
	}

}


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

void DrvierUnload(PDRIVER_OBJECT pDriverObject) {
	NTSTATUS NtStatus;
	work = TRUE;
	DbgPrint("Unload\n");
	//IoStopTimer(pDriverObject->DeviceObject);
	if (pDriverObject->DeviceObject) {
		UNICODE_STRING sysname = { 0 };
		RtlInitUnicodeString(&sysname, SYM_NAME);
		NtStatus = IoDeleteSymbolicLink(&sysname);

		//DbgPrint("DeleteSymbolicLink Return : %d\n", NtStatus);

		IoDeleteDevice(pDriverObject->DeviceObject);

	}


	/*
	PsSetCreateProcessNotifyRoutine(ProcessNotifyFun, TRUE);

	//�������

	PLIST_ENTRY  templist = NULL;

	PMyStruct tempptr = NULL;

	//��������

	for (PLIST_ENTRY templist = listhead.Flink; templist != &listhead; templist = templist->Flink) {
		PMyStruct tempptr = CONTAINING_RECORD(templist, MyStruct, list);
		DbgPrint("--%d--%p--%s\n",
			tempptr->pid, tempptr->pEprocesspbj, tempptr->processname);
	}

	while (listhead.Flink != &listhead) {

		//���ؽڵ�ָ��
		templist = RemoveTailList(&listhead);

		tempptr = CONTAINING_RECORD(templist, MyStruct, list);

		DbgPrint("--%d--%p--%s\n",
			tempptr->pid, tempptr->pEprocesspbj, tempptr->processname);

		ExFreePool(tempptr);
	}
	if (IsListEmpty(&listhead)) {
		DbgPrint("Free List Succeed\n");
	}
	*/
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

	KIRQL oldirql = 0;

	//RtlCopyMemory(readbuffer, "This Message Come From Kernel.", strlen("This Message Come From Kernel."));

	//ֻ����һ��
	//������жϼ��ܹ������
	if (!bLock) {
		//����
		KeAcquireSpinLock(&spinlock, &oldirql);

		bLock = TRUE;

		//����
		KeReleaseSpinLock(&spinlock, oldirql);

		//
		//��������
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
	//�������Ϣͨ��IRP���档
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIRP);

	//��ȡ����
	ULONG writesize = pStack->Parameters.Write.Length;

	//������
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

	//DbgPrint("--Device IO %d--%d--\n", uIocode, IOCTL_COPY);

	switch (uIocode)
	{
	case IOCTL_MUL: {
		//__debugbreak();
		//��ȡ������
		DWORD dwIndata = *(PDWORD)pIRP->AssociatedIrp.SystemBuffer;
		DbgPrint("--Kernel Indata %d--\n", dwIndata);

		//��ȡ���
		PMyEvent myevent = (PMyEvent)pIRP->AssociatedIrp.SystemBuffer;
		//���ֻ�����ڵ�ǰ����,��ȡ��ǰ���¼�����
		//https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle

		status = ObReferenceObjectByHandle(myevent->hEvent1, EVENT_MODIFY_STATE, *ExEventObjectType, KernelMode, &pKernelEvent1, NULL);
		NTSTATUS status2 = ObReferenceObjectByHandle(myevent->hEvent2, EVENT_MODIFY_STATE, *ExEventObjectType, KernelMode, &pKernelEvent2, NULL);

		if (NT_SUCCESS(status) && NT_SUCCESS(status2)) {
			//��ǰ���ü�����һ
			//���������������ں˶���

			HANDLE hThread = NULL;

			status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, KernelThread3, NULL);
			if (!NT_SUCCESS(status)) {
				DbgPrint("Created Thread3 Failed : %x\n", status);
			}
		}

		dwIndata = dwIndata * 5;

		*(PDWORD)pIRP->AssociatedIrp.SystemBuffer = dwIndata;

		ulIoinfo = ulOutlen;
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

		RtlStringCbCatW(target, 0x1000, filepath.target);
		RtlStringCbCatW(source, 0x1000, filepath.source);

		DbgPrint("copy File %ws To %ws\n", target, source);

		status = KernelSmallCopyFile(target, source);

		ulIoinfo = ulOutlen;

		break;
	}
	case IOCTL_PROC: {
		//__debugbreak();
		DbgPrint("IO GetProcess Start! \n");

		DWORD dwCount = *(PDWORD)pIRP->AssociatedIrp.SystemBuffer;

		PUCHAR pOutBuffer = (PUCHAR)pIRP->AssociatedIrp.SystemBuffer;

		RtlZeroMemory(pOutBuffer, ulOutlen);

		PUCHAR testbuffer = ExAllocatePool(NonPagedPool, ulOutlen);

		RtlZeroMemory(testbuffer, ulOutlen);

		for (PLIST_ENTRY templist = listhead.Flink; templist != &listhead; templist = templist->Flink) {
			if (dwCount > 0) {

				PMyStruct tempptr = CONTAINING_RECORD(templist, MyStruct, list);

				UCHAR tempStr[256] = { 0 };

				status = RtlStringCbPrintfA(tempStr, 0x256, "--%d--%p--%s\n",

					tempptr->pid, tempptr->pEprocesspbj, tempptr->processname);

				if ((strlen(tempStr) + strlen(testbuffer)) >= ulOutlen) {
					DbgPrint("[WARNING] Get ProcessName Buffer Tool Small\n");
					break;
				}
				RtlStringCbCatA(testbuffer, ulOutlen, tempStr);

				if (status == STATUS_BUFFER_OVERFLOW) {
					DbgPrint("[WARNING] Get ProcessName Buffer OVERFLOW\n");
					break;
				}
			}
			else {
				break;
			}
			dwCount--;
		}
		///__debugbreak();
		RtlCopyMemory(pOutBuffer, testbuffer, ulOutlen - 1);
		DbgPrint("uOutLen : %d\n", ulOutlen);
		ExFreePool(testbuffer);
		//ʵ�ʳ���
		ulIoinfo = strlen(pOutBuffer) + 1;
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

//ɾ���ļ�
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

//�󻺳���һ�����ļ�����
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


	//�������ļ�

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
		FILE_SUPERSEDE,//�ļ������� �򴴽�
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

	//���������������������ļ�
	ZwClose(hFileD);

	return status;
}

//С����������ļ�����
NTSTATUS KernelSmallCopyFile(PWCHAR pwDestPath, PWCHAR pwSourcePath) {
	UINT64 count = 0;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING target = { 0 };
	UNICODE_STRING source = { 0 };

	//��ʼ���ļ��ַ���
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
			FILE_OPEN,//�ļ����ڲŴ�
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
			FILE_SUPERSEDE,//�ļ������� �򴴽�
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
			//���ʵ�ʶ�ȡ�ĳ���
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

//Dpc����

VOID DpcRoutine(PVOID context) {

	DbgPrint("---Dpc Run Current Irql=%d\n", KeGetCurrentIrql());

	return;
}

VOID TimeWorker(PVOID context) {
	DbgPrint("Irql = %d\n", KeGetCurrentIrql());

	DbgPrint("Processname = %s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));

	return;
}
WORK_QUEUE_ITEM workobj = { 0 };

VOID WorkItemRoutine(PVOID Context) {
	DbgPrint("Irql = %d\n", KeGetCurrentIrql());

	DbgPrint("Processname = %s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));

	LARGE_INTEGER sleeptime = { 0 };

	sleeptime.QuadPart = -10 * 1000 * 1000 * 1;

	while (1)
	{
		if (work) {
			break;
		}
		DbgPrint("Worked Item!\n");
		KeDelayExecutionThread(KernelMode, FALSE, &sleeptime);

	}

	return;
}

VOID WorkItemRoutine2(PVOID Context) {

	DbgPrint("Irql = %d\n", KeGetCurrentIrql());

	DbgPrint("Processname = %s\n", PsGetProcessImageFileName(PsGetCurrentProcess()));
	__debugbreak();

	LARGE_INTEGER sleeptime = { 0 };

	sleeptime.QuadPart = -10 * 1000 * 1000 * 1;

	KeDelayExecutionThread(KernelMode, FALSE, &sleeptime);

	DbgPrint("WorkItemRoutine2 Worked!\n");

	KeSetEvent((PKEVENT)Context, 0, FALSE);

	return;
}
// ʹ����������

//NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
//{
//	pDriverObject->DriverUnload = DrvierUnload;
//
//	NTSTATUS status = STATUS_SUCCESS;
//
//	UNICODE_STRING DeviceName = { 0 };
//
//	UNICODE_STRING uTargetUnicode = { 0 };
//
//	PDEVICE_OBJECT pDevice = NULL;
//
//	HANDLE hThread = NULL;
//	//��׼���� ��ʼ��
//	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
//
//	DbgPrint("---%wZ---\n", pRegistryPath);
//
//	KeInitializeSpinLock(&spinlock);
//
//	//status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, KernelThread1, &gkevent);
//
//	/*
//	KeInitializeDpc(&dpcobj, DpcRoutine, NULL);
//
//	KeInsertQueueDpc(&dpcobj, NULL, NULL);
//	*/
//
//	//DbgPrint("---Current Irql = %d---\n", KeGetCurrentIrql());
//
//	//KIRQL oldirql = 0;
//
//	//oldirql = KeRaiseIrqlToDpcLevel();
//
//	//DbgPrint("---Current Irql = %d---\n", KeGetCurrentIrql());
//
//	//KeLowerIrql(oldirql);
//
//	// ע������
//
//	/*
//	//open reg
//
//	HANDLE hKey = NULL;
//
//	ULONG ulRetSize = 0;
//
//	OBJECT_ATTRIBUTES objaReg = { 0 };
//
//	PKEY_VALUE_PARTIAL_INFORMATION keyinfo = NULL;
//
//	InitializeObjectAttributes(&objaReg,pRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
//	//Open Key
//	//ZwCreateKey ZwOpenKey
//
//	//ZwCreateKey���Դ���Ҳ���Դ�
//	//status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &objaReg, NULL, NULL, REG_OPTION_NON_VOLATILE, &ulDispostion);
//
//	//if (NT_SUCCESS(status)) {
//	//	if (ulDispostion == REG_CREATED_NEW_KEY) {
//	//		DbgPrint("Key has be Created\n");
//	//	}
//	//	else if (ulDispostion == REG_OPENED_EXISTING_KEY)
//	//	{
//	//		DbgPrint("Key has be Opened\n");
//	//	}
//	//	else {
//	//		DbgPrint("Error\n");
//	//	}
//	//}
//	//else {
//	//	DbgPrint("Create Key Failed: %x\n", status);
//	//}
//
//
//	//ȷ����ע�����ڵ�ʱ��ʹ��
//
//	status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &objaReg);
//
//
//	do {
//		UNICODE_STRING name = { 0 };
//
//		RtlInitUnicodeString(&name, L"ImagePath");
//
//		if (!NT_SUCCESS(status))
//			break;
//
//		status = ZwQueryValueKey(hKey, &name, KeyValuePartialInformation, NULL, 0, &ulRetSize);
//
//		if (status == STATUS_BUFFER_TOO_SMALL && ulRetSize != 0) {
//
//			keyinfo = ExAllocatePool(NonPagedPool, ulRetSize);
//
//			if (!keyinfo) {
//
//				DbgPrint("ExAllocatePool Secondly Failed\n");
//
//				break;
//			}
//			RtlZeroMemory(keyinfo, ulRetSize);
//		}
//		status = ZwQueryValueKey(hKey, &name, KeyValuePartialInformation, keyinfo, ulRetSize, &ulRetSize);
//
//		if (!NT_SUCCESS(status))
//			break;
//
//		PWCHAR imagepath = (PWCHAR)(keyinfo->Data);
//
//		DbgPrint("---ImagePath---%ws\n", imagepath);
//
//		//C:\\Windows\System32\drivers \SystemRoot\System32\drivers\acpipmi.sys ���������
//
//		//�κ���ҵ �ж�ǰ׺�Ƿ���\\SystemRoot\\ ���Ѿ�����
//
//		UNICODE_STRING prefix = { 0 };
//		UNICODE_STRING uImagePath = { 0 };
//
//		RtlInitUnicodeString(&prefix, L"\\SystemRoot\\");
//		RtlInitUnicodeString(&uImagePath, imagepath);
//
//
//		if (RtlPrefixUnicodeString(&prefix, &uImagePath, TRUE)) {
//
//			DbgPrint("Already Copied File\n");
//
//			break;
//		}
//
//		status = KernelSmallCopyFile(L"\\??\\C:\\Windows\\System32\\drivers\\NewDriver.sys", imagepath);
//
//		if (!NT_SUCCESS(status)) {
//			DbgPrint("Copy File Failed :%x\n", status);
//			break;
//		}
//
//		//change path
//		PWCHAR  rootpath = L"\\SystemRoot\\system32\\drivers\\NewDriver.sys";
//											//ʹ�û���������UNICODE�ַ���
//		status = ZwSetValueKey(hKey, &name, 0, REG_EXPAND_SZ,rootpath, wcslen(rootpath) * 2 + 2);
//
//		if (!NT_SUCCESS(status)) {
//			DbgPrint("SetValueKey Failed :%x\n", status);
//			break;
//		}
//
//	}while (0);
//
//	if (keyinfo != NULL)
//		ExFreePool(keyinfo);
//	if (hKey != NULL) {
//		ZwClose(hKey);
//		hKey = NULL;
//	}
//
//
//	//��һ�ַ�ʽ д��ע���
//	ULONG tempstart = 1;
//
//	//��װ�õĺ���
//	//RtlWriteRegistryValue(RTL_REGISTRY_ABSOLUTE, pRegistryPath->Buffer, L"Start", REG_DWORD, &tempstart, 4);
//
//	//��ɾ������ ����ɾ������
//	//ZwDeleteKey(hKey);
//
//	//���ע����Ƿ����
//	//status = RtlCheckRegistryKey(RTL_REGISTRY_SERVICES, L"123456");
//
//	//if (NT_SUCCESS(status)) {
//	//	DbgPrint("Be Found\n");
//	//}
//	//else {
//	//	DbgPrint("Not Found\n");
//
//	//	RtlCreateRegistryKey(RTL_REGISTRY_SERVICES, L"123456");
//	//
//	//}
//
//	*/
//
//	//�ַ������
//	/*
//	PCHAR	tempbuffer = "C:\\ABc\\ccc\\bbb\\eee.txt";
//
//	STRING	str = { 0 };
//
//	RtlInitString(&str, tempbuffer);
//
//	//ת���ɿ��ַ�
//
//	RtlAnsiStringToUnicodeString(&DeviceName, &str, TRUE);
//
//
//	DbgPrint("--%wZ--\n", &DeviceName);
//
//	uTargetUnicode.Buffer = ExAllocatePool(NonPagedPool, 0x1000);
//	uTargetUnicode.MaximumLength = 0x1000;
//
//	RtlZeroMemory(uTargetUnicode.Buffer,0x1000);
//
//	RtlCopyUnicodeString(&uTargetUnicode, &DeviceName);
//
//	DbgPrint("--%wZ--\n", &uTargetUnicode);
//
//	//��Сд
//
//	RtlUpcaseUnicodeString(&DeviceName, &DeviceName, FALSE);
//	DbgPrint("--%wZ--\n", &DeviceName);
//
//	//�ͷ�֮ǰ����Ļ�����
//	RtlFreeUnicodeString(&DeviceName);
//	RtlFreeUnicodeString(&uTargetUnicode);
//
//	//
//	//��
//	//��ȫ�����ַ�
//
//	PWCHAR tempbuffer2 = ExAllocatePool(NonPagedPool, 0x1000);
//
//	RtlZeroMemory(tempbuffer2, 0x1000);
//
//	RtlStringCbCopyW(tempbuffer2, 0x1000, L"\\??\\");
//
//	//׷���ַ�
//
//	RtlStringCbCatW(tempbuffer2, 0x1000, L"C:\\ABc\\ccc\\bbb\\eee.txt");
//
//	//ǰ׺�ж�
//	UNICODE_STRING temp1 = { 0 }, temp2 = { 0 };
//
//	RtlInitUnicodeString(&temp1, tempbuffer2);
//
//	RtlInitUnicodeString(&temp2, L"\\??\\");
//
//	if (RtlPrefixUnicodeString(&temp2, &temp1, FALSE)) {
//		DbgPrint("Be Finded\n");
//	}
//	UNICODE_STRING temp3 = { 0 }, temp4 = { 0 };
//
//
//	RtlInitUnicodeString(&temp3, L"C:\\ABc\\ccc\\bbb\\eee.txt");
//
//	RtlInitUnicodeString(&temp4, L"C:\\ABc\\CCC\\bbb\\AVVeee123.txt");
//
//
//	if  (RtlEqualString(&temp3, &temp4, TRUE)) {
//		DbgPrint("temp3 = temp4 \n");
//	}
//
//	//�ַ�����
//	UNICODE_STRING temp5 = { 0 };
//	//һ��Ҫ��д
//	RtlInitUnicodeString(&temp5, L"*EEE*");//*EEE.TXT
//
//	if (FsRtlIsNameInExpression(&temp5, &temp4, TRUE, NULL)) {
//		DbgPrint("Searched\n");
//	}
//
//	DbgPrint("--%ws--\n", tempbuffer2);
//
//	*/
//
//	//�����豸���� 
//
//	status = IoCreateDevice(pDriverObject, 200/*DeviceExtensionSize �豸��չ��С*/, &DeviceName, 
//		FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevice);
//
//	if (!NT_SUCCESS(status)) {
//		DbgPrint("Create Device Failed :%x\n", status);
//
//		return status;
//	}
//
//	//����������д��ʽ
//
//	pDevice->Flags |= DO_BUFFERED_IO; // 0xc8 | 0x200 = 0x2c8
//
//	// �����豸�ɹ� ������������
//
//	UNICODE_STRING symname = { 0 };
//
//	RtlInitUnicodeString(&symname, SYM_NAME);
//
//	//IoDeleteSymbolicLink(&symname);
//	status = IoCreateSymbolicLink(&symname, &DeviceName);
//
//	if (status == STATUS_OBJECT_NAME_COLLISION) {
//		UNICODE_STRING symname = { 0 };
//		RtlInitUnicodeString(&symname, SYM_NAME);
//		IoDeleteSymbolicLink(&symname);
//		status = IoCreateSymbolicLink(&symname, &DeviceName);
//	}
//
//	if (!NT_SUCCESS(status)) {
//
//		DbgPrint("Create SymbolicLink Failed:%x\n", status);
//		IoDeleteDevice(pDevice);
//		return status;
//	}
//
//	//��ǲ����
//
//	pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;
//
//	//�ر� �������
//	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;
//
//	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyClean;
//
//	pDriverObject->MajorFunction[IRP_MJ_READ] = MyRead;
//
//	pDriverObject->MajorFunction[IRP_MJ_WRITE] = MyWrite;
//
//	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyControl;
//
//	////��ʼ��IO��ʱ��
//	//IoInitializeTimer(pDevice, TimeWorker, NULL);
//	//IoInitializeTimer(pDevice, TimeWorker, NULL);
//
//	////����IO��ʱ��
//	//IoStartTimer(pDevice);
//
//	//DPC��ʱ��
//	/*
//
//	KeInitializeTimer(&kerneltimer);
//
//	//��ʼ��DPC
//	KeInitializeDpc(&dpcobj, DpcRoutine, NULL);
//
//	//����dpc���к� �����ִ��
//	LARGE_INTEGER dpctime = { 0 };
//	LARGE_INTEGER timeout = { 0 };
//
//	dpctime.QuadPart = -10 * 1000 * 1000 * 4;
//	timeout.QuadPart = -10 * 1000 * 1000 * 2;
//
//	//����timer
//	//KeSetTimer(&kerneltimer, dpctime, &dpcobj);
//	KeSetTimer(&kerneltimer, dpctime, NULL);
//
//	status = KeWaitForSingleObject(&kerneltimer,Executive,KernelMode,FALSE,&timeout);
//
//
//	if (status == STATUS_TIMEOUT) {
//		DbgPrint("Time out\n");
//	}
//
//	DbgPrint("Dpc Timer has worked\n");
//		*/
//
//	//��ʼ����������
//	//ExInitializeWorkItem(&workobj, WorkItemRoutine, NULL);
//
//	KEVENT workevent = { 0 };
//	//__debugbreak();
//	KeInitializeEvent(&workevent, NotificationEvent, FALSE);
//
//	ExInitializeWorkItem(&workobj, WorkItemRoutine2, &workevent);
//
//	//���빤������
//	//ExQueueWorkItem(&workobj, CriticalWorkQueue);
//	ExQueueWorkItem(&workobj, DelayedWorkQueue);
//
//	KeWaitForSingleObject(&workevent, Executive, KernelMode, FALSE, NULL);
//
//	DbgPrint("WorkItem has be worked!\n");
//
//	//KernelDeleteFile(L"\\??\\C:\\123.exe");
//
//	//KernelSmallCopyFile(L"\\??\\C:\\789.exe", L"\\??\\C:\\567.exe");
//
//	//����ʶ���ķ����ڴ�
//
//	/*
//	PVOID tempbuffer = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'xxaa');
//
//	if (tempbuffer) {
//		//�ڴ�����
//		RtlZeroMemory(tempbuffer, 0x1000);
//		//�ڴ����
//		RtlFillMemory(tempbuffer, 0x1000, 0xcc);
//		//�ͷ�
//		ExFreePoolWithTag(tempbuffer, 'xxaa');
//
//		//�ڴ��Ƿ����
//		//RtlCompareMemory()
//
//		//�ڴ��Ƿ����
//		//RtlEqualMemory();
//	}
//
//	//�����ʼ�������Ϊ�Լ��ĵ�ַ
//	InitializeListHead(&listhead);
//
//	DbgPrint("--%p--%p--%p--\n", &listhead, listhead.Flink, listhead.Blink);
//
//	status = PsSetCreateProcessNotifyRoutine(ProcessNotifyFun, FALSE);
//
//	if (!NT_SUCCESS(status)) {
//		DbgPrint("PsSetCreateProcessNotifyRoutine Failed : %x\n", status);
//	}
//	else {
//		DbgPrint("PsSetCreateProcessNotifyRoutine Successed\n");
//	}
//	*/
//	return status;
//}

VOID FindProcessNotify() {
	UNICODE_STRING apiname = { 0 };

	PUCHAR	apiaddr = NULL;

	LONG offset = 0;

	PLONG64 PspCreateProcessNotifyRoutine = NULL;
	RtlInitUnicodeString(&apiname, L"PsSetCreateThreadNotifyRoutine");

	apiaddr = MmGetSystemRoutineAddress(&apiname);

	if (!apiaddr) {
		DbgPrint("Not Found\n");

		return;
	}
	//__debugbreak();
	DbgPrint("PsSetCreateThreadNotifyRoutine Addr :0x%llp\n", (PVOID)apiaddr);

	apiaddr = apiaddr + 6;

	offset = *(PULONG)(apiaddr + 1);
	// E8 65 00 00 00                                      call    PspSetCreateThreadNotifyRoutine
	apiaddr = apiaddr + offset + 5;

	//4C 8D 2D 9F 93 D4 FF   lea     r13, PspCreateProcessNotifyRoutine
	for (int i = 0; i < 1000; i++) {
		if (*(apiaddr + i) == 0x4c && *(apiaddr + i + 1) == 0x8D && *(apiaddr + i + 2) == 0x2D) {
			apiaddr = apiaddr + i;

			offset = *(PLONG)(apiaddr + 3);

			PspCreateProcessNotifyRoutine = apiaddr + offset + 7;

			break;
		}
	}

	DbgPrint("Routine Nums Addr ��%p\n", PspCreateProcessNotifyRoutine);
	//__debugbreak();

	PULONG64 reallyNotify = NULL;

	ULONG64 RoutineNotify = NULL;

	NTSTATUS status = STATUS_SUCCESS;

	for (int i = 0; i < 64; i++) {

		reallyNotify = (ULONG64)(PspCreateProcessNotifyRoutine) + i*8;

		if (*reallyNotify == 0)
			break;
		RoutineNotify = *(PULONG64)(*reallyNotify & 0xFFFFFFFFFFFFFFF8);

		DbgPrint("CreateProcess Routine Notify:0x%p\n", RoutineNotify);
		
		//ժ��
		if (MmIsAddressValid(*reallyNotify)) {
			DbgPrint("1\n");
			status = PsSetCreateProcessNotifyRoutine((PVOID)RoutineNotify,TRUE);

			if (NT_SUCCESS(status))
			{
				DbgPrint("Remove CreateProcess Notify :0x%p\n", RoutineNotify);
			}
		}
	}
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pReg) {
	NTSTATUS status = STATUS_SUCCESS;

	pDriverObject->DriverUnload = DrvierUnload;

	FindProcessNotify();

	return status;
}