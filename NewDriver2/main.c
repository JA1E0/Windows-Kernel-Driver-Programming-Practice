#include<ntifs.h>
#include<windef.h>

PCHAR PsGetProcessImageFileName(PEPROCESS epobj);

VOID MyCreateProcessRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
	//Create = TRUE 创建进程 FALSE 结束进程
	if (Create) {
		PEPROCESS	tempep = NULL;

		NTSTATUS	status = STATUS_SUCCESS;

		//根据ProcessId返回对应的EPROCESS结构指针
		status = PsLookupProcessByProcessId(ProcessId, &tempep);

		if (NT_SUCCESS(status)) {
			//减引用
			ObDereferenceObject(tempep);

			PCHAR imagename = PsGetProcessImageFileName(tempep);

			DbgPrint("[CreateProcess] ProcessName:<%wZ>, ProcessId:<0x%x>\n", imagename,ProcessId);
		}
	}
	return;
}

VOID MyCreateProcessRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {

	HANDLE hParentProcessId = NULL;

	HANDLE hParentThreadId = NULL;

	HANDLE hCurrnetThreadId = NULL;

	PEPROCESS tempep = NULL;

	NTSTATUS status = STATUS_SUCCESS;
	//获取当前的线程id
	hCurrnetThreadId = PsGetCurrentThreadId();

	if (CreateInfo == NULL) {
		status = PsLookupProcessByProcessId(ProcessId, &tempep);

		if (NT_SUCCESS(status)) {
			//减引用
			ObDereferenceObject(tempep);

			PCHAR imagename = PsGetProcessImageFileName(tempep);
			//进程结束
			DbgPrint("[CloseProcess] [%s], hCurrnetThreadId:[%d],ProcessID:[%d]\n", imagename, hCurrnetThreadId, ProcessId);
		}
		return;
	}
	//__debugbreak();
	hParentProcessId = CreateInfo->CreatingThreadId.UniqueProcess;
	hParentThreadId = CreateInfo->CreatingThreadId.UniqueThread;
	//子进程的线程ID，父进程的进程ID，父进程的创建子进程线程的ID，被创建的子进程的进程ID
	DbgPrint("[CreateProcess] ProcessName:<%wZ>, hCurrnetThreadId:<0x%x>,hParentProcessId:<%d>,hParentThreadId:<%d>,ProcessID:<%d>\n", CreateInfo->ImageFileName, hCurrnetThreadId, hParentProcessId, hParentThreadId, ProcessId);

	return;
}

VOID MyLoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
	//模块名 //加载模块的进程

	PEPROCESS tempep = NULL;

	NTSTATUS status = STATUS_SUCCESS;

	status = PsLookupProcessByProcessId(ProcessId, &tempep);

	PCHAR imagename = NULL;

	if (!NT_SUCCESS(status)) {
		return;
	}

	ObDereferenceObject(tempep);

	imagename = PsGetProcessImageFileName(tempep);

	if (ImageInfo->ExtendedInfoPresent)
	{
		PIMAGE_INFO_EX pInfo = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

		DbgPrint("[%s] Load Image [%wZ] ,FileObject [0x%x],Baseaddr: [0x%x], size is [0x%llx]\n", imagename, FullImageName, pInfo->FileObject, ImageInfo->ImageBase, ImageInfo->ImageSize);

		return;
	}

	DbgPrint("[%s] Load Image [%wZ] ,Baseaddr: [0x%x], size is [0x%llx]\n", imagename, FullImageName, ImageInfo->ImageBase, ImageInfo->ImageSize);

	return;
}

VOID MyCreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	NTSTATUS status;

	PEPROCESS tempep = NULL;

	status = PsLookupProcessByProcessId(ProcessId, &tempep);

	PCHAR imagefilename;

	if (NT_SUCCESS(status)) {
		ObDereferenceObject(tempep);

		imagefilename = PsGetProcessImageFileName(tempep);

		if (Create) {
			DbgPrint("[%s] Create Thread [%d]\n", imagefilename, ThreadId);
		}
		else {
			DbgPrint("[%s] Destory Thread [%d]\n", imagefilename, ThreadId);
		}

	}

	return;

}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {

	PsSetCreateProcessNotifyRoutine(MyCreateProcessRoutine, TRUE);

	//PsSetCreateProcessNotifyRoutineEx(MyCreateProcessRoutineEx, TRUE);

	//卸载
	PsRemoveLoadImageNotifyRoutine(MyLoadImageNotifyRoutine);

	PsRemoveCreateThreadNotifyRoutine(MyCreateThreadNotifyRoutine);

	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) {
	NTSTATUS status = STATUS_SUCCESS;

	pDriverObject->DriverUnload = DriverUnload;

	do
	{
		//进程通知
		status = PsSetCreateProcessNotifyRoutine(MyCreateProcessRoutine, FALSE);
		//https://blog.csdn.net/yymiaoxin2010/article/details/106640655
		//status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)MyCreateProcessRoutineEx, FALSE);

		if (!NT_SUCCESS(status)) {
			DbgPrint("PsSetCreateProcessNotifyRoutineEx Failed: %p\n", status);
			break;
		}

		status = PsSetLoadImageNotifyRoutine(MyLoadImageNotifyRoutine);

		if (!NT_SUCCESS(status)) {
			DbgPrint("PsSetCreateProcessNotifyRoutineEx Failed: %p\n", status);
			break;
		}

		status = PsSetCreateThreadNotifyRoutine(MyCreateThreadNotifyRoutine);
		if (!NT_SUCCESS(status)) {
			DbgPrint("PsSetCreateThreadNotifyRoutine Failed: %p\n", status);
			break;
		}
	} while (0);



	return status;
}