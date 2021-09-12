#include<ntifs.h>

typedef struct {
	LIST_ENTRY listentry;
	ULONG64 unknown;
	LARGE_INTEGER  cookie;
	ULONG64 context;
	ULONG64 function;
}CM_NOTIFY_ENTRY, * PCM_NOTIFY_ENTRY;


typedef struct {
	LIST_ENTRY listEntry;
	ULONG64 unkonw;
	ULONG64 objectHead;
	ULONG64 handle;
	ULONG64 prefunc;
	ULONG64 postfunc;
}OBJECTCALLBACK, * POBJECTCALLBACK;

VOID EnumRegisterCallback() {
	UNICODE_STRING apiname = { 0 };

	PUCHAR apiaddr = NULL;

	PLONG64 CallbackListHead = NULL;

	PCM_NOTIFY_ENTRY tempNotifyEntry = NULL;

	PCM_NOTIFY_ENTRY pNotifyEntry = NULL;

	LONG offset = 0;

	int i = 0;
	
	LARGE_INTEGER lNum[50] = { 0 };

	RtlInitUnicodeString(&apiname, L"CmUnRegisterCallback");

	apiaddr = MmGetSystemRoutineAddress(&apiname);

	if (!apiaddr) {
		DbgPrint("Not Found CmUnRegisterCallback\n");
		return;
	}

	DbgPrint("CmUnRegisterCallback addr %p\n", apiaddr);

	//0B8 48 8D 0D 06 D8 C3 FF                                lea     rcx, CallbackListHead

	for (int i = 0; i < 1000; i++) {
		if (*(apiaddr + i) == 0x48 && *(apiaddr + i + 1) == 0x8D && *(apiaddr + i + 2) == 0x0D) {
			apiaddr = apiaddr + i;

			offset = *(PLONG32)(apiaddr + 3);

			CallbackListHead = apiaddr + 7 + offset;


			break;
		}
	}
	DbgPrint("%p\n", CallbackListHead);

	pNotifyEntry = tempNotifyEntry = *CallbackListHead;
	do
	{
		if (MmIsAddressValid((PVOID)(tempNotifyEntry->function))) {

			DbgPrint("[CmRegCallBack] FuncAddr: %p,Cookie: %p\n", tempNotifyEntry->function, tempNotifyEntry->cookie.QuadPart);

			//º¯ÊýÐ¶ÔØ
			lNum[i] = tempNotifyEntry->cookie;

			i++;
		}

		tempNotifyEntry = tempNotifyEntry->listentry.Flink;

	} while (tempNotifyEntry->listentry.Flink != pNotifyEntry	);

	//__debugbreak();
	//º¯ÊýÐ¶ÔØ
	for (i = 0;i < 50;i++) {
		if (lNum[i].QuadPart == 0) {
			break;
		}
		CmUnRegisterCallback(lNum[i]);
	
	}
	return;
}

VOID EnumProcessCallBack() {
	POBJECTCALLBACK pObjectCallBack = NULL;

	POBJECTCALLBACK ptempobject = NULL;

	PULONG64 temp = NULL;

	PUCHAR pObject = NULL;

	int i = 0;

	ULONG64 ulNum[50] = { 0 };

	pObject = (PUCHAR)*PsProcessType;

	temp = (PULONG64)(pObject + 0x0c8);

	ptempobject = pObjectCallBack = (POBJECTCALLBACK)*temp;

	DbgPrint("%p\n", pObjectCallBack);

	do
	{
		DbgPrint("[ProcCallBack] handle: %p,PreFunc: %p, PostFunc: %p\n", ptempobject->handle,ptempobject->prefunc, ptempobject->postfunc);

		//Ð¶ÔØ
		ulNum[i] = ptempobject->handle;

		i++;

		ptempobject = ptempobject->listEntry.Flink;

	} while (pObjectCallBack != ptempobject->listEntry.Flink);

	//º¯ÊýÐ¶ÔØ
	for (i = 0;i < 50;i++) {
		if (ulNum[i]== 0) {
			break;
		}
		ObUnRegisterCallbacks((PVOID)ulNum[i]);
	}

	return;
}

VOID DriverUnLoad(PDRIVER_OBJECT pDriverObject) {
	DbgPrint("UnLoad\n");

	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) {
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("%wZ\n", pRegPath);

	EnumRegisterCallback();

	EnumProcessCallBack();

	pDriverObject->DriverUnload = DriverUnLoad;

	return status;
}