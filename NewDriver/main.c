#include<ntddk.h>

void nothing(HANDLE hPpid, HANDLE hMypid, BOOLEAN bCreate) {
	DbgPrint("ProcessNotify\n");
}

void DrvierUnload(PDRIVER_OBJECT pDriverObject) {
	DbgPrint("Unload\n");
	PsSetCreateProcessNotifyRoutine(nothing, TRUE);
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	pDriverObject->DriverUnload = DrvierUnload;
	NTSTATUS NtStatus = STATUS_SUCCESS;

	DbgPrint("Kernel Load!\n");
	DbgPrint("---- %wZ -----\n",pRegistryPath);
	PsSetCreateProcessNotifyRoutine(nothing, FALSE);

	return NtStatus;
}