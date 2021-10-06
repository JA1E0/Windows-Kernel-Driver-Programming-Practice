#pragma once
#include"undocumnted.h"

typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

static ZWQUERYSYSTEMINFORMATION ZwQSI = 0;

NTSTATUS NTAPI Undocumented::ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL) {
	return ZwQSI(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

BOOL Undocumented::UndocumentedInit() {
	if (!ZwQSI) {
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
		ZwQSI = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
		if (!ZwQSI)
			return FALSE;
	}
}

//Base	on TitanHide
//Based on: http://alter.org.ua/docs/nt_kernel/procaddr
PVOID	Undocumented::GetKernelBase(PULONG pImageSize) {
	typedef struct _SYSTEM_MODULE_ENTRY {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
	typedef struct _SYSTEM_MODULE_INFORMATION {
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;	
	NTSTATUS	status = STATUS_SUCCESS;
	ULONG	SystemInfoBuffersize = 0;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInfo = NULL;

	status = Undocumented::ZwQuerySystemInformation(SystemModuleInformation,
		&SystemInfoBuffersize,
		0,
		&SystemInfoBuffersize);
	if (!SystemInfoBuffersize) {
		DbgPrint("[-]	ZwQuerySystemInformation GetLength	Error\n");
		return NULL;
	}

	pSystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)RtlAllocateMemory(true, SystemInfoBuffersize * 2);
	if (!pSystemModuleInfo) {
		DbgPrint("[-]	RtlAllocateMemory SystemModuleInfo	Error\n");
		return NULL;
	}

	status = Undocumented::ZwQuerySystemInformation(SystemModuleInformation,
		pSystemModuleInfo,
		SystemInfoBuffersize * 2,
		&SystemInfoBuffersize);
	if (NT_SUCCESS(status)) {
		pModuleBase = pSystemModuleInfo->Module[0].ImageBase;
		if (pImageSize)
			*pImageSize = pSystemModuleInfo->Module[0].ImageSize;
	}
	else {
		DbgPrint("[-]	ZwQuerySystemInformation SystemModuleInfo	Error\n");
	}
	
	RtlFreeMemory(pSystemModuleInfo);

	return pModuleBase;
}
