#include"ntdll.h"
#include"pe.h"

PUCHAR NTDLL::pFileData = nullptr;
ULONG NTDLL::FileSize = 0;

INT NTDLL::GetSSDTIndex(CONST CHAR* ExportName) {
	INT SerialNumber = -1;
	
	//获取导出表的文件偏移地址
	ULONG_PTR ExportOffset = PE::GetExportOffset(pFileData, FileSize, ExportName);
	if (ExportOffset == PE_ERROR_VALUE) {
			DbgPrint("[-]	GetExportOffset	Error\n");
			return PE_ERROR_VALUE;
	}
	PUCHAR pFuntion = (PUCHAR)(pFileData + ExportOffset);
	//	.text:000000018009C510 000 4C 8B D1                            mov     r10, rcx; NtOpenProcess
	//	.text:000000018009C513 000 B8 26 00 00 00                      mov     eax, 26h; '&'

	for (int i = 0; i < 32 ; i++) {
		// ret xx  == C2 xxxx
		//ret == C3 
		//判断是否达到函数底部
		if (*(pFuntion + i) == 0xC2 || *(pFuntion + i) == 0xC2) 
			break;
		//  mov     eax,
		if (*(pFuntion + i) == 0xB8) {
			SerialNumber = *(PINT)(pFuntion + i + 1);
			break;
		}
	}

	if (SerialNumber == -1) {
		DbgPrint("[-]	GetSSDTINDEX	ERROR\n");
	}

	return SerialNumber;
}

NTSTATUS NTDLL::Initialize() {
	// \SystemRoot\System32\drivers\ntdll.dll
	NTSTATUS status = STATUS_SUCCESS;

	//打开ntdll并映射到内存空间中
	UNICODE_STRING	uFileName = { 0 };
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };

	RtlInitUnicodeString(&uFileName, L"\\SystemRoot\\System32\\ntdll.dll");
	InitializeObjectAttributes(&ObjectAttributes,
		&uFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);
	//校验权限，运行ZwCreateFile
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		DbgPrint("[-]	KeGetCurrentIrql() != PASSIVE_LEVEL)\n");
		return STATUS_UNSUCCESSFUL;
	}

	//打开文件
	status = ZwCreateFile(&hFile,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(status)) {
		//文件结构初始化
		FILE_STANDARD_INFORMATION StandardInformation = { 0 };
		LARGE_INTEGER ByteOffset = { 0 };

		//通过结构体查询数据
		status = ZwQueryInformationFile(hFile, &IoStatusBlock,
			&StandardInformation,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation);
		if (NT_SUCCESS(status)) {
			FileSize = StandardInformation.EndOfFile.LowPart;
#ifdef _DEBUG
			DbgPrint("[+]	Ntdll FileSize	0x%08X\n", FileSize);
#endif // _DEBUG
			//申请内存空间
			pFileData = (PUCHAR)RtlAllocateMemory(TRUE, FileSize);
#ifdef _DEBUG
			DbgPrint("[+]	pFileData	0x%p\n", pFileData);
#endif // _DEBUG
			status = ZwReadFile(hFile, NULL, NULL, NULL,
				&IoStatusBlock,
				pFileData,
				FileSize,
				&ByteOffset, NULL);
			if (!NT_SUCCESS(status)) {
				RtlFreeMemory(pFileData);
				DbgPrint("[-]	Read Ntdll Failed!Error: % d\n", status);
			}

		}
		else {
			DbgPrint("[-]	Query Ntdll Failed!	Error: %d\n", status);
			ZwClose(hFile);
		}
	}
	else {
		DbgPrint("[-]	Open Ntdll Failed!	Error: %d\n", status);
	}
	return status;
}
//释放内存
void NTDLL::Deinitialize() {
	if (pFileData != nullptr)
		ExFreePool(pFileData);
}