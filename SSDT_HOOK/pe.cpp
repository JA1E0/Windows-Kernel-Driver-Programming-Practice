#include"pe.h"

ULONG RvaToOffset(PIMAGE_NT_HEADERS	pNtHeader, ULONG FileSize, ULONG Rva) {
	//PE加载到内存后 通过SectionTable进行展开
	//所以直接判断RVA就行
	USHORT NumberOfSection = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < NumberOfSection; i++) {
		if (pImageSection->VirtualAddress <= Rva) {
			//内存块中的RVA值 内存块中的大小
			if ((pImageSection->VirtualAddress + pImageSection->Misc.VirtualSize) > Rva) {
				Rva -= pImageSection->VirtualAddress;
				Rva += pImageSection->PointerToRawData;
				return Rva < FileSize ? Rva : PE_ERROR_VALUE;
			}
		}
		pImageSection++;
	}

	return PE_ERROR_VALUE;
}

//获取导出表的特定函数地址
ULONG	PE::GetExportOffset(PUCHAR	pFileData, ULONG FileSize, const char* ExportName) {
	//判断Dos头部
	PIMAGE_DOS_HEADER	pDosHeader = (PIMAGE_DOS_HEADER)pFileData;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DbgPrint("[-]	IMAGE_DOS_HEADER	Error\n");
		return PE_ERROR_VALUE;
	}

	//判断NTHeader
	PIMAGE_NT_HEADERS	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + pFileData);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		DbgPrint("[-]	IMAGE_NT_HEADERS	Error\n");
		return PE_ERROR_VALUE;
	}
	//获取导出表的文件偏移
	PIMAGE_DATA_DIRECTORY	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory);
	ULONG	ExportStartRva = pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG	ExportSize = pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG	ExportOffset = RvaToOffset(pNtHeader, FileSize, ExportStartRva);
	if (ExportOffset == PE_ERROR_VALUE) {
		DbgPrint("[-]	GetExportTableOffset	Error\n");
		return PE_ERROR_VALUE;
	}

	//读取导出表
	//获取导出表重要数据  NumberOfFunctions NumberOfNames AddressOfFunctions AddressOfNames AddressOfNameOrdinals
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pFileData + ExportOffset);
	ULONG NumberOfFunctions = pExportDirectory->NumberOfFunctions;
	ULONG NumberOfNames = pExportDirectory->NumberOfNames;
	//导出函数地址表
	ULONG AddressOfFunctions = RvaToOffset(pNtHeader, FileSize, pExportDirectory->AddressOfFunctions);
	//导出函数名称表
	ULONG AddressOfNames = RvaToOffset(pNtHeader, FileSize, pExportDirectory->AddressOfNames);
	//导出函数序号表
	ULONG AddressOfNameOrdinals = RvaToOffset(pNtHeader, FileSize, pExportDirectory->AddressOfNameOrdinals);
	if (AddressOfFunctions == PE_ERROR_VALUE
		|| AddressOfNames == PE_ERROR_VALUE
		|| AddressOfNameOrdinals == PE_ERROR_VALUE) {
		DbgPrint("[-]	ReadExport	Error\n");
		return PE_ERROR_VALUE;
	}
	//地址数组
	PULONG	pAddressOfFuncions = (PULONG)(pFileData + AddressOfFunctions);
	//名称RVA数组
	PULONG	pAddressOfName = (PULONG)(pFileData + AddressOfNames);
	//序号数组
	PUSHORT	pAddressOfNameOrdinals = (PUSHORT)(pFileData + AddressOfNameOrdinals);

	//在导出表中查询函数
	ULONG	CurrentFunctionOffset = PE_ERROR_VALUE;
	for (ULONG i = 0; i < NumberOfNames; i++) {
		//获取当前的函数名偏移地址
		ULONG	CurrentNameOffset = RvaToOffset(pNtHeader, FileSize, pAddressOfName[i]);
		if (CurrentNameOffset == PE_ERROR_VALUE)
			continue;

		const char* pCurrentName = (const char*)(pFileData + CurrentNameOffset);
		//忽略内部转发函数
		//计算当前函数的RVA
		ULONG CurrentFunctionRva = pAddressOfFuncions[pAddressOfNameOrdinals[i]];
		if (CurrentFunctionRva >= ExportStartRva && CurrentFunctionRva < ExportStartRva + ExportSize)
			continue;
		//名称比较
		if (!strcmp(pCurrentName, ExportName)) {
			CurrentFunctionOffset = RvaToOffset(pNtHeader, FileSize, CurrentFunctionRva);
			break;
		}
	}
	if (CurrentFunctionOffset == PE_ERROR_VALUE) {
		DbgPrint("[-]	FindExport	Error\n");
	}
	return CurrentFunctionOffset;
}
