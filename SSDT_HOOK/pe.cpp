#include"pe.h"

ULONG RvaToOffset(PIMAGE_NT_HEADERS	pNtHeader, ULONG FileSize, ULONG Rva) {
	//PE���ص��ڴ�� ͨ��SectionTable����չ��
	//����ֱ���ж�RVA����
	USHORT NumberOfSection = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSection = IMAGE_FIRST_SECTION(pNtHeader);

	for (int i = 0; i < NumberOfSection; i++) {
		if (pImageSection->VirtualAddress <= Rva) {
			//�ڴ���е�RVAֵ �ڴ���еĴ�С
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

//��ȡ��������ض�������ַ
ULONG	PE::GetExportOffset(PUCHAR	pFileData, ULONG FileSize, const char* ExportName) {
	//�ж�Dosͷ��
	PIMAGE_DOS_HEADER	pDosHeader = (PIMAGE_DOS_HEADER)pFileData;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DbgPrint("[-]	IMAGE_DOS_HEADER	Error\n");
		return PE_ERROR_VALUE;
	}

	//�ж�NTHeader
	PIMAGE_NT_HEADERS	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + pFileData);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		DbgPrint("[-]	IMAGE_NT_HEADERS	Error\n");
		return PE_ERROR_VALUE;
	}
	//��ȡ��������ļ�ƫ��
	PIMAGE_DATA_DIRECTORY	pDataDirectory = (PIMAGE_DATA_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory);
	ULONG	ExportStartRva = pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG	ExportSize = pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG	ExportOffset = RvaToOffset(pNtHeader, FileSize, ExportStartRva);
	if (ExportOffset == PE_ERROR_VALUE) {
		DbgPrint("[-]	GetExportTableOffset	Error\n");
		return PE_ERROR_VALUE;
	}

	//��ȡ������
	//��ȡ��������Ҫ����  NumberOfFunctions NumberOfNames AddressOfFunctions AddressOfNames AddressOfNameOrdinals
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pFileData + ExportOffset);
	ULONG NumberOfFunctions = pExportDirectory->NumberOfFunctions;
	ULONG NumberOfNames = pExportDirectory->NumberOfNames;
	//����������ַ��
	ULONG AddressOfFunctions = RvaToOffset(pNtHeader, FileSize, pExportDirectory->AddressOfFunctions);
	//�����������Ʊ�
	ULONG AddressOfNames = RvaToOffset(pNtHeader, FileSize, pExportDirectory->AddressOfNames);
	//����������ű�
	ULONG AddressOfNameOrdinals = RvaToOffset(pNtHeader, FileSize, pExportDirectory->AddressOfNameOrdinals);
	if (AddressOfFunctions == PE_ERROR_VALUE
		|| AddressOfNames == PE_ERROR_VALUE
		|| AddressOfNameOrdinals == PE_ERROR_VALUE) {
		DbgPrint("[-]	ReadExport	Error\n");
		return PE_ERROR_VALUE;
	}
	//��ַ����
	PULONG	pAddressOfFuncions = (PULONG)(pFileData + AddressOfFunctions);
	//����RVA����
	PULONG	pAddressOfName = (PULONG)(pFileData + AddressOfNames);
	//�������
	PUSHORT	pAddressOfNameOrdinals = (PUSHORT)(pFileData + AddressOfNameOrdinals);

	//�ڵ������в�ѯ����
	ULONG	CurrentFunctionOffset = PE_ERROR_VALUE;
	for (ULONG i = 0; i < NumberOfNames; i++) {
		//��ȡ��ǰ�ĺ�����ƫ�Ƶ�ַ
		ULONG	CurrentNameOffset = RvaToOffset(pNtHeader, FileSize, pAddressOfName[i]);
		if (CurrentNameOffset == PE_ERROR_VALUE)
			continue;

		const char* pCurrentName = (const char*)(pFileData + CurrentNameOffset);
		//�����ڲ�ת������
		//���㵱ǰ������RVA
		ULONG CurrentFunctionRva = pAddressOfFuncions[pAddressOfNameOrdinals[i]];
		if (CurrentFunctionRva >= ExportStartRva && CurrentFunctionRva < ExportStartRva + ExportSize)
			continue;
		//���ƱȽ�
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
