#include"GetSSDT.h"
#include"ntdll.h"
#include"undocumnted.h"
#include"pe.h"

PVOID	SSDT::NtMoudleTextFind() {
	ULONG	KernelSize;
	ULONG_PTR	KernelBase = (ULONG_PTR)Undocumented::GetKernelBase(&KernelSize);
	if (KernelBase == 0 || KernelBase == 0)
		return NULL;

	//查找.text段
	PIMAGE_NT_HEADERS pNtHeader = RtlImageNtHeader((PVOID)KernelBase);
	PIMAGE_SECTION_HEADER	pSection = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER	pTextSetion = NULL;
	for (ULONG i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
		char SectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
		RtlCopyMemory(SectionName, pSection->Name, IMAGE_SIZEOF_SHORT_NAME);
		SectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
		//判断text段名
		if (strncmp(SectionName, ".text", sizeof(".text") - sizeof(char)) == 0) {
			pTextSetion = pSection;
		}
		pSection++;
	}
	
	return pTextSetion;
}

PSSDTStruct SSDT::SSDTFind() {
	static	PSSDTStruct pSSDT = NULL;
	ULONG	KernelSize;
	ULONG_PTR	KernelBase = (ULONG_PTR)Undocumented::GetKernelBase(&KernelSize);
	if (KernelBase == 0 || KernelBase == 0)
		return NULL;

	//获取nt模块text段地址
	PIMAGE_SECTION_HEADER	pTextSetion = (PIMAGE_SECTION_HEADER)NtMoudleTextFind();
	if (pTextSetion == NULL)
		return NULL;
	//.text:FFFFF8046BDCDE00                                         KiSystemServiceStart : ; DATA XREF : KiServiceInternal + 5A↑o
	//.text:FFFFF8046BDCDE00 190 48 89 A3 90 00 00 00                                mov[rbx + 90h], rsp; _KTHREAD.SystemCallNumber = rsp
	//.text:FFFFF8046BDCDE07 190 8B F8                                               mov     edi, eax
	//.text:FFFFF8046BDCDE09 190 C1 EF 07                                            shr     edi, 7; 除以128
	//.text:FFFFF8046BDCDE0C 190 83 E7 20 and edi, 20h; 计算偏移号
	//.text:FFFFF8046BDCDE0F 190 25 FF 0F 00 00 and eax, 0FFFh; GDI 系统调用（调用号 >= 0x1000
	//.text:FFFFF8046BDCDE14
	//.text:FFFFF8046BDCDE14                                         KiSystemServiceRepeat : ; CODE XREF : KiSystemCall64 + 8EE↓j
	//.text:FFFFF8046BDCDE14 190 4C 8D 15 65 9A 3B 00                                lea     r10, KeServiceDescriptorTable; #pragma pack()
	//.text:FFFFF8046BDCDE1B 190 4C 8D 1D 5E 1C 3A 00                                lea     r11, KeServiceDescriptorTableShadow
	//查找KiSystemServiceStart特征码
	const	unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
	const	ULONG	SignatureSize = sizeof(KiSystemServiceStartPattern);
	BOOL Found = FALSE;
	ULONG	i;
	for (i = 0; i < pTextSetion->Misc.VirtualSize - SignatureSize; i++) {
		if (RtlEqualMemory((PUCHAR)(KernelBase + pTextSetion->VirtualAddress + i), KiSystemServiceStartPattern, SignatureSize) == TRUE) {
			Found = TRUE;
			break;
		}
	}
	if (!Found)
		return NULL;

	//.text:FFFFF8046BDCDE14 190 4C 8D 15 65 9A 3B 00                                lea     r10, KeServiceDescriptorTable; #pragma pack()
	//获取KeServiceDescriptorTable的相对偏移值
	ULONG_PTR LeaR10 = KernelBase + pTextSetion->VirtualAddress + i + SignatureSize;
	LONG	SSDTOffset = 0;
	if ((*(PUCHAR)LeaR10 == 0x4c) &&
		(*(PUCHAR)(LeaR10 + 1) == 0x8D) &&
		(*(PUCHAR)(LeaR10 + 2) == 0x15)) {
		SSDTOffset = *(PLONG)(LeaR10 + 3);
	}
	if (SSDTOffset == 0)
		return NULL;

	pSSDT = (PSSDTStruct)(LeaR10 + SSDTOffset + 7);
#ifdef _DEBUG
	DbgPrint("[+]	SSDTAddress:	0x%p\n",pSSDT);
#endif // _DEBUG


	return pSSDT;
}

PShadowSSDTStruct	SSDT::ShadowSSDTFind() {
	PShadowSSDTStruct	pShadowSSDT = NULL;
	static	PSSDTStruct pSSDT = NULL;
	ULONG	KernelSize;
	ULONG_PTR	KernelBase = (ULONG_PTR)Undocumented::GetKernelBase(&KernelSize);
	if (KernelBase == 0 || KernelBase == 0)
		return NULL;

	//获取nt模块text段地址
	PIMAGE_SECTION_HEADER	pTextSetion = (PIMAGE_SECTION_HEADER)NtMoudleTextFind();
	if (pTextSetion == NULL)
		return NULL;
	//.text:FFFFF8046BDCDE00                                         KiSystemServiceStart : ; DATA XREF : KiServiceInternal + 5A↑o
	//.text:FFFFF8046BDCDE00 190 48 89 A3 90 00 00 00                                mov[rbx + 90h], rsp; _KTHREAD.SystemCallNumber = rsp
	//.text:FFFFF8046BDCDE07 190 8B F8                                               mov     edi, eax
	//.text:FFFFF8046BDCDE09 190 C1 EF 07                                            shr     edi, 7; 除以128
	//.text:FFFFF8046BDCDE0C 190 83 E7 20 and edi, 20h; 计算偏移号
	//.text:FFFFF8046BDCDE0F 190 25 FF 0F 00 00 and eax, 0FFFh; GDI 系统调用（调用号 >= 0x1000
	//.text:FFFFF8046BDCDE14
	//.text:FFFFF8046BDCDE14                                         KiSystemServiceRepeat : ; CODE XREF : KiSystemCall64 + 8EE↓j
	//.text:FFFFF8046BDCDE14 190 4C 8D 15 65 9A 3B 00                                lea     r10, KeServiceDescriptorTable; #pragma pack()
	//.text:FFFFF8046BDCDE1B 190 4C 8D 1D 5E 1C 3A 00                                lea     r11, KeServiceDescriptorTableShadow
	//查找KiSystemServiceStart特征码
	const	unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
	const	ULONG	SignatureSize = sizeof(KiSystemServiceStartPattern);
	BOOL Found = FALSE;
	ULONG	i;
	for (i = 0; i < pTextSetion->Misc.VirtualSize - SignatureSize; i++) {
		if (RtlEqualMemory((PUCHAR)(KernelBase + pTextSetion->VirtualAddress + i), KiSystemServiceStartPattern, SignatureSize) == TRUE) {
			Found = TRUE;
			break;
		}
	}
	if (!Found)
		return NULL;

	//.text:FFFFF8046BDCDE14 190 4C 8D 15 65 9A 3B 00                                lea     r10, KeServiceDescriptorTable; #pragma pack()
	//.text:FFFFF8046BDCDE1B 190 4C 8D 1D 5E 1C 3A 00                                lea     r11, KeServiceDescriptorTableShadow
	//获取KeServiceDescriptorTable的相对偏移值
	ULONG_PTR LeaR10 = KernelBase + pTextSetion->VirtualAddress + i + SignatureSize;
	LONG	SSDTOffset = 0;
	if ((*(PUCHAR)LeaR10 == 0x4c) &&
		(*(PUCHAR)(LeaR10 + 1) == 0x8D) &&
		(*(PUCHAR)(LeaR10 + 2) == 0x15)) {
		//直接定位到 KeServiceDescriptorTableShadow
		SSDTOffset = *(PLONG)(LeaR10 + 10);
	}
	if (SSDTOffset == 0)
		return NULL;

	pSSDT = (PSSDTStruct)(LeaR10 + SSDTOffset + 14);
	DbgPrint("[+]	sizeof(SSDTStruct)	:%d\n", sizeof(SSDTStruct));
	pShadowSSDT = (PShadowSSDTStruct)((ULONG_PTR)pSSDT + sizeof(SSDTStruct));
#ifdef _DEBUG
	DbgPrint("[+]	ShadowSSDTAddress:	0x%p\n", pShadowSSDT);
#endif // _DEBUG


	return pShadowSSDT;
}

ULONG_PTR SSDT::GetSSDTFunctionAddress(const char* apiname) {
	//获取SSDT序号
	INT FunctionSerialNumber = NTDLL::GetSSDTIndex(apiname);
	//获取地址
	ULONG_PTR pFunc = SSDT::GetSSDTFunctionAddress(FunctionSerialNumber);

	return pFunc;
}

ULONG_PTR SSDT::GetSSDTFunctionAddress(INT Num) {
	PSSDTStruct SSDT = SSDT::SSDTFind();
	if (SSDT == NULL) {
		DbgPrint("[-]	SSDTFind	Error\n");
		return NULL;
	}

	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	LONG SSDTOffset = SSDT->pServiceTable[Num];
	ULONGLONG	NumerOfService = SSDT->NumerOfService;
	if (Num > NumerOfService) {
		DbgPrint("[-]	SerialNumber Bigger	Error\n");
		return NULL;
	}

	ULONG_PTR	pFuncBase = (ULONG_PTR)(SSDTbase + (SSDTOffset >> 4));

	return pFuncBase;
}