/*
#include<ntifs.h>


//Windows7 sp1

//PAGE:00000001403532EC                                         ; NTSTATUS __stdcall NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
//PAGE:00000001403532EC                                         public NtOpenProcess
//PAGE : 00000001403532EC                                         NtOpenProcess proc near
//PAGE : 00000001403532EC
//PAGE : 00000001403532EC                                         var_18 = byte ptr - 18h
//PAGE : 00000001403532EC                                         PreviousMode = byte ptr - 10h
//PAGE : 00000001403532EC
//PAGE : 00000001403532EC 000 48 83 EC 38                         sub     rsp, 38h
//PAGE : 00000001403532F0 038 65 48 8B 04 25 88 01 00 00          mov     rax, gs:188h
//PAGE : 00000001403532F9 038 44 8A 90 F6 01 00 00                mov     r10b, [rax + 1F6h]
//PAGE:0000000140353300 038 44 88 54 24 28                      mov[rsp + 38h + PreviousMode], r10b; PreviousMode
//PAGE : 0000000140353305 038 44 88 54 24 20                      mov[rsp + 38h + var_18], r10b; char
//PAGE : 000000014035330A 038 E8 51 FC FF FF                      call    PsOpenProcess
//PAGE : 000000014035330F 038 48 83 C4 38                         add     rsp, 38h
//PAGE : 0000000140353313 000 C3                                  retn

//00007FF9959406C0 | 48:B8 2222222211111111                 | mov rax,1111111122222222                                    |
//00007FF9959406CA | FFE0 | jmp rax |

//00007FF95BB10935 | FF25 00000000 | jmp qword ptr ds : [7FF95BB1093B] |
//00007FF95BB1093B | 1111 | adc dword ptr ds : [rcx] , edx |
//00007FF95BB1093D | 1111 | adc dword ptr ds : [rcx] , edx |
//00007FF95BB1093F | 1111 | adc dword ptr ds : [rcx] , edx |
//00007FF95BB10941 | 1111 | adc dword ptr ds : [rcx] , edx |


//nt!KiSystemServiceRepeat:
//fffff800`03e98772 4c8d15c7202300  lea     r10, [nt!KeServiceDescriptorTable(fffff800`040ca840)]
//fffff800`03e98779 4c8d1d00212300  lea     r11, [nt!KeServiceDescriptorTableShadow(fffff800`040ca880)]
//fffff800`03e98780 f7830001000080000000 test dword ptr[rbx + 100h], 80h
//fffff800`03e9878a 4d0f45d3        cmovne  r10, r11

typedef NTSTATUS(*pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	PULONG_PTR ServiceTableBase;	//SSDT基址
	PVOID ServiceCounterTableBase;	//SSDT中服务被调用次数计数器
	ULONG NumberOfService;	//SSDT服务个数
	PUCHAR ParamTableBase;
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

PVOID pOldCode = NULL;

PULONG64 ReturnCode = NULL;

PVOID pApiAddr = NULL;

BOOLEAN g_HookFlag = FALSE;

KIRQL	UpIRQL();

VOID	DownIRQL(KIRQL OldIrql);

NTSTATUS	HookNtOpen();

VOID	RestoreCode();

NTSTATUS GetSSDTFunc();

NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

VOID	DriverUnload(PDRIVER_OBJECT pDriverObject) {
	DbgPrint("UnLoad\n");

	if (g_HookFlag) {
		//恢复钩子
		RestoreCode();
		//释放创建的内存
		ExFreePool(pOldCode, 0x100);
	}

	return;
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) {
	pDriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = STATUS_SUCCESS;

	//status = HookNtOpen();

	////Hook NtOpenProcess
	//if (NT_SUCCESS(status)) {
	//	g_HookFlag = TRUE;
	//}

	//获取SSDT
	//status = GetSSDTFunc();


	return status;
}

NTSTATUS HookNtOpen() {
	NTSTATUS status = STATUS_SUCCESS;

	CHAR JmpCode[12] = { 0x48,0xB8,0x22,0x22,0x22,0x22,0x11,0x11,0x11,0x11,0xFF,0xE0 };

	CHAR SpringBoard[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11 };

	UNICODE_STRING puApiName = { 0 };

	KIRQL OldIrql = 0;

	RtlInitUnicodeString(&puApiName, L"NtOpenProcess");
	//获取函数地址
	pApiAddr = MmGetSystemRoutineAddress(&puApiName);

	if (pApiAddr == NULL) {
		return STATUS_NOT_FOUND;
	}

	//构建shellcode
	*((PULONG64)(JmpCode + 2)) = (PULONG64)MyNtOpenProcess;

	*((PULONG64)(SpringBoard + 6)) = (ULONG64)pApiAddr + 13;

	pOldCode = ExAllocatePool(NonPagedPool, 0x100);

	if (!pOldCode) {
		DbgPrint("ExAllocatePool Failed!\n");
	}
	//进行旧数据保存
	RtlZeroMemory(pOldCode, 0x100);

	RtlCopyMemory(pOldCode, pApiAddr, 12);

	//辅助跳板构建
	RtlCopyMemory((PVOID)((ULONG64)pOldCode + 13), SpringBoard, sizeof(SpringBoard));

	//提升中断权限
	OldIrql = UpIRQL();
	//Hook
	RtlCopyMemory(pApiAddr, JmpCode, sizeof(JmpCode));

	//降低中断权限
	DownIRQL(OldIrql);

	return status;
}

NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
	if (ClientId->UniqueProcess == 3624) {
		return STATUS_ACCESS_DENIED;
	}

	//DbgPrint("OpenProcess Pid:%d\n", ClientId->UniqueProcess);

	pNtOpenProcess pFunc = pOldCode;

	return pFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//提升中断权限，防止被打断
//关闭写保护 操作Cr0标志位
//关中断 当前执行不被中断
KIRQL UpIRQL() {
	KIRQL OldIrql = KeRaiseIrqlToDpcLevel();

	UINT64 cr0 = __readcr0();

	cr0 &= 0xfffffffffffeffff;

	__writecr0(cr0);

	_disable();

	return OldIrql;
}

//恢复中断短线
//打开写保护
//开中断
VOID DownIRQL(KIRQL OldIrql) {
	KeLowerIrql(OldIrql);

	UINT64 cr0 = __readcr0();

	cr0 |= 0x10000;

	__writecr0(cr0);

	_enable();

	return;
}

VOID	RestoreCode() {

	KIRQL OldIrql = UpIRQL();

	RtlCopyMemory(pApiAddr, pOldCode, 12);

	DownIRQL(OldIrql);
	return;
}

NTSTATUS GetSSDTFunc() {
	NTSTATUS	status = STATUS_SUCCESS;
	PUCHAR	pSystemCall = 0;
	ULONG	uCodeOffset = 0;
	ULONG	uFuncOffset = 0;
	PULONG	uFuncNum = 0;
	DWORD dwNum = 2;
	PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable = NULL;
	PULONG_PTR pBaseAddr = NULL;
	ULONG64 pFuncAddr = NULL;


	pSystemCall = (PUCHAR)__readmsr(0xC0000082);

	//.text:FFFFF80003E98772                                         KiSystemServiceRepeat:                  ; CODE XREF: KiSystemCall64+47B↓j
	//.text:FFFFF80003E98772 000 4C 8D 15 C7 20 23 00                lea     r10, KeServiceDescriptorTable
	for (int i = 0; i < 1000; i++) {
		if (*(pSystemCall + i) == 0x4c && *(pSystemCall + i + 1) == 0x8D && *(pSystemCall + i + 2) == 0x15) {
			pSystemCall += i;
			uCodeOffset = *((PULONG32)(pSystemCall + 3));
			KeServiceDescriptorTable = (PKSERVICE_TABLE_DESCRIPTOR)((ULONG64)pSystemCall + 7 + uCodeOffset);

			break;
		}
	}

	pBaseAddr = KeServiceDescriptorTable->ServiceTableBase;
	uFuncNum = (PULONG)pBaseAddr;
	uFuncOffset = uFuncNum[dwNum] >> 4;
	pFuncAddr = (ULONG64)pBaseAddr + uFuncOffset;

	DbgPrint("Function Address: %p\n", pFuncAddr);

	return status;
}
*/

#include"ntdll.h"
#include"GetSSDT.h"
#include"undocumnted.h"

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject) {
	//释放加载的DLL
	NTDLL::Deinitialize();
	return;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvierObject, PUNICODE_STRING pRegPath) {
	NTSTATUS status = STATUS_SUCCESS;
	BOOL	Flag = FALSE;

	pDrvierObject->DriverUnload = DriverUnload;

	status = NTDLL::Initialize();
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-]	NTDLL::Init Failed	Error:%d\n", status);
		return status;
	}
	Flag = Undocumented::UndocumentedInit();
	if (!Flag) {
		DbgPrint("[-]	Undocumented::UndocumentedInit Failed	Error:%d\n", status);
		return STATUS_UNSUCCESSFUL;
	}

	CHAR name[] = "NtOpenThread";
	int Num = NTDLL::GetSSDTIndex(name);
	if (Num == -1) {
		DbgPrint("[-]	NTDLL::GetSSDTIndex Failed	Error\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("[+]	%d	\n", Num);
	ULONG_PTR pFunc = SSDT::GetSSDTFunctionAddress(name);
	if (pFunc == NULL) {
		DbgPrint("[-]	SDT::GetFunctionAddress(name)	Error\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[+]	%s	Address:%p\n", name, pFunc);

	PShadowSSDTStruct pShadowSSDT= SSDT::ShadowSSDTFind();
	if (pShadowSSDT == NULL) {
		DbgPrint("[-]	ShadowSSDTFind	Error\n");
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

