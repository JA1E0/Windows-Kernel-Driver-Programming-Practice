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

typedef NTSTATUS (*pNtOpenProcess)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

PVOID pOldCode = NULL;

PULONG64 ReturnCode = NULL;

PVOID pApiAddr = NULL;

NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

KIRQL	UpIRQL();

VOID	DownIRQL(KIRQL OldIrql);

VOID	RestoreCode();

VOID	DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	DbgPrint("UnLoad\n");
	//�ָ�����
	RestoreCode();
	//�ͷŴ������ڴ�
	ExFreePool(pOldCode, 0x100);

	return;
}

NTSTATUS	DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = STATUS_SUCCESS;

	CHAR JmpCode[12] = { 0x48,0xB8,0x22,0x22,0x22,0x22,0x11,0x11,0x11,0x11,0xFF,0xE0 };

	CHAR SpringBoard[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};

	UNICODE_STRING puApiName = { 0 };
	
	KIRQL OldIrql = 0;

	RtlInitUnicodeString(&puApiName, L"NtOpenProcess");
	//��ȡ������ַ
	pApiAddr = MmGetSystemRoutineAddress(&puApiName);

	if (pApiAddr == NULL) {
		return STATUS_NOT_FOUND;
	}

	//����shellcode
	*((PULONG64)(JmpCode+2)) = (PULONG64)MyNtOpenProcess;
	
	*((PULONG64)(SpringBoard + 6)) = (ULONG64)pApiAddr + 13;

	pOldCode = ExAllocatePool(NonPagedPool, 0x100);

	if (!pOldCode) {
		DbgPrint("ExAllocatePool Failed!\n");
	}
	//���о����ݱ���
	RtlZeroMemory(pOldCode, 0x100);

	RtlCopyMemory(pOldCode, pApiAddr, 12);

	//�������幹��
	RtlCopyMemory((PVOID)((ULONG64)pOldCode + 13), SpringBoard, sizeof(SpringBoard));
	
	//�����ж�Ȩ��
	OldIrql = UpIRQL();
	//Hook
	RtlCopyMemory(pApiAddr, JmpCode, sizeof(JmpCode));

	//�����ж�Ȩ��
	DownIRQL(OldIrql);

	return status;
}

NTSTATUS MyNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	if (ClientId->UniqueProcess == 2222) {
		return STATUS_ACCESS_DENIED;
	}
	//DbgPrint("OpenProcess Pid:%d\n", ClientId->UniqueProcess);

	pNtOpenProcess pFunc = pOldCode;

	return pFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//�����ж�Ȩ�ޣ���ֹ�����
//�ر�д���� ����Cr0��־λ
//���ж� ��ǰִ�в����ж�
KIRQL UpIRQL()
{
	KIRQL OldIrql = KeRaiseIrqlToDpcLevel();

	UINT64 cr0 = __readcr0();

	cr0 &= 0xfffffffffffeffff;

	__writecr0(cr0);

	_disable();

	return OldIrql;
}
//�ָ��ж϶���
//��д����
//���ж�
VOID DownIRQL(KIRQL OldIrql)
{
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