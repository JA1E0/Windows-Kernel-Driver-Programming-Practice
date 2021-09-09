#include<ntifs.h>
#include<windef.h>

#define LDRP_VALID_SECTION 0x20
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  

PCHAR PsGetProcessImageFileName(PEPROCESS epobj);

//����ȡ��
LARGE_INTEGER g_cookie = { 0 };
BOOLEAN g_bSuccRegister = FALSE;
HANDLE ProcessCallBackHandle = NULL;
HANDLE ThreadCallBackHandle = NULL;

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	PVOID GpValue;
	PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused;
	PVOID SectionPointer;
	ULONG CheckSum;
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

//��һ������ ���ݵĲ���
//�ڶ������� ע�������
//���������� REG_XXXX_INFORMATION �ṹ��
NTSTATUS RregistryCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	NTSTATUS status = STATUS_SUCCESS;

	switch ((REG_NOTIFY_CLASS)Argument1)
	{
	case RegNtPreOpenKey:
	case RegNtPreOpenKeyEx:
	case RegNtPreCreateKey:
	case RegNtPreCreateKeyEx:
	{
		//DbgPrint("Create Key or Open Key\n");

		PREG_CREATE_KEY_INFORMATION	pkeyinfo = (PREG_CREATE_KEY_INFORMATION)Argument2;

		UNICODE_STRING tempservice = { 0 };

		//RtlInitUnicodeString(&tempservice, L"*AAABBB123B");
		//���˷���ע��
		//key info [SYSTEM\ControlSet001\Services\666666]
		RtlInitUnicodeString(&tempservice, L"SYSTEM\\CONTROLSET001\\SERVICES\\*");

		__try
		{
			//��ӡע���·��
			//DbgPrint("key info [%wZ]\n", pkeyinfo->CompleteName);

			if (FsRtlIsNameInExpression(&tempservice, pkeyinfo->CompleteName, TRUE, NULL)) {
				DbgPrint("Bad Create\n");

				//ͨ��ƥ���ַ�����ע��������
				status = STATUS_ACCESS_DENIED;
			}
		}
		__except (1)
		{
			DbgPrint("Bad Memory\n");
		}
		break;
	}
	default:
		break;
	}
	return status;
}

OB_PREOP_CALLBACK_STATUS   PreOperation_Process(PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation) {
	//�������ǽ��̶���

	OB_PREOP_CALLBACK_STATUS status = OB_PREOP_SUCCESS;

	PUCHAR imagefilename = PsGetProcessImageFileName(OperationInformation->Object);

	DbgPrint("Process Name : [%s]\n", imagefilename);

	//��������calc�Ľ��̡�
	if (strstr(imagefilename, "calc")) {
		//__debugbreak();
		//https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
	}

	return  status;
}

OB_PREOP_CALLBACK_STATUS PreOperation_Thread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	OB_PREOP_CALLBACK_STATUS status = OB_PREOP_SUCCESS;

	PETHREAD pthread = OperationInformation->Object;

	HANDLE ThreadId = PsGetThreadId(pthread);

	PEPROCESS peprocess = PsGetThreadProcess(pthread);

	PUCHAR imagefilename = PsGetProcessImageFileName(peprocess);

	DbgPrint("Process Name : [%s] CreateThread [%d] \n", imagefilename, ThreadId);

	if (strstr(imagefilename, "calc")) {
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
			if ((OperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD){
				DbgPrint("Calc Create Thread Failed\n");

				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;

				status = STATUS_UNSUCCESSFUL;
			}
		}
	}

	return status;
}

NTSTATUS RegProcessCallBack(PDRIVER_OBJECT pDriverObject) {

	NTSTATUS status = STATUS_SUCCESS;
	//���̶���ص�
//https://revers.engineering/superseding-driver-altitude-checks-on
	PKLDR_DATA_TABLE_ENTRY pLdr = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;

	pLdr->Flags |= LDRP_VALID_SECTION;

	OB_CALLBACK_REGISTRATION ob = { 0 };

	OB_OPERATION_REGISTRATION oor = { 0 };

	//�߶�,˭ע��ĸ���֪ͨ˭,�߶Ⱥ��ʾ���
	UNICODE_STRING attde = { 0 };
	//ע��ص��汾
	ob.Version = ObGetFilterVersion();
	//OperationRegistration������
	ob.OperationRegistrationCount = 1;
	//����ָ��
	ob.OperationRegistration = &oor;
	//�߶�
	RtlInitUnicodeString(&attde, L"321999");
	ob.Altitude = attde;
	//����
	ob.RegistrationContext = NULL;

	//ָ�򴥷��ص����̵Ķ������͵�ָ��
	oor.ObjectType = PsProcessType;
	//��־λ
	//�򿪣����ƾ��
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//ǰ��������
	oor.PreOperation = PreOperation_Process;
	//���������
	oor.PostOperation = NULL;

	status = ObRegisterCallbacks(&ob, &ProcessCallBackHandle);

	return status;
}

NTSTATUS RegThreadCallBack(PDRIVER_OBJECT pDriverObject) {
	NTSTATUS status = STATUS_SUCCESS;

	PKLDR_DATA_TABLE_ENTRY pLdr = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;

	pLdr->Flags |= LDRP_VALID_SECTION;

	OB_CALLBACK_REGISTRATION ob = { 0 };

	OB_OPERATION_REGISTRATION oor = { 0 };

	UNICODE_STRING altitude = { 0 };

	RtlInitUnicodeString(&altitude, L"319999");

	ob.Version = ObGetFilterVersion();

	ob.OperationRegistrationCount = 1;

	ob.RegistrationContext = NULL;

	ob.Altitude = altitude;

	ob.OperationRegistration = &oor;

	oor.ObjectType = PsThreadType;

	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	oor.PreOperation = PreOperation_Thread;

	oor.PostOperation = NULL;

	ObRegisterCallbacks(&ob, &ThreadCallBackHandle);

	return status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {

	if (g_bSuccRegister) {
		CmUnRegisterCallback(g_cookie);
	}

	//ObUnRegisterCallbacks(ProcessCallBackHandle);

	ObUnRegisterCallbacks(ThreadCallBackHandle);

	DbgPrint("UnLoad\n");
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) {
	NTSTATUS status = STATUS_SUCCESS;

	pDriverObject->DriverUnload = DriverUnload;
	//\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\CallBack
	DbgPrint("%wZ\n", pRegPath);

	do
	{
		//ע���ص�
		status = CmRegisterCallback(RregistryCallback, (PVOID)0x123445, &g_cookie);
		if (!NT_SUCCESS(status))
			break;
		g_bSuccRegister = TRUE;


		//���̻ص�
		//status = RegProcessCallBack(pDriverObject);
		//if (!NT_SUCCESS(status))
		//	break;
		//�̻߳ص�
		status = RegThreadCallBack(pDriverObject);
		if (!NT_SUCCESS(status))
			break;

	} while (FALSE);

	//DbgPrint("Status : [%p]\n", status);
	return status;
}