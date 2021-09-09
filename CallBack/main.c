#include<ntifs.h>
#include<windef.h>

#define LDRP_VALID_SECTION 0x20
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  

PCHAR PsGetProcessImageFileName(PEPROCESS epobj);

//用于取消
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

//第一个参数 传递的参数
//第二个参数 注册表类型
//第三个参数 REG_XXXX_INFORMATION 结构体
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
		//过滤服务注册
		//key info [SYSTEM\ControlSet001\Services\666666]
		RtlInitUnicodeString(&tempservice, L"SYSTEM\\CONTROLSET001\\SERVICES\\*");

		__try
		{
			//打印注册表路径
			//DbgPrint("key info [%wZ]\n", pkeyinfo->CompleteName);

			if (FsRtlIsNameInExpression(&tempservice, pkeyinfo->CompleteName, TRUE, NULL)) {
				DbgPrint("Bad Create\n");

				//通过匹配字符串，注册表的拦截
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
	//操作的是进程对象

	OB_PREOP_CALLBACK_STATUS status = OB_PREOP_SUCCESS;

	PUCHAR imagefilename = PsGetProcessImageFileName(OperationInformation->Object);

	DbgPrint("Process Name : [%s]\n", imagefilename);

	//保护带有calc的进程。
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
	//进程对象回调
//https://revers.engineering/superseding-driver-altitude-checks-on
	PKLDR_DATA_TABLE_ENTRY pLdr = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;

	pLdr->Flags |= LDRP_VALID_SECTION;

	OB_CALLBACK_REGISTRATION ob = { 0 };

	OB_OPERATION_REGISTRATION oor = { 0 };

	//高度,谁注册的高先通知谁,高度合适就行
	UNICODE_STRING attde = { 0 };
	//注册回调版本
	ob.Version = ObGetFilterVersion();
	//OperationRegistration的条数
	ob.OperationRegistrationCount = 1;
	//数组指针
	ob.OperationRegistration = &oor;
	//高度
	RtlInitUnicodeString(&attde, L"321999");
	ob.Altitude = attde;
	//参数
	ob.RegistrationContext = NULL;

	//指向触发回调例程的对象类型的指针
	oor.ObjectType = PsProcessType;
	//标志位
	//打开，复制句柄
	oor.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	//前操作例程
	oor.PreOperation = PreOperation_Process;
	//后操作例程
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
		//注册表回调
		status = CmRegisterCallback(RregistryCallback, (PVOID)0x123445, &g_cookie);
		if (!NT_SUCCESS(status))
			break;
		g_bSuccRegister = TRUE;


		//进程回调
		//status = RegProcessCallBack(pDriverObject);
		//if (!NT_SUCCESS(status))
		//	break;
		//线程回调
		status = RegThreadCallBack(pDriverObject);
		if (!NT_SUCCESS(status))
			break;

	} while (FALSE);

	//DbgPrint("Status : [%p]\n", status);
	return status;
}