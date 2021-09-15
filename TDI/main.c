#include<ntifs.h>
#include<windef.h>
#include<tdi.h>
#include<tdikrnl.h>

#define  HTONS(A) (((A&0xff00) >> 8) | ((A&0x00ff) << 8))
//Windows7
PDEVICE_OBJECT pfilterdevobj = NULL;

PDEVICE_OBJECT pdodevobj = NULL;

BOOLEAN g_attachTcp = FALSE;

NTSTATUS MyDispatch(DEVICE_OBJECT* DeviceObject, IRP* pIrp);
NTSTATUS NotSupport(DEVICE_OBJECT* DeviceObject, IRP* pIrp);

typedef struct _NETWORK_ADDRESS {
	UCHAR address[4];
	CHAR port[4];
}NETWORK_ADDRESS,*PNETWORK_ADDRESS;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject) {
	//__debugbreak();
	DbgPrint("UnLoad\n");

	if (g_attachTcp) {
		IoDetachDevice(pdodevobj);
	}
	if (pfilterdevobj != NULL) {
		IoDeleteDevice(pfilterdevobj);
	}
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath) {
	pDriverObject->DriverUnload = DriverUnload;

	NTSTATUS status = STATUS_SUCCESS;

	UNICODE_STRING devicename = { 0 };
	//__debugbreak();
	do {
		status = IoCreateDevice(pDriverObject, 0, NULL, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &pfilterdevobj);

		if (!NT_SUCCESS(status)) {
			DbgPrint("Error Create %x\n", status);
			break;
		}

		for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
			pDriverObject->MajorFunction[i] = NotSupport;
		}
		pDriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = MyDispatch;

		RtlInitUnicodeString(&devicename, L"\\Device\\Tcp");
		//__debugbreak();
		//第三个参数是下层设备的指针
		status = IoAttachDevice(pfilterdevobj, &devicename, &pdodevobj);

		if (!NT_SUCCESS(status)) {
			DbgPrint("Error Attach %x\n", status);

			IoDeleteDevice(pfilterdevobj);

			break;
		}
		g_attachTcp = TRUE;
	} while (FALSE);

	return status;

}
NTSTATUS NotSupport(DEVICE_OBJECT* pDeviceObject, IRP* pIrp) {
	//递增跳过，让下一层拿到当前的数据
	IoSkipCurrentIrpStackLocation(pIrp);
	//一定要使用AttachDevice后的下层驱动设备指针
	return IoCallDriver(pdodevobj, pIrp);
}

NTSTATUS MyDispatch(DEVICE_OBJECT* pDeviceObject, IRP* pIrp) {
	//DbgPrint("This Is Filter\n");
	PIO_STACK_LOCATION pIrpStack = NULL;
	//判断是否是当前的过滤设备
	if (pDeviceObject == pfilterdevobj) {
		pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

		if (pIrpStack == NULL) {
			return STATUS_UNSUCCESSFUL;
		}
		//MajorFunction 对应IRP_MJ_XXXX
		//MinorFunction 对应定义的其他请求

		if (pIrpStack->MinorFunction == TDI_CONNECT) {
			NETWORK_ADDRESS network = { 0 };

			PTDI_REQUEST_KERNEL_CONNECT param = (PTDI_REQUEST_KERNEL_CONNECT)(&pIrpStack->Parameters);

			PTA_ADDRESS remote_addr = ((TRANSPORT_ADDRESS*)(param->RequestConnectionInformation->RemoteAddress))->Address;

			PTDI_ADDRESS_IP tdi_addr = (PTDI_ADDRESS_IP)(remote_addr->Address);

			DWORD address = tdi_addr->in_addr;

			DWORD port = tdi_addr->sin_port;

			network.address[0] = ((PUCHAR)&address)[0];

			network.address[1] = ((PUCHAR)&address)[1];

			network.address[2] = ((PUCHAR)&address)[2];

			network.address[3] = ((PUCHAR)&address)[3];

			port = HTONS(port);

			DbgPrint("connect ip address [%d.%d.%d.%d:%d]\n", network.address[0],network.address[1],network.address[2],network.address[3],port);
		}
	}

	//递增跳过，让下一层拿到当前的数据
	IoSkipCurrentIrpStackLocation(pIrp);
	//一定要使用AttachDevice后的下层驱动设备指针
	return IoCallDriver(pdodevobj, pIrp);
}
