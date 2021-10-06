#pragma once
#include"_global.h"

//Base on TitanHide https://github.com/mrexodia/TitanHide
//SSDT struct
typedef struct _SSDTSTRUCT {
	//Long���ȿɱ� ��64bit 8�ֽڣ�32bit 4�ֽ�
	PLONG	pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG	NumerOfService;
#endif // _WIN64
	PCHAR	pArgumentTable;
}SSDTStruct,*PSSDTStruct;

typedef struct _SHADOWSSDTSTRUCT {
	//Long���ȿɱ� ��64bit 8�ֽڣ�32bit 4�ֽ�
	PLONG	pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG	NumerOfService;
#endif // _WIN64
	PCHAR	pArgumentTable;
}ShadowSSDTStruct, *PShadowSSDTStruct;

class SSDT 
{
public:
	//����ntģ��text�ε�ַ
	static	PVOID	NtMoudleTextFind();
	//SSDT��ַ��ȡ
	static PSSDTStruct	SSDTFind();
	//ShadowSSDT��ַ��ȡ
	static PShadowSSDTStruct	ShadowSSDTFind();
	//����api���ֻ�ȡ��ַ
	static ULONG_PTR GetSSDTFunctionAddress(const char* apiname);
	//����api���ֻ�ȡ��ַ
	static ULONG_PTR GetSSDTFunctionAddress(INT Num);
	//����SSDT
	

};



