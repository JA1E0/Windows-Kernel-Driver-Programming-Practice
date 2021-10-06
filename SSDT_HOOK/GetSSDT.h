#pragma once
#include"_global.h"

//Base on TitanHide https://github.com/mrexodia/TitanHide
//SSDT struct
typedef struct _SSDTSTRUCT {
	//Long长度可变 ，64bit 8字节，32bit 4字节
	PLONG	pServiceTable;
	PVOID pCounterTable;
#ifdef _WIN64
	ULONGLONG	NumerOfService;
#endif // _WIN64
	PCHAR	pArgumentTable;
}SSDTStruct,*PSSDTStruct;

typedef struct _SHADOWSSDTSTRUCT {
	//Long长度可变 ，64bit 8字节，32bit 4字节
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
	//查找nt模块text段地址
	static	PVOID	NtMoudleTextFind();
	//SSDT地址获取
	static PSSDTStruct	SSDTFind();
	//ShadowSSDT地址获取
	static PShadowSSDTStruct	ShadowSSDTFind();
	//根据api名字获取地址
	static ULONG_PTR GetSSDTFunctionAddress(const char* apiname);
	//根据api名字获取地址
	static ULONG_PTR GetSSDTFunctionAddress(INT Num);
	//遍历SSDT
	

};



