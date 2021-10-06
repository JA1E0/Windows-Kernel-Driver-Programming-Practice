#ifndef _GLOBAL_H
#define _GLOBAL_H


#ifdef __cplusplus
extern "C"
{
#endif
#include<ntifs.h>
#include<windef.h>
#include<ntintsafe.h>


#ifdef __cplusplus
}
#endif


//typedef struct _FUNCNAMENUM{
//	CHAR	name[64];
//	INT		num;
//	LONG	rva;
//}FuncNameNum, * PFuncNameNum;
//
//typedef struct _EXPORTFUNC {
//	FuncNameNum	funcaddr;
//	PLONG	addr;
//}ExportFunc, * PExportFunc;


VOID*	RtlAllocateMemory(BOOL InZeroMemory, SIZE_T InSize);
VOID	RtlFreeMemory(VOID* pInPointer);
#endif // !_GLOBAL_H
