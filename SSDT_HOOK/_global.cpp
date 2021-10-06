#include"_global.h"


VOID* RtlAllocateMemory(BOOL InZeroMemory, SIZE_T InSize) {
	PVOID pResult = ExAllocatePool(NonPagedPool, InSize);
	if (InZeroMemory && (pResult != NULL))
		RtlZeroMemory(pResult, InSize);
	return pResult;
}

VOID	RtlFreeMemory(VOID* pInPointer) {
	ExFreePool(pInPointer);
}