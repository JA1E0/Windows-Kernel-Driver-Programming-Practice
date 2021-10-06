#ifndef _NTDLL_H
#define _NTDLL_H

#include"_global.h"

//base on TitanHide https://github.com/mrexodia/TitanHide

class NTDLL
{
public:
	//读取ntdll,初始化
	static	NTSTATUS	Initialize();
	//释放内存
	static	void	Deinitialize();
	//根据名字获取序号
	static	INT	GetSSDTIndex(CONST CHAR* ExportName);

private:
	static PUCHAR pFileData;
	static ULONG FileSize;

};
#endif