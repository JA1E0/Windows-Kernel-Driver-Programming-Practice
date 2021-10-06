#ifndef _NTDLL_H
#define _NTDLL_H

#include"_global.h"

//base on TitanHide https://github.com/mrexodia/TitanHide

class NTDLL
{
public:
	//��ȡntdll,��ʼ��
	static	NTSTATUS	Initialize();
	//�ͷ��ڴ�
	static	void	Deinitialize();
	//�������ֻ�ȡ���
	static	INT	GetSSDTIndex(CONST CHAR* ExportName);

private:
	static PUCHAR pFileData;
	static ULONG FileSize;

};
#endif