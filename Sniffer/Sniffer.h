#pragma once




#ifndef __AFXWIN_H__
#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"

class CSnifferApp :public CWinApp
{
public:
	CSnifferApp();

public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP();
};

extern CSnifferApp theApp;