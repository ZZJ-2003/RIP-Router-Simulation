#pragma once
#ifndef __AFXWIN_H__
#error "�ڰ������ļ�֮ǰ���� 'stdafx.h' ������ PCH �ļ�"
#endif

#include "resource.h"

class CRouterApp : public CWinApp
{
public:
	CRouterApp();
	virtual BOOL InitInstance();
	DECLARE_MESSAGE_MAP()
};

extern CRouterApp theApp;