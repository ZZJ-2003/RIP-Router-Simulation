#include "stdafx.h"
#include "RIPRouterSimulator.h"
#include "RIPRouterSimulatorDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CRouterApp theApp;

BEGIN_MESSAGE_MAP(CRouterApp, CWinApp)
END_MESSAGE_MAP()

CRouterApp::CRouterApp()
{
}

BOOL CRouterApp::InitInstance()
{
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return FALSE;
	}

	AfxEnableControlContainer();

	CRouterDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
	}
	else if (nResponse == IDCANCEL)
	{
	}

	return FALSE;
}
