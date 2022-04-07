#include "stdafx.h"
#include "Sniffer.h"
#include "Sniffer_1.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CSnifferApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()

CSnifferApp::CSnifferApp() {
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;
}


CSnifferApp theApp;

BOOL CSnifferApp::InitInstance() {
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);
	CWinApp::InitInstance();

	skinppLoadSkin((CHAR*)"AlphaOS.ssk");

	AfxEnableControlContainer();


	CShellManager* pShellManager = new CShellManager;


	SetRegistryKey(_T("应用程序生成"));

	CSnifferDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK) {

	}
	else if (nResponse == IDCANCEL) {

	}

	if (pShellManager != NULL) {
		delete pShellManager;
	}

	return FALSE;
}