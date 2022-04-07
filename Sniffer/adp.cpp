//实现网卡绑定
#include "stdafx.h"
#include "Sniffer.h"
#include "adp.h"
#include "afxdialogex.h"
#include "Sniffer_1.h"

IMPLEMENT_DYNAMIC(CAdpDlg, CDialogEx)

CAdpDlg::CAdpDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CAdpDlg::IDD, pParent)
{

}

CAdpDlg::~CAdpDlg()
{
}

void CAdpDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list1);
}


BEGIN_MESSAGE_MAP(CAdpDlg, CDialogEx)

	ON_NOTIFY(NM_CLICK, IDC_LIST1, &CAdpDlg::OnNMClickList1)
	ON_BN_CLICKED(IDOK, &CAdpDlg::OnBnClickedOk)
END_MESSAGE_MAP()

BOOL CAdpDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();

	m_list1.SetExtendedStyle(m_list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_list1.InsertColumn(0, _T("设备名"), LVCFMT_LEFT, 350);
	m_list1.InsertColumn(1, _T("设备描述"), LVCFMT_LEFT, 250);

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		return FALSE;

	for (d = alldevs; d; d = d->next) {
		m_list1.InsertItem(0, (CString)d->name);
		m_list1.SetItemText(0, 1, (CString)d->description);
	}
	d = NULL;
	return TRUE;
}

void CAdpDlg::OnNMClickList1(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

	NMLISTVIEW* pNMListView = (NMLISTVIEW*)pNMHDR;
	if (-1 != pNMListView->iItem) {
		adpname = m_list1.GetItemText(pNMListView->iItem, 0);
		SetDlgItemText(IDC_EDIT1, adpname);
	}

}

pcap_if_t* CAdpDlg::GetDevice() {
	if (adpname) {
		for (d = alldevs; d; d = d->next) {
			if (d->name == adpname)
				return d;
		}
	}
	return NULL;
}

void CAdpDlg::OnBnClickedOk() {
	d = GetDevice();
	if (d) {
		MessageBox(_T("绑定成功"));
		CDialogEx::OnOK();
	}
	else MessageBox(_T("请先绑定网卡"));
}

pcap_if_t* CAdpDlg::returnd() {
	return d;
}