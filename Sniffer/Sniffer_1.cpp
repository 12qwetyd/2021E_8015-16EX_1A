#include "stdafx.h"
#include "Sniffer.h"
#include "Sniffer_1.h"
#include "afxdialogex.h"

#include "adp.h"
#include "filter.h"
#include "head.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

DWORD WINAPI CapturePacket(LPVOID lpParam);

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:

};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	//	ON_COMMAND(ID_HELP, &CAboutDlg::OnHelp)
END_MESSAGE_MAP()


// CSnifferDlg 对话框




CSnifferDlg::CSnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CSnifferDlg::IDD, pParent)
	, m_pDevice(NULL)
	, m_bFlag(false)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_tcpnum = _T("");
	m_udpnum = _T("");
	m_arpnum = _T("");
	m_icmpnum = _T("");
	m_igmpnum = _T("");
	m_totalnum = _T("");
	m_httpnum = _T("");
	m_dnsnum = _T("");
	//  m_qqnum = _T("");

	m_weixinnum = _T("");
	m_qqnum = _T("");
	m_VMnum = _T("");
	m_baiduNetnum = _T("");
	m_talknum = _T("");
	m_firfoxnum = _T("");


}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_list1);
	DDX_Control(pDX, IDC_TREE1, m_tree1);
	DDX_Control(pDX, IDC_EDIT1, m_edit1);
	DDX_Text(pDX, IDC_EDIT2, m_tcpnum);
	DDX_Text(pDX, IDC_EDIT3, m_udpnum);
	DDX_Text(pDX, IDC_EDIT4, m_arpnum);
	DDX_Text(pDX, IDC_EDIT5, m_icmpnum);
	DDX_Text(pDX, IDC_EDIT6, m_igmpnum);
	DDX_Text(pDX, IDC_EDIT7, m_totalnum);
	DDX_Text(pDX, IDC_EDIT8, m_httpnum);
	DDX_Text(pDX, IDC_EDIT9, m_dnsnum);
	//  DDX_Text(pDX, IDC_EDIT11, m_qqnum);



	DDX_Text(pDX, IDC_EDIT10, m_weixinnum);
	DDX_Text(pDX, IDC_EDIT11, m_qqnum);
	DDX_Text(pDX, IDC_EDIT12, m_VMnum);
	DDX_Text(pDX, IDC_EDIT13, m_baiduNetnum);
	DDX_Text(pDX, IDC_EDIT14, m_firfoxnum);
	DDX_Text(pDX, IDC_EDIT15, m_talknum);

}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_COMMAND(ID_ADP, &CSnifferDlg::OnAdp)
	ON_COMMAND(ID_HELP, &CSnifferDlg::OnHelp)
	ON_COMMAND(ID_FILTER, &CSnifferDlg::OnFilter)
	ON_COMMAND(ID_START, &CSnifferDlg::OnStart)
	ON_COMMAND(ID_STOP, &CSnifferDlg::OnStop)
	ON_COMMAND(ID_Read, &CSnifferDlg::OnRead)
	ON_COMMAND(ID_Save, &CSnifferDlg::OnSave)

	//	ON_NOTIFY(HDN_ITEMCHANGED, 0, &CSnifferDlg::OnHdnItemchangedList1)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferDlg::OnLvnItemchangedList1)
	ON_COMMAND(ID_EXIT, &CSnifferDlg::OnExit)
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序

BOOL CSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	m_pDevice = NULL;
	m_bFlag = false;

	//列表视图初始化
	m_list1.SetExtendedStyle(m_list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);// 为列表视图控件添加全行选中和栅格风格
	m_list1.InsertColumn(0, _T("序号"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(1, _T("时间"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(2, _T("源MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(3, _T("目的MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(4, _T("长度"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(5, _T("协议"), LVCFMT_CENTER, 70);
	m_list1.InsertColumn(6, _T("源IP地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(7, _T("目的IP地址"), LVCFMT_CENTER, 120);

	m_tcpCount = 0;
	m_udpCount = 0;
	m_arpCount = 0;
	m_icmpCount = 0;
	m_igmpCount = 0;
	m_totalCount = 0;
	m_httpCount = 0;
	m_dnsCount = 0;





	m_weixinCount = 0;
	m_qqCount = 0;
	m_VMCount = 0;
	m_baiduNetCount = 0;
	m_talkCount = 0;
	m_firfoxCount = 0;

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//显示选择适配器对话框
void CSnifferDlg::OnAdp()
{
	// TODO: 在此添加命令处理程序代码
	CAdpDlg adpdlg;
	if (adpdlg.DoModal() == IDOK)
	{
		m_pDevice = adpdlg.returnd();
	}
}

//显示关于对话框
void CSnifferDlg::OnHelp()
{
	// TODO: 在此添加命令处理程序代码
	CAboutDlg aboutdlg;
	aboutdlg.DoModal();
}


void CSnifferDlg::OnFilter()
{
	// TODO: 在此添加命令处理程序代码
	CFilterDlg filterdlg;
	if (filterdlg.DoModal() == IDOK)
	{
		int len = WideCharToMultiByte(CP_ACP, 0, filterdlg.GetFilterName(), -1, NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_ACP, 0, filterdlg.GetFilterName(), -1, m_filtername, len, NULL, NULL);

	}
}

void CSnifferDlg::OnStart()
{
	// TODO: 在此添加命令处理程序代码
	if (m_pDevice == NULL)
	{
		AfxMessageBox(_T("请选择要绑定的网卡"));
		return;
	}
	m_bFlag = true;
	CreateThread(NULL, NULL, CapturePacket, (LPVOID)this, true, NULL);
}

void CSnifferDlg::OnStop()
{
	// TODO: 在此添加命令处理程序代码
	m_bFlag = false;
}




DWORD WINAPI CapturePacket(LPVOID lpParam)
{
	CSnifferDlg* pDlg = (CSnifferDlg*)lpParam;
	pcap_t* pCap;
	//char	strErrorBuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	u_int netmask;
	struct bpf_program fcode;

	if ((pCap = pcap_open_live(pDlg->m_pDevice->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, pDlg->strErrorBuf)) == NULL)
	{
		return -1;
	}

	if (pDlg->m_pDevice->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(pDlg->m_pDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	//编译过滤器
	if (pcap_compile(pCap, &fcode, pDlg->m_filtername, 1, netmask) < 0)
	{
		AfxMessageBox(_T("请设置过滤规则"));
		return -1;
	}
	//设置过滤器
	if (pcap_setfilter(pCap, &fcode) < 0)
		return -1;
	CFileFind file;

	char thistime[30];
	struct tm* ltime;
	memset(pDlg->filepath, 0, 512);
	memset(pDlg->filename, 0, 64);

	if (!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"), NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
	strcpy(pDlg->filepath, "SavedData\\");
	strcat(pDlg->filename, thistime);
	strcat(pDlg->filename, ".lix");

	strcat(pDlg->filepath, pDlg->filename);
	pDlg->dumpfile = pcap_dump_open(pCap, pDlg->filepath);
	if (pDlg->dumpfile == NULL)
	{
		AfxMessageBox(_T("文件创建错误！"));
		return -1;
	}

	while ((res = pcap_next_ex(pCap, &pkt_header, &pkt_data)) >= 0)
	{

		if (res == 0)
			continue;
		if (!pDlg->m_bFlag)
			break;
		CSnifferDlg* pDlg = (CSnifferDlg*)AfxGetApp()->GetMainWnd();
		pDlg->ShowPacketList(pkt_header, pkt_data);
		
		if (pDlg->dumpfile != NULL)
		{
			pcap_dump((unsigned char*)pDlg->dumpfile, pkt_header, pkt_data);
		}

		pDlg = NULL;
	}

	

	pcap_close(pCap);
	pDlg = NULL;
	return 1;
}

void CSnifferDlg::ShowPacketList(const pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	//用于存诸网络中的数据，并保存到CArray中,以备将来使用
	struct pcap_pkthdr* pHeader = new pcap_pkthdr;
	u_char* pData;
	unsigned char* pPosition = (unsigned char*)pkt_data;

	long nIndex = 0;//标识当前的数据包位置
	long nCount = 0;//标识后来

	pHeader->caplen = pkt_header->caplen;
	pHeader->len = pkt_header->len;

	pData = new unsigned char[pHeader->len];
	memcpy((void*)pData, pkt_data, pHeader->len);

	m_pktHeaders.Add(pHeader);
	m_pktDatas.Add(pData);

	
	nIndex = m_pktHeaders.GetSize() - 1;
	CString str;
	str.Format(_T("%d"), nIndex);
	nCount = m_list1.InsertItem(nIndex, str, 0);
	m_totalCount++;//总数据包加1

	/*显示时间*/
	struct tm* ltime;
	time_t local_tv_sec;
	local_tv_sec = pkt_header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	str.Format(_T("%d:%d:%d.%.6d"), ltime->tm_hour, ltime->tm_min, ltime->tm_sec, pkt_header->ts.tv_usec);
	m_list1.SetItemText(nCount, 1, str);
	/*处理链路层*/
	ethernet_header* eh;
	eh = (ethernet_header*)pkt_data;
	str.Format(_T("%x:%x:%x:%x:%x:%x"), eh->saddr.byte1, eh->saddr.byte2, eh->saddr.byte3, eh->saddr.byte4, eh->saddr.byte5, eh->saddr.byte6);
	m_list1.SetItemText(nCount, 2, str);
	str.Format(_T("%x:%x:%x:%x:%x:%x"), eh->daddr.byte1, eh->daddr.byte2, eh->daddr.byte3, eh->daddr.byte4, eh->daddr.byte5, eh->daddr.byte6);
	m_list1.SetItemText(nCount, 3, str);
	str.Format(_T("%ld"), pHeader->len);
	m_list1.SetItemText(nCount, 4, str);
	/*处理网络层*/
	switch (ntohs(eh->type))
	{
	case IP:
	{
		ip_header* ih;
		const u_char* ip_data;
		ip_data = pkt_data + 14;
		ih = (ip_header*)ip_data;
		u_int ip_len;//IP首部长度
		ip_len = (ih->ver_ihl & 0xf) * 4;
		str.Format(_T("%d.%d.%d.%d"), ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		m_list1.SetItemText(nCount, 6, str);
		str.Format(_T("%d.%d.%d.%d"), ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		m_list1.SetItemText(nCount, 7, str);
		/*处理传输层*/
		switch (ih->type)
		{
		case TCP:
		{
			m_tcpCount++;
			tcp_header* th;
			const u_char* tcp_data;
			tcp_data = ip_data + ip_len;
			th = (tcp_header*)tcp_data;
			if (ntohs(th->sport) == HTTP)
			{
				m_list1.SetItemText(nCount, 5, _T("源HTTP"));
				m_httpCount++;
			}
			else if (ntohs(th->dport) == HTTP)
			{
				m_list1.SetItemText(nCount, 5, _T("目的HTTP"));
				m_httpCount++;
			}
			else if (ntohs(th->dport) == DNS || ntohs(th->sport) == DNS)
			{
				m_list1.SetItemText(nCount, 5, _T("DNS"));
				m_dnsCount++;
			}
			else
				m_list1.SetItemText(nCount, 5, _T("TCP"));
			if (ntohs(th->sport) == 0xC1DD || ntohs(th->dport) == 0xC1DD
				|| ntohs(th->sport) == 0xC2A1 || ntohs(th->dport) == 0xC2A1
				|| ntohs(th->sport) == 0xC2B4 || ntohs(th->dport) == 0xC2B4
				|| ntohs(th->sport) == 0xC2C2 || ntohs(th->dport) == 0xC2C2
				|| ntohs(th->sport) == 0xC306 || ntohs(th->dport) == 0xC306
				|| ntohs(th->sport) == 0xC311 || ntohs(th->dport) == 0xC311
				|| ntohs(th->sport) == 0xC313 || ntohs(th->dport) == 0xC313
				|| ntohs(th->sport) == 0xC32F || ntohs(th->dport) == 0xC32F
				|| ntohs(th->sport) == 0x10CD || ntohs(th->dport) == 0x10CD  //QQ登录流量为TCP端口4301
				|| ntohs(th->sport) == 0xC1E0 || ntohs(th->dport) == 0xC1E0
				|| ntohs(th->sport) == 0xC2D4 || ntohs(th->dport) == 0xC2D4
				|| ntohs(th->sport) == 0xC2E1 || ntohs(th->dport) == 0xC2E1
				|| ntohs(th->sport) == 0xC2E4 || ntohs(th->dport) == 0xC2E4)
				m_qqCount++;
			else if (ntohs(th->sport) == 0x280A || ntohs(th->dport) == 0x280A ||
				ntohs(th->sport) == 0x21E8 || ntohs(th->dport) == 0x21E8
				|| ntohs(th->sport) == 0xC132 || ntohs(th->dport) == 0xC132
				|| ntohs(th->sport) == 0x6738 || ntohs(th->dport) == 0x6738)	    //微信为TCP端口8680  10250      C514  49458
				m_weixinCount++;
			else if (ntohs(th->sport) == 0xC514 || ntohs(th->dport) == 0xC514    //50452 3
				|| ntohs(th->sport) == 0xC515 || ntohs(th->dport) == 0xC515
				|| ntohs(th->sport) == 0xC502 || ntohs(th->dport) == 0xC502  //50434 ~35
				|| ntohs(th->sport) == 0xC503 || ntohs(th->dport) == 0xC503
				|| ntohs(th->sport) == 0xC4F1 || ntohs(th->dport) == 0xC4F1  //50417  50418
				|| ntohs(th->sport) == 0xC4F2 || ntohs(th->dport) == 0xC4F2

				|| ntohs(th->sport) == 0xC4F4 || ntohs(th->dport) == 0xC4F4  //50420  21
				|| ntohs(th->sport) == 0xC4F5 || ntohs(th->dport) == 0xC4F5
				|| ntohs(th->sport) == 0xC511 || ntohs(th->dport) == 0xC511
				|| ntohs(th->sport) == 0xC512 || ntohs(th->dport) == 0xC512
				)   //C502
				m_weixinCount++;
			//火狐
			else if (ntohs(th->sport) == 0xC511 || ntohs(th->dport) == 0xC511    //50449 450
				|| ntohs(th->sport) == 0xC512 || ntohs(th->dport) == 0xC512)
				m_firfoxCount++;	
			//百度网盘  7475

			else if (ntohs(th->sport) == 0x1D33 || ntohs(th->dport) == 0x1D33)
				m_baiduNetCount++;
			else m_talkCount++;   //其他
			
			break;
		}
		case UDP:
		{
			m_udpCount++;
			udp_header* uh;
			const u_char* udp_data;
			udp_data = ip_data + ip_len;
			uh = (udp_header*)udp_data;
			if (ntohs(uh->dport) == DNS || ntohs(uh->sport) == DNS)
			{
				m_list1.SetItemText(nCount, 5, _T("DNS"));
				m_dnsCount++;
			}
			else
				m_list1.SetItemText(nCount, 5, _T("UDP"));
			if (ntohs(uh->dport) == 0xFB4 || ntohs(uh->sport) == 0xFB4
				|| ntohs(uh->dport) == 0xE3DC || ntohs(uh->sport) == 0xE3DC     //58332
				|| ntohs(uh->dport) == 0x1F90 || ntohs(uh->sport) == 0x1F90
				|| ntohs(uh->dport) == 0xE45F || ntohs(uh->sport) == 0xE45F
				|| ntohs(uh->dport) == 0xE460 || ntohs(uh->sport) == 0xE460
				|| ntohs(uh->dport) == 0xE461 || ntohs(uh->sport) == 0xE461
				|| ntohs(uh->dport) == 0xE462 || ntohs(uh->sport) == 0xE462
				|| ntohs(uh->dport) == 0xF42B || ntohs(uh->sport) == 0xF42B
				|| ntohs(uh->dport) == 0xD683 || ntohs(uh->sport) == 0xD683)		//QQ流量为UDP端口4020或。。。
				m_qqCount++;
			else if (ntohs(uh->dport) == 0xF378 || ntohs(uh->sport) == 0xF378)
				m_weixinCount++;
			else if (ntohs(uh->dport) == 0xD51B || ntohs(uh->dport) == 0xD51B)  //VM
				m_VMCount++;
			else if (ntohs(uh->sport) == 0xEB8A || ntohs(uh->dport) == 0xEB8A ||    //火狐 55066  60298
				ntohs(uh->sport) == 0xD71A || ntohs(uh->dport) == 0xD71A)
				m_firfoxCount++;
			else if (ntohs(uh->dport) == 0xF93C || ntohs(uh->dport) == 0xF93C ||     
				ntohs(uh->sport) == 0x1EAE || ntohs(uh->sport) == 0x1F7D)		//百度网怕流量为UDP端口7854  8061
				m_baiduNetCount++;
			else m_talkCount++;
			break;
		}
		case ICMP:m_icmpCount++; m_list1.SetItemText(nCount, 5, _T("ICMP")); break;
		case IGMP:m_igmpCount++; m_list1.SetItemText(nCount, 5, _T("IGMP")); break;
		case EGP:m_list1.SetItemText(nCount, 5, _T("EGP")); break;
		case IPv6:m_list1.SetItemText(nCount, 5, _T("IPv6")); break;
		case OSPF:m_list1.SetItemText(nCount, 5, _T("OSPF")); break;
		default:m_list1.SetItemText(nCount, 5, _T("未知"));
		}
		break;
	}
	case ARP:
	{
		m_arpCount++;
		arp_header* ah;
		const u_char* arp_data;
		arp_data = pkt_data + 14;
		ah = (arp_header*)arp_data;
		str.Format(_T("%d.%d.%d.%d"), ah->arp_sip.byte1, ah->arp_sip.byte2, ah->arp_sip.byte3, ah->arp_sip.byte4);
		m_list1.SetItemText(nCount, 6, str);
		str.Format(_T("%d.%d.%d.%d"), ah->arp_dip.byte1, ah->arp_dip.byte2, ah->arp_dip.byte3, ah->arp_dip.byte4);
		m_list1.SetItemText(nCount, 7, str);
		m_list1.SetItemText(nCount, 5, _T("ARP"));
		break;
	}
	case RARP:
		m_list1.SetItemText(nCount, 5, _T("RARP"));
		break;
	default:
		m_list1.SetItemText(nCount, 5, _T("未知协议"));
	}
	ShowPckNum();
}

void CSnifferDlg::ShowPacketTree(const pcap_pkthdr* pkt_header, const u_char* pkt_data, long index)
{
	m_tree1.DeleteAllItems();
	CString str;
	str.Format(_T("数据包:%ld"), index);
	HTREEITEM hRoot;
	HTREEITEM hSubItem;
	HTREEITEM hItem;
	HTREEITEM hItem2;

	hRoot = m_tree1.InsertItem(str);
	hSubItem = m_tree1.InsertItem(_T("数据链路层"), hRoot);
	ethernet_header* eh;
	eh = (ethernet_header*)pkt_data;
	str.Format(_T("源MAC:%x:%x:%x:%x:%x:%x"), eh->saddr.byte1, eh->saddr.byte2, eh->saddr.byte3, eh->saddr.byte4, eh->saddr.byte5, eh->saddr.byte6);
	hItem = m_tree1.InsertItem(str, hSubItem);
	str.Format(_T("目的MAC:%x:%x:%x:%x:%x:%x"), eh->daddr.byte1, eh->daddr.byte2, eh->daddr.byte3, eh->daddr.byte4, eh->daddr.byte5, eh->daddr.byte6);
	hItem = m_tree1.InsertItem(str, hSubItem);
	switch (ntohs(eh->type))
	{
	case IP:
	{
		hItem = m_tree1.InsertItem(_T("上层协议:IP"), hSubItem);
		hSubItem = m_tree1.InsertItem(_T("网络层"), hRoot);
		ip_header* ih;
		const u_char* ip_data;
		ip_data = pkt_data + 14;
		ih = (ip_header*)ip_data;
		str.Format(_T("版本：%d"), (ih->ver_ihl & 0xf0) / 0x10);
		hItem = m_tree1.InsertItem(str, hSubItem);
		u_int ip_len;//IP首部长度
		ip_len = (ih->ver_ihl & 0xf) * 4;
		str.Format(_T("首部长度：%d"), ip_len);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("服务类型：0x%x"), ih->tos);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("总长度：%d"), ntohs(ih->tlen));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("标识：0x%x"), ntohs(ih->identification));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("标志：0x%x"), ntohs(ih->flags_fo) & 0xe000 / 0x2000);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("片偏移：%d"), ntohs(ih->flags_fo) & 0x1fff);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("生存时间：%d"), ih->ttl);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("首部校验和：0x%x"), ntohs(ih->crc));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("源IP地址：%d.%d.%d.%d"), ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("目的IP地址：%d.%d.%d.%d"), ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4);
		hItem = m_tree1.InsertItem(str, hSubItem);
		switch (ih->type)
		{
		case TCP:
		{
			hItem = m_tree1.InsertItem(_T("上层协议:TCP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("传输层"), hRoot);
			tcp_header* th;
			const u_char* tcp_data;
			tcp_data = ip_data + ip_len;
			th = (tcp_header*)tcp_data;
			str.Format(_T("源端口号：%d"), ntohs(th->sport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("目的口号：%d"), ntohs(th->dport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("顺序号：%d"), ntohs(th->seq));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("确认号：%d"), ntohs(th->ack));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("TCP头长：%d"), (th->len & 0xf0) / 0x10 * 4);
			hItem = m_tree1.InsertItem(str, hSubItem);
			hItem = m_tree1.InsertItem(_T("控制位"), hSubItem);
			str.Format(_T("紧急URG:%d"), (th->flags & 0x20) / 0x20);
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("确认ACK:%d"), (th->flags & 0x10) / 0x10);
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("推送PSH:%d"), (th->flags & 0x08) / 0x08);
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("复位RSTG:%d"), (th->flags & 0x04) / 0x04);
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("同步SYN:%d"), (th->flags & 0x02) / 0x02);
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("结束FIN:%d"), (th->flags & 0x01) / 0x01);
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("窗口：%d"), ntohs(th->win));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("校验和：0x%x"), ntohs(th->crc));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("紧急指针：0x%x"), ntohs(th->urp));
			hItem = m_tree1.InsertItem(str, hSubItem);
			break;
		}
		case UDP:
		{
			hItem = m_tree1.InsertItem(_T("上层协议:UDP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("传输层"), hRoot);
			udp_header* uh;
			const u_char* udp_data;
			udp_data = ip_data + ip_len;
			uh = (udp_header*)udp_data;
			str.Format(_T("源端口号：%d"), ntohs(uh->sport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("目的口号：%d"), ntohs(uh->dport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("长度：%d"), ntohs(uh->len));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("校验和：0x%x"), ntohs(uh->crc));
			hItem = m_tree1.InsertItem(str, hSubItem);
			if (ntohs(uh->dport) == DNS || ntohs(uh->sport) == DNS)
			{
				hSubItem = m_tree1.InsertItem(_T("应用层"), hRoot);
				dns_header* dh;
				const u_char* dns_data;
				dns_data = udp_data + 8;
				dh = (dns_header*)dns_data;
				str.Format(_T("标识：0x%x"), ntohs(dh->identification));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("标志：0x%x"), ntohs(dh->flags));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("问题数：%d"), ntohs(dh->questions_num));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("资源记录数：%d"), ntohs(dh->answers_num));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("授权资源记录数：%d"), ntohs(dh->authority_num));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("额外资源记录数：%d"), ntohs(dh->addition_num));
				hItem = m_tree1.InsertItem(str, hSubItem);
			}
			break;
		}
		case ICMP:
		{
			hItem = m_tree1.InsertItem(_T("上层协议:ICMP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("传输层"), hRoot);
			icmp_header* icmph;
			const u_char* icmp_data;
			icmp_data = ip_data + ip_len;
			icmph = (icmp_header*)icmp_data;
			str.Format(_T("类型：%d"), icmph->type);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("代码：%d"), icmph->code);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("校验和：0x%x"), ntohs(icmph->checksum));
			hItem = m_tree1.InsertItem(str, hSubItem);
			break;
		}
		case IGMP:hItem = m_tree1.InsertItem(_T("上层协议:IGMP"), hSubItem); break;
		case EGP:hItem = m_tree1.InsertItem(_T("上层协议:EGP"), hSubItem); break;
		case IPv6:hItem = m_tree1.InsertItem(_T("上层协议:IPv6"), hSubItem); break;
		case OSPF:hItem = m_tree1.InsertItem(_T("上层协议:OSPF"), hSubItem); break;
		default:hItem = m_tree1.InsertItem(_T("上层协议:未知"), hSubItem);
		}
		break;
	}
	case ARP:
	{
		hItem = m_tree1.InsertItem(_T("上层协议:ARP"), hSubItem);
		hSubItem = m_tree1.InsertItem(_T("网络层"), hRoot);
		arp_header* ah;
		const u_char* arp_data;
		arp_data = pkt_data + 14;
		ah = (arp_header*)arp_data;
		str.Format(_T("硬件类型：%d"), ntohs(ah->arp_hdr));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("协议类型：0x%x"), ntohs(ah->arp_pro));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("硬件长度：%d"), ah->arp_hln);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("协议长度：%d"), ah->apr_pln);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("操作类型：%d"), ntohs(ah->arp_opt));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("发送端MAC地址：%x:%x:%x:%x:%x:%x"), ah->arp_smac.byte1, ah->arp_smac.byte2, ah->arp_smac.byte3, ah->arp_smac.byte4, ah->arp_smac.byte5, ah->arp_smac.byte6);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("发送端协议地址：%d.%d.%d.%d"), ah->arp_sip.byte1, ah->arp_sip.byte2, ah->arp_sip.byte3, ah->arp_sip.byte4);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("接收端MAC地址：%x:%x:%x:%x:%x:%x"), ah->arp_dmac.byte1, ah->arp_dmac.byte2, ah->arp_dmac.byte3, ah->arp_dmac.byte4, ah->arp_dmac.byte5, ah->arp_dmac.byte6);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("接收端协议地址：%d.%d.%d.%d"), ah->arp_dip.byte1, ah->arp_dip.byte2, ah->arp_dip.byte3, ah->arp_dip.byte4);
		hItem = m_tree1.InsertItem(str, hSubItem);
		break;
	}
	case RARP:
	{
		hItem = m_tree1.InsertItem(_T("上层协议:RARP"), hSubItem);
		break;
	}
	default:
		hItem = m_tree1.InsertItem(_T("上层协议:未知"), hSubItem);
	}

	m_tree1.Expand(hRoot, TVE_EXPAND);		//默认展开目录
	m_tree1.Expand(hSubItem, TVE_EXPAND);

	CString strHex;
	int nCount = 0;
	CString strText;
	for (unsigned short i = 0; i < pkt_header->caplen; i++)
	{
		CString hex;
		if ((i % 16) == 0)
		{
			hex.Format(_T("\x0d\x0a 0X%04x   "), nCount);
			nCount++;
			if (i != 0)
			{
				strHex += _T("  ") + strText;
				strText = _T("");
			}
			strHex += hex;
		}
		hex.Format(_T("%2.2x "), pkt_data[i - 1]);
		strHex += hex;
		if (pkt_data[i - 1] <= 127 && pkt_data[i - 1] >= 0)
			hex.Format(_T("%c"), pkt_data[i - 1]);
		else
			hex = _T(".");
		strText += hex;
	}
	if (strText != _T(""))
		strHex += strText;
	m_edit1.SetWindowText(strHex);
}

void CSnifferDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;

	POSITION pos = m_list1.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	long index = m_list1.GetNextSelectedItem(pos);
	if (index < 0)
		return;

	ShowPacketTree(m_pktHeaders.GetAt(index), m_pktDatas.GetAt(index), index);
}

void CSnifferDlg::ShowPckNum()
{
	m_tcpnum.Format(_T("%ld"), m_tcpCount);
	this->SetDlgItemText(IDC_EDIT2, m_tcpnum);
	m_udpnum.Format(_T("%ld"), m_udpCount);
	this->SetDlgItemText(IDC_EDIT3, m_udpnum);
	m_arpnum.Format(_T("%ld"), m_arpCount);
	this->SetDlgItemText(IDC_EDIT4, m_arpnum);
	m_icmpnum.Format(_T("%ld"), m_icmpCount);
	this->SetDlgItemText(IDC_EDIT5, m_icmpnum);
	m_igmpnum.Format(_T("%ld"), m_igmpCount);
	this->SetDlgItemText(IDC_EDIT6, m_igmpnum);
	m_totalnum.Format(_T("%ld"), m_totalCount);
	this->SetDlgItemText(IDC_EDIT7, m_totalnum);
	m_httpnum.Format(_T("%ld"), m_httpCount);
	this->SetDlgItemText(IDC_EDIT8, m_httpnum);
	m_dnsnum.Format(_T("%ld"), m_dnsCount);
	this->SetDlgItemText(IDC_EDIT9, m_dnsnum);



	m_weixinnum.Format(_T("%ld"), m_weixinCount);
	this->SetDlgItemText(IDC_EDIT10, m_weixinnum);

	m_qqnum.Format(_T("%ld"), m_qqCount);
	this->SetDlgItemText(IDC_EDIT11, m_qqnum);

	m_VMnum.Format(_T("%ld"), m_VMCount);
	this->SetDlgItemText(IDC_EDIT12, m_VMnum);

	m_firfoxnum.Format(_T("%ld"), m_firfoxCount);
	this->SetDlgItemText(IDC_EDIT13, m_firfoxnum);

	m_baiduNetnum.Format(_T("%ld"), m_baiduNetCount);
	this->SetDlgItemText(IDC_EDIT14, m_baiduNetnum);

	m_talknum.Format(_T("%ld"), m_talkCount);
	this->SetDlgItemText(IDC_EDIT15, m_talknum);

}

void CSnifferDlg::OnExit()
{
	// TODO: 在此添加命令处理程序代码
	CDialogEx::OnCancel();
}


void CSnifferDlg::OnRead() {
	
}
//保存菜单
void CSnifferDlg::OnSave()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->lixsniff_saveFile() < 0)
		return;
}


//保存文件


int CSnifferDlg::lixsniff_saveFile()
{
	CFileFind find;
	if (NULL == find.FindFile(CString(filepath)))
	{
		AfxMessageBox(_T("保存文件遇到未知意外"));
		return -1;
	}

	//打开文件对话框
	CFileDialog   FileDlg(FALSE, _T(".lix"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("d:\\");
	if (FileDlg.DoModal() == IDOK)
	{
		CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);
	}
	return 1;
}


