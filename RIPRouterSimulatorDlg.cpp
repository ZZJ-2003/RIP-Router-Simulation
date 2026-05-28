#include "stdafx.h"
#include "RIPRouterSimulator.h"
#include "RIPRouterSimulatorDlg.h"
#include "resource.h"
#if _MSC_VER >= 1600
#pragma execution_character_set("utf-8")
#endif

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#pragma pack(1)
typedef struct FrameHeader_t {
	UCHAR	DesMAC[6];
	UCHAR	SrcMAC[6];
	USHORT	FrameType;
} FrameHeader_t;

typedef struct ARPFrame_t {
	FrameHeader_t	FrameHeader;
	WORD			HardwareType;
	WORD			ProtocolType;
	BYTE			HLen;
	BYTE			PLen;
	WORD			Operation;
	UCHAR			SendHa[6];
	ULONG			SendIP;
	UCHAR			RecvHa[6];
	ULONG			RecvIP;
} ARPFrame_t;

typedef struct IPHeader_t {
	BYTE	Ver_HLen;
	BYTE	TOS;
	WORD	TotalLen;
	WORD	ID;
	WORD	Flag_Segment;
	BYTE	TTL;
	BYTE	Protocol;
	WORD	Checksum;
	ULONG	SrcIP;
	ULONG	DstIP;
} IPHeader_t;

typedef struct ICMPHeader_t {
	BYTE    Type;
	BYTE    Code;
	WORD    Checksum;
	WORD    Id;
	WORD    Sequence;
} ICMPHeader_t;

typedef struct UDPHeader_t {
	USHORT  SrcPort;
	USHORT  DstPort;
	USHORT  Len;
	USHORT  Checksum;
} UDPHeader_t;

typedef struct IPFrame_t {
	FrameHeader_t	FrameHeader;
	IPHeader_t		IPHeader;
} IPFrame_t;

typedef struct RIPRouteEntry {
	USHORT  AddressFamily;
	USHORT  RouteTag;
	ULONG   IPAddress;
	ULONG   SubnetMask;
	ULONG   NextHop;
	ULONG   Metric;
} RIPRouteEntry;

typedef struct RIPHeader {
	BYTE    Command;
	BYTE    Version;
	USHORT  Reserved;
} RIPHeader;

typedef struct RIPPacket {
	RIPHeader       header;
	RIPRouteEntry   entries[25];
} RIPPacket;

typedef struct RIPRouteTableEntry {
	ULONG   DstIP;
	ULONG   Mask;
	ULONG   NextHop;
	UINT    IfNo;
	UINT    Metric;
	UINT    InvalidTimer;
	UINT    FlushTimer;
	BOOL    bInvalid;
} RIPRouteTableEntry;
#pragma pack()

typedef struct ip_t {
	ULONG	IPAddr;
	ULONG	IPMask;
} ip_t;

typedef struct IfInfo_t {
	char* DeviceName;
	CString	Description;
	UCHAR	MACAddr[6];
	CArray<ip_t, ip_t&> ip;
	pcap_t* adhandle;

	IfInfo_t() : DeviceName(nullptr), adhandle(nullptr) {
		memset(MACAddr, 0, sizeof(MACAddr));
	}
} IfInfo_t;

typedef struct SendPacket_t {
	int		len;
	BYTE	PktData[2000];
	ULONG	TargetIP;
	UINT_PTR n_mTimer;
	UINT	IfNo;
	UINT	ArpRetries;
} SendPacket_t;

typedef struct RouteTable_t {
	ULONG	Mask;
	ULONG	DstIP;
	ULONG	NextHop;
	UINT	IfNo;
	UINT	Metric;
	BOOL	bStatic;
} RouteTable_t;

typedef struct IP_MAC_t {
	ULONG	IPAddr;
	UCHAR	MACAddr[6];
} IP_MAC_t;

typedef struct SentFrame_t {
	UINT	IfNo;
	UINT	Len;
	DWORD	Tick;
	ULONG	Hash;
} SentFrame_t;

IfInfo_t	    IfInfo[MAX_IF];
int			    IfCount = 0;
UINT_PTR        TimerCount = ARP_TIMER_BASE;

CList<SendPacket_t, SendPacket_t&> SP;
CList<IP_MAC_t, IP_MAC_t&> IP_MAC;
CList<SentFrame_t, SentFrame_t&> SentFrames;
CList<RouteTable_t, RouteTable_t&> RouteTable;
CList<RIPRouteTableEntry, RIPRouteTableEntry&> RIPRouteTable;
CMutex mMutex;
CMutex sentMutex;

CRouterDlg* pDlg = nullptr;
BOOL bRunning = FALSE;

CString IPntoa(ULONG nIPAddr);
CString MACntoa(UCHAR* nMACAddr);
bool cmpMAC(UCHAR* MAC1, UCHAR* MAC2);
void cpyMAC(UCHAR* MAC1, UCHAR* MAC2);
bool IPLookup(ULONG ipaddr, UCHAR* p);
bool UpdateARPCache(ULONG ip, const UCHAR* mac);
void FlushPendingPackets(ULONG ip, const UCHAR* mac);
bool SendOrQueuePacket(UINT ifNo, ULONG targetIP, BYTE* frame, int len);
bool IsLocalMAC(const UCHAR* mac);
ULONG PacketHash(const BYTE* data, UINT len);
UINT GetInterfaceNoByHandle(pcap_t* adhandle);
void RecordSentFrame(UINT ifNo, const BYTE* data, UINT len);
bool IsRecentlySentFrame(UINT ifNo, const BYTE* data, UINT len);
int SendRawPacket(pcap_t* adhandle, const BYTE* frame, int len);
UINT GetInterfaceNo(IfInfo_t* pIfInfo);
bool ResolveInterfaceMAC(IfInfo_t* pIfInfo);
ULONG GetInterfaceIPForTarget(UINT ifNo, ULONG targetIP);
void PoisonRoute(ULONG dst, ULONG mask, UINT ifNo);
void ProbeNextHopARP(UINT ifNo, ULONG targetIP);
void WarmUpNextHopARPCache();
UINT Capture(PVOID pParam);
UINT CaptureLocalARP(PVOID pParam);
void ARPRequest(pcap_t* adhandle, UCHAR* srcMAC, ULONG srcIP, ULONG targetIP);
void LearnSenderIPMAC(const u_char* pkt_data);
DWORD RouteLookup(UINT& ifNo, DWORD dst);
void ARPPacketProc(struct pcap_pkthdr* header, const u_char* pkt_data, int ifNo);
void IPPacketProc(IfInfo_t* pIfInfo, struct pcap_pkthdr* header, const u_char* pkt_data);
void ICMPPacketProc(IfInfo_t* pIfInfo, BYTE type, BYTE code, const u_char* pkt_data);
unsigned short ChecksumCompute(unsigned short* buffer, int size);
void SendRIPPacket(pcap_t* adhandle, int ifNo, BOOL bBroadcast);
void SendICMPEchoReply(IfInfo_t* pIf, const u_char* pkt_data);

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg() : CDialogEx(CAboutDlg::IDD) {}
	enum { IDD = IDD_ABOUTBOX };
protected:
	virtual void DoDataExchange(CDataExchange* pDX) { CDialogEx::DoDataExchange(pDX); }
	DECLARE_MESSAGE_MAP()
};
BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()

CRouterDlg::CRouterDlg(CWnd* pParent) : CDialogEx(CRouterDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	if (m_hIcon == NULL) m_hIcon = ::LoadIcon(NULL, IDI_APPLICATION);
	m_alldevs = nullptr;
	m_selectdevs = nullptr;
}

void CRouterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_Log);
	DDX_Control(pDX, IDC_LIST_ROUTE, m_RouteList);
	DDX_Control(pDX, IDC_IPADDRESS2, m_Mask);
	DDX_Control(pDX, IDC_IPADDRESS1, m_Destination);
	DDX_Control(pDX, IDC_IPADDRESS3, m_NextHop);
	DDX_Control(pDX, IDC_LIST3, mc_dev);
	DDX_Control(pDX, IDC_LIST_SELECTED_IF, m_SelectedIf);
}

BEGIN_MESSAGE_MAP(CRouterDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_START, &CRouterDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_ADD, &CRouterDlg::OnBnClickedAdd)
	ON_BN_CLICKED(IDC_DEL, &CRouterDlg::OnBnClickedDel)
	ON_BN_CLICKED(IDC_RETURN, &CRouterDlg::OnBnClickedReturn)
	ON_BN_CLICKED(IDC_ADD_IF, &CRouterDlg::OnBnClickedAddIf)
	ON_WM_DESTROY()
	ON_WM_SETTINGCHANGE()
	ON_WM_TIMER()
	ON_WM_VSCROLL()
END_MESSAGE_MAP()

void CRouterDlg::LogAdd(const CString& msg)
{
	const unsigned int MAX_LOG_LINES = 500;
	while ((unsigned int)m_Log.GetCount() > MAX_LOG_LINES) m_Log.DeleteString(0);
	m_Log.AddString(msg);
	SCROLLINFO si;
	si.cbSize = sizeof(si);
	si.fMask = SIF_ALL;
	m_Log.GetScrollInfo(SB_VERT, &si);
	// 只有滚动条已经在最底部时，才自动滚动到新消息
	if ((int)si.nPos == (int)(si.nMax - si.nPage)) {
		int cnt = m_Log.GetCount();
		m_Log.SetCurSel(cnt - 1);
		m_Log.SendMessage(WM_VSCROLL, SB_BOTTOM, 0);
	}
	m_Log.UpdateWindow();
}

void CRouterDlg::OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
{
	CDialogEx::OnVScroll(nSBCode, nPos, pScrollBar);
}

BOOL CRouterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	CString title;
	GetWindowText(title);
	SetWindowText(title + _T("-RIP路由器模拟"));

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL) {
		CString strAbout;
		VERIFY(strAbout.LoadString(IDS_ABOUTBOX));
		if (!strAbout.IsEmpty()) {
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, ID_APP_ABOUT, strAbout);
		}
	}
	SetIcon(m_hIcon, TRUE);
	SetIcon(m_hIcon, FALSE);
	pDlg = this;

	m_RouteList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_SHOWSELALWAYS);
	m_RouteList.InsertColumn(0, _T("类型"), LVCFMT_LEFT, 70);
	m_RouteList.InsertColumn(1, _T("子网掩码"), LVCFMT_LEFT, 140);
	m_RouteList.InsertColumn(2, _T("目的网络"), LVCFMT_LEFT, 140);
	m_RouteList.InsertColumn(3, _T("下一跳"), LVCFMT_LEFT, 160);
	m_RouteList.InsertColumn(4, _T("度量值"), LVCFMT_LEFT, 90);
	m_RouteList.InsertColumn(5, _T("接口"), LVCFMT_LEFT, 70);
	m_RouteList.InsertColumn(6, _T("状态/计时器"), LVCFMT_LEFT, 180);

	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs(&m_alldevs, errbuf) == -1) {
		LogAdd(_T("获取网卡失败: ") + CString(errbuf));
		return TRUE;
	}

	for (pcap_if_t* d = m_alldevs; d; d = d->next) {
		CStringA strA = d->name;
		if (d->description) { strA += " | "; strA += d->description; }
		CStringW strW(strA);
		mc_dev.AddString(strW);
	}
	if (mc_dev.GetCount() > 0) mc_dev.SetCurSel(0);

	mc_dev.SetHorizontalExtent(1600);
	m_Log.SetHorizontalExtent(1600);
	m_SelectedIf.SetHorizontalExtent(1600);

	LogAdd(_T("==================== RIP Router Simulator ===================="));
	LogAdd(_T("基于 Npcap, RIPv2 224.0.0.9组播, 水平分割/毒性逆转, 3/18/24秒演示定时器"));
	LogAdd(_T("使用方法: 添加网卡 -> 启动"));
	return TRUE;
}

void CRouterDlg::OnPaint()
{
	if (IsIconic()) {
		CPaintDC dc(this);
		SendMessage(WM_ICONERASEBKGND, (WPARAM)dc.GetSafeHdc(), 0);
		CRect rc; GetClientRect(&rc);
		int cx = GetSystemMetrics(SM_CXICON);
		int cy = GetSystemMetrics(SM_CYICON);
		dc.DrawIcon((rc.Width() - cx) / 2, (rc.Height() - cy) / 2, m_hIcon);
	}
	else CDialogEx::OnPaint();
}

HCURSOR CRouterDlg::OnQueryDragIcon() {
	return (HCURSOR)m_hIcon;
}

void CRouterDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == ID_APP_ABOUT) {
		CAboutDlg dlg; dlg.DoModal();
	}
	else CDialogEx::OnSysCommand(nID, lParam);
}

void CRouterDlg::OnBnClickedAddIf()
{
	int sel = mc_dev.GetCurSel();
	if (sel == LB_ERR) {
		MessageBox(_T("Please select an adapter"));
		return;
	}

	CString txt;
	mc_dev.GetText(sel, txt);

	for (int i = 0; i < m_SelectedIf.GetCount(); ++i) {
		CString s;
		m_SelectedIf.GetText(i, s);
		if (s.Find(_T("|")) >= 0) {
			CString n = s.Left(s.Find(_T("|")));
			if (_ttoi(n) == sel) {
				MessageBox(_T("该网卡已添加"));
				return;
			}
		}
	}

	CString item;
	item.Format(_T("%d|%s"), sel, txt);
	m_SelectedIf.AddString(item);
	LogAdd(_T("已添加网卡: ") + txt);
}

void CRouterDlg::OnBnClickedStart()
{
	if (m_SelectedIf.GetCount() == 0) {
		MessageBox(_T("请先添加一个网卡"));
		return;
	}

	GetDlgItem(IDC_START)->EnableWindow(FALSE);
	GetDlgItem(IDC_ADD_IF)->EnableWindow(FALSE);
	mc_dev.EnableWindow(FALSE);
	m_SelectedIf.EnableWindow(FALSE);

	char errbuf[PCAP_ERRBUF_SIZE];
	IfCount = 0;
	TimerCount = ARP_TIMER_BASE;
	bRunning = TRUE;
	RouteTable.RemoveAll();
	RIPRouteTable.RemoveAll();
	SP.RemoveAll();
	IP_MAC.RemoveAll();
	sentMutex.Lock();
	SentFrames.RemoveAll();
	sentMutex.Unlock();

	for (int i = 0; i < m_SelectedIf.GetCount(); ++i) {
		CString s;
		m_SelectedIf.GetText(i, s);
		int pos = s.Find('|');
		if (pos < 0) continue;
		int idx = _ttoi(s.Left(pos));

		pcap_if_t* d = m_alldevs;
		for (int j = 0; j < idx && d->next; j++) d = d->next;

		IfInfo[IfCount].DeviceName = d->name;
		IfInfo[IfCount].Description = d->description;
		bool hasIP = false;

		for (pcap_addr_t* a = d->addresses; a; a = a->next) {
			if (a->addr->sa_family == AF_INET) {
				ip_t ip;
				ip.IPAddr = ((sockaddr_in*)a->addr)->sin_addr.s_addr;
				ip.IPMask = ((sockaddr_in*)a->netmask)->sin_addr.s_addr;
				IfInfo[IfCount].ip.Add(ip);
				hasIP = 1;
			}
		}

		if (!hasIP) {
			MessageBox(_T("该网卡没有IPv4地址"));
			bRunning = FALSE;
			GetDlgItem(IDC_START)->EnableWindow(TRUE);
			GetDlgItem(IDC_ADD_IF)->EnableWindow(TRUE);
			mc_dev.EnableWindow(TRUE);
			m_SelectedIf.EnableWindow(TRUE);
			return;
		}

		IfInfo[IfCount].adhandle = pcap_open(IfInfo[IfCount].DeviceName, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, 0, errbuf);
		if (!IfInfo[IfCount].adhandle) {
			MessageBox(_T("打开网卡失败"));
			bRunning = FALSE;
			GetDlgItem(IDC_START)->EnableWindow(TRUE);
			GetDlgItem(IDC_ADD_IF)->EnableWindow(TRUE);
			mc_dev.EnableWindow(TRUE);
			m_SelectedIf.EnableWindow(TRUE);
			return;
		}

		if (!ResolveInterfaceMAC(&IfInfo[IfCount])) {
			MessageBox(_T("无法获取网卡MAC地址，不能启动转发"));
			pcap_close(IfInfo[IfCount].adhandle);
			IfInfo[IfCount].adhandle = nullptr;
			bRunning = FALSE;
			GetDlgItem(IDC_START)->EnableWindow(TRUE);
			GetDlgItem(IDC_ADD_IF)->EnableWindow(TRUE);
			mc_dev.EnableWindow(TRUE);
			m_SelectedIf.EnableWindow(TRUE);
			return;
		}

		LogAdd(_T("Adapter initialized"));
		LogAdd(MACntoa(IfInfo[IfCount].MACAddr));

		for (int j = 0; j < IfInfo[IfCount].ip.GetSize(); j++) {
			LogAdd(IPntoa(IfInfo[IfCount].ip[j].IPAddr) + _T(" ") + IPntoa(IfInfo[IfCount].ip[j].IPMask));
		}

		for (int j = 0; j < IfInfo[IfCount].ip.GetSize(); j++) {
			RouteTable_t rt;
			rt.IfNo = IfCount;
			rt.DstIP = IfInfo[IfCount].ip[j].IPAddr & IfInfo[IfCount].ip[j].IPMask;
			rt.Mask = IfInfo[IfCount].ip[j].IPMask;
			rt.NextHop = 0;
			rt.Metric = 0;
			rt.bStatic = FALSE;
			RouteTable.AddTail(rt);
		}

		char f[] = "udp port 520 or arp or ip";
		bpf_program code;
		pcap_compile(IfInfo[IfCount].adhandle, &code, f, 1, 0xFFFFFFFF);
		pcap_setfilter(IfInfo[IfCount].adhandle, &code);

		AfxBeginThread(Capture, &IfInfo[IfCount]);
		IfCount++;
	}

	InitRIP();
	RefreshRouteTableUI();
}

void CRouterDlg::InitRIP()
{
	RIPRouteTable.RemoveAll();
	SetTimer(RIP_UPDATE_TIMER_ID, 1000, NULL);
	LogAdd(_T("RIP已初始化"));
	WarmUpNextHopARPCache();
	SendRIPUpdate(-1);
}

void CRouterDlg::SendRIPUpdate(int ifNo, BOOL bBroadcast)
{
	if (ifNo == -1) {
		for (int i = 0; i < IfCount; i++) {
			SendRIPPacket(IfInfo[i].adhandle, i, bBroadcast);
		}
	}
	else if (ifNo < IfCount) {
		SendRIPPacket(IfInfo[ifNo].adhandle, ifNo, bBroadcast);
	}
}

void CRouterDlg::RefreshRouteTableUI()
{
	m_RouteList.SetRedraw(FALSE);
	m_RouteList.DeleteAllItems();
	int n = 0;

	POSITION pos = RouteTable.GetHeadPosition();
	while (pos) {
		RouteTable_t rt = RouteTable.GetNext(pos);
		m_RouteList.InsertItem(n, rt.bStatic ? _T("静态") : _T("直连"));
		m_RouteList.SetItemText(n, 1, IPntoa(rt.Mask));
		m_RouteList.SetItemText(n, 2, IPntoa(rt.DstIP));
		m_RouteList.SetItemText(n, 3, rt.NextHop == 0 ? _T("(直连)") : IPntoa(rt.NextHop));
		CString metric; metric.Format(_T("%u"), rt.Metric);
		m_RouteList.SetItemText(n, 4, metric);
		CString ifText; ifText.Format(_T("%u"), rt.IfNo);
		m_RouteList.SetItemText(n, 5, ifText);
		m_RouteList.SetItemText(n, 6, rt.bStatic ? _T("静态配置") : _T("本地接口"));
		n++;
	}

	pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		m_RouteList.InsertItem(n, e.bInvalid ? _T("RIP(失效)") : _T("RIP"));
		m_RouteList.SetItemText(n, 1, IPntoa(e.Mask));
		m_RouteList.SetItemText(n, 2, IPntoa(e.DstIP));
		m_RouteList.SetItemText(n, 3, IPntoa(e.NextHop));
		CString m; m.Format(_T("%u"), e.Metric);
		m_RouteList.SetItemText(n, 4, m);
		CString ifText; ifText.Format(_T("%u"), e.IfNo);
		m_RouteList.SetItemText(n, 5, ifText);
		CString state;
		state.Format(_T("%s 无效:%us 删除:%us"),
			e.bInvalid ? _T("毒性/待删除") : _T("有效"),
			e.InvalidTimer / 1000,
			e.FlushTimer / 1000);
		m_RouteList.SetItemText(n, 6, state);
		n++;
	}
	m_RouteList.SetRedraw(TRUE);
	m_RouteList.Invalidate();
}

void CRouterDlg::OnTimer(UINT_PTR nIDEvent)
{
	if (nIDEvent == RIP_UPDATE_TIMER_ID) {
		RIPTimerCheck();
		static int t = 0;
		t += 1000;
		if (t >= RIP_UPDATE_INTERVAL) {
			t = 0;
			CString logTimer;
			logTimer.Format(_T("[RIP] 周期性发送RIP更新 (%d秒)"), RIP_UPDATE_INTERVAL / 1000);
			LogAdd(logTimer);
			WarmUpNextHopARPCache();
			SendRIPUpdate(-1);
		}
		RefreshRouteTableUI();
	}
	else {
		// ARP重试/超时处理，避免首个业务包因一次ARP丢失而直接超时。
		mMutex.Lock();
		POSITION pos = SP.GetHeadPosition();
		while (pos) {
			POSITION cur = pos;
			SendPacket_t pkt = SP.GetNext(pos);
			if (pkt.n_mTimer == nIDEvent) {
				if (pkt.ArpRetries < ARP_MAX_RETRIES && pkt.IfNo < (UINT)IfCount) {
					pkt.ArpRetries++;
					SP.SetAt(cur, pkt);
					ULONG srcIP = GetInterfaceIPForTarget(pkt.IfNo, pkt.TargetIP);
					if (srcIP != 0) {
						CString logRetry;
						logRetry.Format(_T("[ARP] 重试解析 %s (%u/%u)"), IPntoa(pkt.TargetIP), pkt.ArpRetries, ARP_MAX_RETRIES);
						LogAdd(logRetry);
						ARPRequest(IfInfo[pkt.IfNo].adhandle, IfInfo[pkt.IfNo].MACAddr, srcIP, pkt.TargetIP);
					}
					SetTimer(pkt.n_mTimer, ARP_RETRY_INTERVAL, NULL);
					mMutex.Unlock();
					CDialogEx::OnTimer(nIDEvent);
					return;
				}
				CString logARP;
				logARP.Format(_T("[ARP] 超时: 无法解析 %s 的MAC地址"), IPntoa(pkt.TargetIP));
				LogAdd(logARP);
				SP.RemoveAt(cur);
				break;
			}
		}
		mMutex.Unlock();
		KillTimer(nIDEvent);
	}
	CDialogEx::OnTimer(nIDEvent);
}

void CRouterDlg::OnBnClickedAdd()
{
	DWORD ip;
	RouteTable_t rt = { 0 };

	if (!m_Mask.GetAddress(ip)) { MessageBox(_T("请输入有效的子网掩码")); return; }
	rt.Mask = htonl(ip);
	if (!m_Destination.GetAddress(ip)) { MessageBox(_T("请输入有效的目的网络")); return; }
	rt.DstIP = htonl(ip) & rt.Mask;
	if (!m_NextHop.GetAddress(ip)) { MessageBox(_T("请输入有效的下一跳")); return; }
	rt.NextHop = htonl(ip);
	rt.Metric = 0;
	rt.bStatic = TRUE;

	bool ok = false;
	for (int i = 0; i < IfCount; i++) {
		for (int j = 0; j < IfInfo[i].ip.GetSize(); j++) {
			ULONG nip = IfInfo[i].ip[j].IPAddr;
			ULONG nm = IfInfo[i].ip[j].IPMask;
			if ((nip & nm) == (rt.NextHop & nm)) {
				rt.IfNo = i;
				RouteTable.AddTail(rt);
				ProbeNextHopARP(rt.IfNo, rt.NextHop);
				POSITION pos = RIPRouteTable.GetHeadPosition();
				while (pos) {
					POSITION cur = pos;
					RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
					if (e.DstIP == rt.DstIP && e.Mask == rt.Mask) {
						RIPRouteTable.RemoveAt(cur);
						break;
					}
				}
				RefreshRouteTableUI();
				LogAdd(_T("[RIP] 触发更新: 静态路由添加，立即发送RIP更新"));
				SendRIPUpdate(-1);
				return;
			}
		}
	}
	MessageBox(_T("下一跳不可达"));
}

void CRouterDlg::OnBnClickedDel()
{
	int sel = m_RouteList.GetSelectionMark();
	if (sel < 0) { MessageBox(_T("请选择一条路由")); return; }

	CString type = m_RouteList.GetItemText(sel, 0);
	if (type == _T("直连")) { MessageBox(_T("直连路由不能删除")); return; }

	ULONG mask = inet_addr(CT2A(m_RouteList.GetItemText(sel, 1)));
	ULONG dst = inet_addr(CT2A(m_RouteList.GetItemText(sel, 2)));

	POSITION pos = RouteTable.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		RouteTable_t rt = RouteTable.GetNext(pos);
		if (rt.Mask == mask && rt.DstIP == dst) {
			RouteTable.RemoveAt(cur);
			PoisonRoute(rt.DstIP, rt.Mask, rt.IfNo);
			RefreshRouteTableUI();
			LogAdd(_T("[RIP] 触发更新: 静态路由删除，立即发送RIP更新"));
			SendRIPUpdate(-1);
			return;
		}
	}

	pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		if (e.Mask == mask && e.DstIP == dst) {
			e.Metric = RIP_INFINITY;
			e.bInvalid = TRUE;
			e.InvalidTimer = RIP_INVALID_TIMER;
			if (e.FlushTimer < RIP_INVALID_TIMER) e.FlushTimer = RIP_INVALID_TIMER;
			RIPRouteTable.SetAt(cur, e);
			RefreshRouteTableUI();
			LogAdd(_T("[RIP] 触发更新: RIP路由删除，先通告毒性路由"));
			SendRIPUpdate(-1);
			return;
		}
	}
}

void CRouterDlg::OnBnClickedReturn()
{
	bRunning = FALSE;
	KillTimer(RIP_UPDATE_TIMER_ID);

	// 先用pcap_breakloop中断Capture线程的pcap_next_ex等待
	for (int i = 0; i < IfCount; i++) {
		if (IfInfo[i].adhandle) pcap_breakloop(IfInfo[i].adhandle);
	}
	Sleep(500); // 等待线程退出

	m_Log.ResetContent();
	m_RouteList.DeleteAllItems();
	m_SelectedIf.ResetContent();

	RouteTable.RemoveAll();
	RIPRouteTable.RemoveAll();
	SP.RemoveAll();
	IP_MAC.RemoveAll();
	sentMutex.Lock();
	SentFrames.RemoveAll();
	sentMutex.Unlock();

	for (int i = 0; i < IfCount; i++) {
		if (IfInfo[i].adhandle) pcap_close(IfInfo[i].adhandle);
		IfInfo[i].ip.RemoveAll();
		IfInfo[i].adhandle = nullptr;
	}
	IfCount = 0;

	GetDlgItem(IDC_START)->EnableWindow(TRUE);
	GetDlgItem(IDC_ADD_IF)->EnableWindow(TRUE);
	mc_dev.EnableWindow(TRUE);
	m_SelectedIf.EnableWindow(TRUE);
}

void CRouterDlg::OnDestroy()
{
	bRunning = FALSE;
	KillTimer(RIP_UPDATE_TIMER_ID);
	for (int i = 0; i < IfCount; i++) {
		if (IfInfo[i].adhandle) {
			pcap_breakloop(IfInfo[i].adhandle);
			pcap_close(IfInfo[i].adhandle);
		}
	}
	if (m_alldevs) pcap_freealldevs(m_alldevs);
	CDialogEx::OnDestroy();
}

void CRouterDlg::OnSettingChange(UINT uFlags, LPCTSTR lpszSection) {
	CDialogEx::OnSettingChange(uFlags, lpszSection);
}

void CRouterDlg::ProcessRIPPacket(const u_char* pkt_data, UINT pkt_len, int ifNo)
{
	if (pkt_len < sizeof(FrameHeader_t) + sizeof(IPHeader_t) + sizeof(UDPHeader_t) + sizeof(RIPHeader)) {
		LogAdd(_T("[RIP] 丢弃过短的RIP报文"));
		return;
	}
	IPHeader_t* iph = (IPHeader_t*)(pkt_data + sizeof(FrameHeader_t));
	int ipHlen = (iph->Ver_HLen & 0x0F) * 4;
	if (ipHlen < 20 || pkt_len < sizeof(FrameHeader_t) + ipHlen + sizeof(UDPHeader_t) + sizeof(RIPHeader)) {
		LogAdd(_T("[RIP] 丢弃IP头长度异常的RIP报文"));
		return;
	}
	UDPHeader_t* udp = (UDPHeader_t*)((BYTE*)iph + ipHlen);
	RIPPacket* rip = (RIPPacket*)((BYTE*)udp + sizeof(UDPHeader_t));
	UINT udpLen = ntohs(udp->Len);
	if (ntohs(udp->SrcPort) != RIP_PORT || ntohs(udp->DstPort) != RIP_PORT ||
		udpLen < sizeof(UDPHeader_t) + sizeof(RIPHeader) ||
		sizeof(FrameHeader_t) + ipHlen + udpLen > pkt_len) {
		LogAdd(_T("[RIP] 丢弃UDP端口或长度异常的RIP报文"));
		return;
	}

	if (rip->header.Version != RIP_VERSION || (rip->header.Command != 1 && rip->header.Command != 2)) {
		LogAdd(_T("[RIP] 无效的RIP包 (版本或命令不对)"));
		return;
	}

	LearnSenderIPMAC(pkt_data);

	if (rip->header.Command == 1) {
		LogAdd(_T("[RIP RX] 收到RIPv2请求，立即回应完整路由表"));
		SendRIPUpdate(ifNo);
		return;
	}

	// 过滤自身发出的RIP包，防止自收自包重置计时器
	ULONG src_ip = iph->SrcIP; // 网络序
	for (int i = 0; i < IfCount; i++) {
		for (int j = 0; j < IfInfo[i].ip.GetSize(); j++) {
			if (IfInfo[i].ip[j].IPAddr == src_ip) {
				return; // 来自自身IP，忽略
			}
		}
	}

	// 检查源IP是否来自接收接口的直连网络（只检查收到该RIP包的接口）
	bool from_direct = false;
	for (int j = 0; j < IfInfo[ifNo].ip.GetSize(); j++) {
		ULONG ifIP = IfInfo[ifNo].ip[j].IPAddr;   // 网络序
		ULONG ifMask = IfInfo[ifNo].ip[j].IPMask;  // 网络序
		if ((src_ip & ifMask) == (ifIP & ifMask)) {
			from_direct = true;
		}
	}

	if (!from_direct) {
		CString logSkip;
		logSkip.Format(_T("[RIP RX] (忽略来自 %s 的更新，非直连网络)"), IPntoa(iph->SrcIP));
		if (pDlg) pDlg->LogAdd(logSkip);
		return;
	}

	CString logStart;
	logStart.Format(_T("[RIP RX] 收到来自 %s 的RIP更新"), IPntoa(iph->SrcIP));
	LogAdd(logStart);

	int nAdd = 0, nUpdate = 0, nSkip = 0, nPoison = 0;
	bool changed = false;
	int entryCount = (udpLen - sizeof(UDPHeader_t) - sizeof(RIPHeader)) / sizeof(RIPRouteEntry);
	if (entryCount > 25) entryCount = 25;

	for (int i = 0; i < entryCount; i++) {
		RIPRouteEntry& e = rip->entries[i];
		if (ntohs(e.AddressFamily) != 2) { nSkip++; continue; }

		ULONG dst = e.IPAddress;
		ULONG mask = e.SubnetMask;
		UINT advertisedMetric = ntohl(e.Metric);
		if (advertisedMetric > RIP_INFINITY) { nSkip++; continue; }
		UINT metric = advertisedMetric >= RIP_INFINITY ? RIP_INFINITY : advertisedMetric + 1;
		if (metric > RIP_INFINITY) metric = RIP_INFINITY;
		ULONG from = iph->SrcIP;

		// 检查是否为本地直连网络
		bool local = false;
		for (int j = 0; j < IfCount && !local; j++) {
			for (int k = 0; k < IfInfo[j].ip.GetSize(); k++) {
				ULONG localNet = IfInfo[j].ip[k].IPAddr & IfInfo[j].ip[k].IPMask;
				ULONG localMask = IfInfo[j].ip[k].IPMask;
				if (dst == localNet && mask == localMask) { local = true; }
			}
		}
		if (local) { nSkip++; continue; }

		// 检查RouteTable中是否已有相同目的网络的路由（静态路由优先于RIP）
		bool existsInRouteTable = false;
		POSITION posRT = RouteTable.GetHeadPosition();
		while (posRT) {
			RouteTable_t rt = RouteTable.GetNext(posRT);
			if (rt.DstIP == dst && rt.Mask == mask) { existsInRouteTable = true; break; }
		}
		if (existsInRouteTable) { nSkip++; continue; }

		// 处理度量值16（毒性逆转/路由不可达）
		if (metric >= RIP_INFINITY) {
			bool foundSameNextHop = false;
			POSITION posRIP = RIPRouteTable.GetHeadPosition();
			while (posRIP) {
				RIPRouteTableEntry re = RIPRouteTable.GetNext(posRIP);
				if (re.DstIP == dst && re.Mask == mask && re.NextHop == from) { foundSameNextHop = true; break; }
			}
			if (foundSameNextHop) {
				nPoison++;
				if (RIPRouteUpdate(dst, mask, from, metric, ifNo)) changed = true;
			}
			else {
				nSkip++;
			}
			continue;
		}

		// 检查是否为更新已有路由
		bool isUpdate = false;
		POSITION posCheck = RIPRouteTable.GetHeadPosition();
		while (posCheck) {
			RIPRouteTableEntry re = RIPRouteTable.GetNext(posCheck);
			if (re.DstIP == dst && re.Mask == mask && re.NextHop == from) { isUpdate = true; break; }
		}

		if (RIPRouteUpdate(dst, mask, from, metric, ifNo)) changed = true;
		if (isUpdate) nUpdate++; else nAdd++;
	}

	CString logSummary;
	logSummary.Format(_T("[RIP RX] 收到 %d 条路由: 新增%d, 更新%d, 跳过%d, 毒性%d"), nAdd + nUpdate + nSkip + nPoison, nAdd, nUpdate, nSkip, nPoison);
	LogAdd(logSummary);
	if (changed) {
		LogAdd(_T("[RIP] 触发更新: 路由变化，立即发送RIP更新"));
		SendRIPUpdate(-1);
	}
	RefreshRouteTableUI();
}

BOOL CRouterDlg::RIPRouteUpdate(ULONG dst, ULONG mask, ULONG nextHop, UINT metric, UINT ifNo)
{
	POSITION pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		if (e.DstIP == dst && e.Mask == mask) {
			if (e.NextHop == nextHop) {
				// 来自同一下一跳的更新，始终接受（包括度量值变差或变为16）
				BOOL changed = (e.Metric != metric || e.IfNo != ifNo || (metric >= RIP_INFINITY && !e.bInvalid));
				e.Metric = metric;
				e.IfNo = ifNo;
				if (metric >= RIP_INFINITY) {
					// 毒性路由立即进入无效状态，删除计时器仍以最后一次有效更新为基准。
					e.InvalidTimer = RIP_INVALID_TIMER;
					e.bInvalid = TRUE;
				}
				else {
					e.InvalidTimer = 0;
					e.FlushTimer = 0;
					e.bInvalid = FALSE;
				}
				RIPRouteTable.SetAt(cur, e);
				if (metric < RIP_INFINITY) ProbeNextHopARP(ifNo, nextHop);
				return changed;
			}
			else if (metric < e.Metric || e.bInvalid) {
				// 来自不同下一跳但度量值更优，切换下一跳
				e.Metric = metric;
				e.NextHop = nextHop;
				e.IfNo = ifNo;
				if (metric >= RIP_INFINITY) {
					e.InvalidTimer = RIP_INVALID_TIMER;
					e.bInvalid = TRUE;
				}
				else {
					e.InvalidTimer = 0;
					e.FlushTimer = 0;
					e.bInvalid = FALSE;
				}
				RIPRouteTable.SetAt(cur, e);
				if (metric < RIP_INFINITY) ProbeNextHopARP(ifNo, nextHop);
				return TRUE;
			}
			return FALSE;
		}
	}

	// 不存在则添加新路由（度量值>=16的路由不添加）
	if (metric >= RIP_INFINITY) return FALSE;

	RIPRouteTableEntry ne = { 0 };
	ne.DstIP = dst;
	ne.Mask = mask;
	ne.NextHop = nextHop;
	ne.IfNo = ifNo;
	ne.Metric = metric;
	ne.bInvalid = FALSE;
	RIPRouteTable.AddTail(ne);
	ProbeNextHopARP(ifNo, nextHop);
	return TRUE;
}

void CRouterDlg::RIPTimerCheck()
{
	bool bNeedTriggeredUpdate = false;
	POSITION pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		e.InvalidTimer += 1000;
		e.FlushTimer += 1000;

		bool bDeleted = false;

		if (!e.bInvalid && e.InvalidTimer >= RIP_INVALID_TIMER) {
			e.bInvalid = TRUE;
			e.Metric = RIP_INFINITY;
			CString logInvalid;
			logInvalid.Format(_T("[RIP] 路由失效: %s/%s, 度量值=16 (%d秒未收到更新)"), IPntoa(e.DstIP), IPntoa(e.Mask), RIP_INVALID_TIMER / 1000);
			LogAdd(logInvalid);
			bNeedTriggeredUpdate = true;
		}
		else if (e.FlushTimer >= RIP_FLUSH_TIMER) {
			CString logFlush;
			logFlush.Format(_T("[RIP] 路由删除: %s/%s (%d秒超时，从路由表移除)"), IPntoa(e.DstIP), IPntoa(e.Mask), RIP_FLUSH_TIMER / 1000);
			LogAdd(logFlush);
			RIPRouteTable.RemoveAt(cur);
			bDeleted = true;
		}

		// 关键：每次递增计时器后必须写回链表，否则计时器值丢失，路由永远不会老化
		if (!bDeleted) {
			RIPRouteTable.SetAt(cur, e);
		}
	}
	if (bNeedTriggeredUpdate) {
		LogAdd(_T("[RIP] 触发更新: 路由失效，立即发送RIP更新(含毒性逆转)"));
		SendRIPUpdate(-1);
	}
}

UINT CaptureLocalARP(PVOID p) {
	return 0;
}

UINT Capture(PVOID pParam)
{
	IfInfo_t* pIf = (IfInfo_t*)pParam;
	UINT ifNo = (UINT)(pIf - IfInfo);
	while (bRunning) {
		pcap_pkthdr* hdr;
		const u_char* data;
		int r = pcap_next_ex(pIf->adhandle, &hdr, &data);
		if (r != 1) {
			if (!bRunning) break;
			continue;
		}
		if (hdr->caplen < sizeof(FrameHeader_t)) continue;

		FrameHeader_t* fh = (FrameHeader_t*)data;
		if (IsRecentlySentFrame(ifNo, data, hdr->caplen)) {
			continue;
		}
		if (ntohs(fh->FrameType) == 0x0806) {
			// ARP包不进行IsLocalMAC过滤：多实例同机部署时ARP回复可能来自同MAC的网卡
			ARPPacketProc(hdr, data, (int)ifNo);
		}
		else if (ntohs(fh->FrameType) == 0x0800) {
			if (hdr->caplen < sizeof(FrameHeader_t) + sizeof(IPHeader_t)) continue;
			IPHeader_t* iph = (IPHeader_t*)(data + sizeof(FrameHeader_t));
			// RIP数据包：绕过IsLocalMAC过滤，由ProcessRIPPacket根据源IP自行过滤
			if (iph->Protocol == IPPROTO_UDP) {
				int hlen = (iph->Ver_HLen & 0x0F) * 4;
				if (hlen >= 20 && hdr->caplen >= sizeof(FrameHeader_t) + hlen + sizeof(UDPHeader_t)) {
					UDPHeader_t* udp = (UDPHeader_t*)((BYTE*)iph + hlen);
					if (ntohs(udp->DstPort) == 520 && pDlg) {
						pDlg->ProcessRIPPacket(data, hdr->caplen, (int)ifNo);
						continue;
					}
				}
			}
			// 不再按源MAC一刀切丢包；同机多实例可能共享同一个网卡MAC。
			IPPacketProc(pIf, hdr, data);
		}
	}
	return 0;
}

void ARPPacketProc(pcap_pkthdr* header, const u_char* pkt_data, int ifNo)
{
	ARPFrame_t* arp = (ARPFrame_t*)pkt_data;
	UpdateARPCache(arp->SendIP, arp->SendHa);
	FlushPendingPackets(arp->SendIP, arp->SendHa);

	if (ntohs(arp->Operation) == 1) {
		// ARP请求 - 检查是否请求我们的IP
		ULONG targetIP = arp->RecvIP; // 网络序
		if (ifNo >= 0 && ifNo < IfCount) {
			for (int j = 0; j < IfInfo[ifNo].ip.GetSize(); j++) {
				if (IfInfo[ifNo].ip[j].IPAddr == targetIP) {
					// 发送ARP回复
					BYTE buf[1500] = { 0 };
					ARPFrame_t* reply = (ARPFrame_t*)buf;
					memcpy(reply->FrameHeader.DesMAC, arp->SendHa, 6);
					memcpy(reply->FrameHeader.SrcMAC, IfInfo[ifNo].MACAddr, 6);
					reply->FrameHeader.FrameType = htons(0x0806);
					reply->HardwareType = htons(1);
					reply->ProtocolType = htons(0x0800);
					reply->HLen = 6;
					reply->PLen = 4;
					reply->Operation = htons(2); // ARP回复
					memcpy(reply->SendHa, IfInfo[ifNo].MACAddr, 6);
					reply->SendIP = IfInfo[ifNo].ip[j].IPAddr;
					memcpy(reply->RecvHa, arp->SendHa, 6);
					reply->RecvIP = arp->SendIP;
					SendRawPacket(IfInfo[ifNo].adhandle, buf, sizeof(ARPFrame_t));

					CString logARP;
					logARP.Format(_T("[ARP] 回复: %s 是 %s"), IPntoa(targetIP), MACntoa(IfInfo[ifNo].MACAddr));
					if (pDlg) pDlg->LogAdd(logARP);
					return;
				}
			}
		}
	}
	else if (ntohs(arp->Operation) == 2) {
		// ARP回复 - 学习IP-MAC映射（FlushPendingPackets已在前面统一调用）
		ULONG ip = arp->SendIP;
		CString logARP;
		logARP.Format(_T("[ARP] 学习: %s -> %s"), IPntoa(ip), MACntoa(arp->SendHa));
		if (pDlg) pDlg->LogAdd(logARP);
	}
}

void LearnSenderIPMAC(const u_char* pkt_data)
{
	if (pkt_data == nullptr) return;

	FrameHeader_t* fh = (FrameHeader_t*)pkt_data;
	if (ntohs(fh->FrameType) != 0x0800) return;

	IPHeader_t* iph = (IPHeader_t*)(pkt_data + sizeof(FrameHeader_t));
	if ((iph->Ver_HLen >> 4) != 4 || (iph->Ver_HLen & 0x0F) < 5) return;

	ULONG srcIP = iph->SrcIP;
	ULONG srcHost = ntohl(srcIP);
	if (srcHost == 0 || srcHost == 0xFFFFFFFF ||
		(srcHost >= 0xE0000000 && srcHost <= 0xEFFFFFFF)) {
		return;
	}

	for (int i = 0; i < IfCount; i++) {
		for (int j = 0; j < IfInfo[i].ip.GetSize(); j++) {
			if (IfInfo[i].ip[j].IPAddr == srcIP) return;
		}
	}

	UpdateARPCache(srcIP, fh->SrcMAC);
}

bool UpdateARPCache(ULONG ip, const UCHAR* mac)
{
	if (ip == 0 || mac == nullptr) return false;
	UCHAR zero[6] = { 0 };
	UCHAR broadcast[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
	if (memcmp(mac, zero, 6) == 0 || memcmp(mac, broadcast, 6) == 0) return false;

	// 拒绝缓存属于本机自身的IP（避免循环），但允许同MAC不同IP（多实例部署场景）
	for (int i = 0; i < IfCount; i++) {
		for (int j = 0; j < IfInfo[i].ip.GetSize(); j++) {
			if (IfInfo[i].ip[j].IPAddr == ip) return false;
		}
	}

	mMutex.Lock();
	POSITION pos = IP_MAC.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		IP_MAC_t im = IP_MAC.GetNext(pos);
		if (im.IPAddr == ip) {
			if (memcmp(im.MACAddr, mac, 6) != 0) {
				memcpy(im.MACAddr, mac, 6);
				IP_MAC.SetAt(cur, im);
			}
			mMutex.Unlock();
			return true;
		}
	}

	IP_MAC_t im;
	im.IPAddr = ip;
	memcpy(im.MACAddr, mac, 6);
	IP_MAC.AddHead(im);

	const int MAX_IP_MAC_ENTRIES = 500;
	while (IP_MAC.GetCount() > MAX_IP_MAC_ENTRIES) {
		IP_MAC.RemoveTail();
	}
	mMutex.Unlock();
	return true;
}

void FlushPendingPackets(ULONG ip, const UCHAR* mac)
{
	mMutex.Lock();
	POSITION pos = SP.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		SendPacket_t pkt = SP.GetNext(pos);
		if (pkt.TargetIP == ip && pkt.IfNo < (UINT)IfCount) {
			FrameHeader_t* fh = (FrameHeader_t*)pkt.PktData;
			memcpy(fh->DesMAC, mac, 6);
			memcpy(fh->SrcMAC, IfInfo[pkt.IfNo].MACAddr, 6);
			if (SendRawPacket(IfInfo[pkt.IfNo].adhandle, pkt.PktData, pkt.len) == 0) {
				SP.RemoveAt(cur);
				if (pDlg) pDlg->KillTimer(pkt.n_mTimer);
			}
			else {
				// 发送失败，保留数据包等待ARP重试定时器触发
				CString logSendFail;
				logSendFail.Format(_T("[PKT] 发送失败: 目标IP %s 接口%u, 等待ARP重试"), IPntoa(ip), pkt.IfNo);
				if (pDlg) pDlg->LogAdd(logSendFail);
			}
		}
	}
	mMutex.Unlock();
}

bool SendOrQueuePacket(UINT ifNo, ULONG targetIP, BYTE* frame, int len)
{
	if (frame == nullptr || len <= (int)sizeof(FrameHeader_t) || len > 2000 ||
		ifNo >= (UINT)IfCount || targetIP == 0) {
		return false;
	}

	FrameHeader_t* fh = (FrameHeader_t*)frame;
	UCHAR mac[6];
	if (IPLookup(targetIP, mac)) {
		memcpy(fh->DesMAC, mac, 6);
		memcpy(fh->SrcMAC, IfInfo[ifNo].MACAddr, 6);
		if (SendRawPacket(IfInfo[ifNo].adhandle, frame, len) == 0) {
			return true;
		}
		// 直接发送失败，回退到队列等待ARP重试
	}

	SendPacket_t sp;
	sp.len = len;
	sp.TargetIP = targetIP;
	sp.IfNo = ifNo;
	sp.ArpRetries = 0;
	memcpy(sp.PktData, frame, len);

	mMutex.Lock();
	sp.n_mTimer = TimerCount++;
	if (pDlg) pDlg->SetTimer(sp.n_mTimer, ARP_RETRY_INTERVAL, NULL);
	SP.AddTail(sp);
	mMutex.Unlock();

	ULONG srcIP = GetInterfaceIPForTarget(ifNo, targetIP);
	if (srcIP != 0) {
		ARPRequest(IfInfo[ifNo].adhandle, IfInfo[ifNo].MACAddr, srcIP, targetIP);
	}
	return true;
}

bool IsLocalMAC(const UCHAR* mac)
{
	if (mac == nullptr) return false;
	for (int i = 0; i < IfCount; i++) {
		if (memcmp(mac, IfInfo[i].MACAddr, 6) == 0) return true;
	}
	return false;
}

ULONG PacketHash(const BYTE* data, UINT len)
{
	if (data == nullptr) return 0;

	ULONG hash = 2166136261u;
	for (UINT i = 0; i < len; i++) {
		hash ^= data[i];
		hash *= 16777619u;
	}
	return hash;
}

UINT GetInterfaceNoByHandle(pcap_t* adhandle)
{
	if (adhandle == nullptr) return (UINT)-1;

	for (int i = 0; i < IfCount; i++) {
		if (IfInfo[i].adhandle == adhandle) return (UINT)i;
	}
	return (UINT)-1;
}

void RecordSentFrame(UINT ifNo, const BYTE* data, UINT len)
{
	if (ifNo >= (UINT)IfCount || data == nullptr || len == 0) return;

	SentFrame_t sf;
	sf.IfNo = ifNo;
	sf.Len = len;
	sf.Tick = GetTickCount();
	sf.Hash = PacketHash(data, len);

	sentMutex.Lock();
	SentFrames.AddHead(sf);

	const DWORD SENT_FRAME_TTL = 2000;
	const int MAX_SENT_FRAMES = 256;
	DWORD now = GetTickCount();
	POSITION pos = SentFrames.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		SentFrame_t old = SentFrames.GetNext(pos);
		if ((DWORD)(now - old.Tick) > SENT_FRAME_TTL) {
			SentFrames.RemoveAt(cur);
		}
	}
	while (SentFrames.GetCount() > MAX_SENT_FRAMES) {
		SentFrames.RemoveTail();
	}
	sentMutex.Unlock();
}

bool IsRecentlySentFrame(UINT ifNo, const BYTE* data, UINT len)
{
	if (ifNo >= (UINT)IfCount || data == nullptr || len == 0) return false;

	const DWORD SENT_FRAME_TTL = 2000;
	DWORD now = GetTickCount();
	ULONG hash = PacketHash(data, len);
	bool matched = false;

	sentMutex.Lock();
	POSITION pos = SentFrames.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		SentFrame_t old = SentFrames.GetNext(pos);
		if ((DWORD)(now - old.Tick) > SENT_FRAME_TTL) {
			SentFrames.RemoveAt(cur);
			continue;
		}
		if (old.IfNo == ifNo && old.Len == len && old.Hash == hash) {
			SentFrames.RemoveAt(cur);
			matched = true;
			break;
		}
	}
	sentMutex.Unlock();
	return matched;
}

int SendRawPacket(pcap_t* adhandle, const BYTE* frame, int len)
{
	UINT ifNo = GetInterfaceNoByHandle(adhandle);
	if (ifNo != (UINT)-1 && frame != nullptr && len > 0) {
		RecordSentFrame(ifNo, frame, (UINT)len);
	}
	return pcap_sendpacket(adhandle, frame, len);
}

UINT GetInterfaceNo(IfInfo_t* pIfInfo)
{
	if (pIfInfo == nullptr) return (UINT)-1;
	for (int i = 0; i < IfCount; i++) {
		if (&IfInfo[i] == pIfInfo) return (UINT)i;
	}
	return (UINT)-1;
}

bool ResolveInterfaceMAC(IfInfo_t* pIfInfo)
{
	if (pIfInfo == nullptr) return false;

	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
	ULONG family = AF_INET;
	ULONG bufLen = 0;
	DWORD ret = GetAdaptersAddresses(family, flags, nullptr, nullptr, &bufLen);
	if (ret != ERROR_BUFFER_OVERFLOW || bufLen == 0) return false;

	std::vector<BYTE> buffer(bufLen);
	IP_ADAPTER_ADDRESSES* adapters = (IP_ADAPTER_ADDRESSES*)&buffer[0];
	ret = GetAdaptersAddresses(family, flags, nullptr, adapters, &bufLen);
	if (ret != NO_ERROR) return false;

	for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter; adapter = adapter->Next) {
		if (adapter->PhysicalAddressLength != 6) continue;
		for (IP_ADAPTER_UNICAST_ADDRESS* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
			if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
			ULONG addr = ((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr.s_addr;
			for (int i = 0; i < pIfInfo->ip.GetSize(); i++) {
				if (pIfInfo->ip[i].IPAddr == addr) {
					memcpy(pIfInfo->MACAddr, adapter->PhysicalAddress, 6);
					return true;
				}
			}
		}
	}
	return false;
}

ULONG GetInterfaceIPForTarget(UINT ifNo, ULONG targetIP)
{
	if (ifNo >= (UINT)IfCount || IfInfo[ifNo].ip.GetSize() == 0) return 0;
	for (int i = 0; i < IfInfo[ifNo].ip.GetSize(); i++) {
		ULONG ifIP = IfInfo[ifNo].ip[i].IPAddr;
		ULONG mask = IfInfo[ifNo].ip[i].IPMask;
		if ((ifIP & mask) == (targetIP & mask)) return ifIP;
	}
	return IfInfo[ifNo].ip[0].IPAddr;
}

void ProbeNextHopARP(UINT ifNo, ULONG targetIP)
{
	if (ifNo >= (UINT)IfCount || targetIP == 0) return;

	UCHAR mac[6];
	if (IPLookup(targetIP, mac)) return;

	ULONG srcIP = GetInterfaceIPForTarget(ifNo, targetIP);
	if (srcIP == 0) return;

	CString logProbe;
	logProbe.Format(_T("[ARP] 预解析下一跳: %s (接口%u)"), IPntoa(targetIP), ifNo);
	if (pDlg) pDlg->LogAdd(logProbe);
	ARPRequest(IfInfo[ifNo].adhandle, IfInfo[ifNo].MACAddr, srcIP, targetIP);
}

void WarmUpNextHopARPCache()
{
	POSITION pos = RouteTable.GetHeadPosition();
	while (pos) {
		RouteTable_t rt = RouteTable.GetNext(pos);
		if (rt.NextHop != 0) ProbeNextHopARP(rt.IfNo, rt.NextHop);
	}

	pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		if (!e.bInvalid && e.Metric < RIP_INFINITY) ProbeNextHopARP(e.IfNo, e.NextHop);
	}
}

void PoisonRoute(ULONG dst, ULONG mask, UINT ifNo)
{
	POSITION pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		POSITION cur = pos;
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		if (e.DstIP == dst && e.Mask == mask) {
			e.Metric = RIP_INFINITY;
			e.bInvalid = TRUE;
			e.InvalidTimer = RIP_INVALID_TIMER;
			if (e.FlushTimer < RIP_INVALID_TIMER) e.FlushTimer = RIP_INVALID_TIMER;
			RIPRouteTable.SetAt(cur, e);
			return;
		}
	}

	RIPRouteTableEntry e = { 0 };
	e.DstIP = dst;
	e.Mask = mask;
	e.NextHop = 0;
	e.IfNo = ifNo;
	e.Metric = RIP_INFINITY;
	e.InvalidTimer = RIP_INVALID_TIMER;
	e.FlushTimer = RIP_INVALID_TIMER;
	e.bInvalid = TRUE;
	RIPRouteTable.AddTail(e);
}

void IPPacketProc(IfInfo_t* pIf, pcap_pkthdr* header, const u_char* pkt_data)
{
	if (header->caplen > 2000) {
		if (pDlg) pDlg->LogAdd(_T("[IP] 丢弃超长数据包"));
		return;
	}
	if (header->caplen >= sizeof(FrameHeader_t) + sizeof(IPHeader_t)) {
		LearnSenderIPMAC(pkt_data);
	}
	BYTE frame[2000];
	memcpy(frame, pkt_data, header->caplen);
	IPFrame_t* ipf = (IPFrame_t*)frame;
	int ipHlen = (ipf->IPHeader.Ver_HLen & 0x0F) * 4;
	if (ipHlen < 20 || header->caplen < sizeof(FrameHeader_t) + ipHlen) return;
	int ipTotalLen = ntohs(ipf->IPHeader.TotalLen);
	if (ipTotalLen < ipHlen || sizeof(FrameHeader_t) + ipTotalLen > header->caplen) {
		if (pDlg) pDlg->LogAdd(_T("[IP] 丢弃长度异常的数据包"));
		return;
	}
	int frameLen = sizeof(FrameHeader_t) + ipTotalLen;
	ULONG dstHost = ntohl(ipf->IPHeader.DstIP);
	if ((dstHost >= 0xE0000000 && dstHost <= 0xEFFFFFFF) || dstHost == 0xFFFFFFFF) {
		return; // Do not forward multicast or limited broadcast traffic.
	}

	bool isForMe = false;
	for (int i = 0; i < IfCount && !isForMe; i++) {
		for (int j = 0; j < IfInfo[i].ip.GetSize(); j++) {
			if (IfInfo[i].ip[j].IPAddr == ipf->IPHeader.DstIP) isForMe = true;
		}
	}
	if (isForMe) {
		// 处理发往本路由器的ICMP回显请求(Ping)
		if (ipf->IPHeader.Protocol == IPPROTO_ICMP && ipTotalLen >= ipHlen + (int)sizeof(ICMPHeader_t)) {
			ICMPHeader_t* icmp = (ICMPHeader_t*)((BYTE*)&ipf->IPHeader + ipHlen);
			if (icmp->Type == 8) { // Echo Request
				SendICMPEchoReply(pIf, frame);
			}
		}
		return;
	}

	CString logIP;
	logIP.Format(_T("[IP] Forwarding: %s -> %s"), IPntoa(ipf->IPHeader.SrcIP), IPntoa(ipf->IPHeader.DstIP));
	if (pDlg) pDlg->LogAdd(logIP);

	if (ipf->IPHeader.TTL <= 1) {
		ICMPPacketProc(pIf, 11, 0, frame);
		return;
	}

	UINT ifNo;
	DWORD nh = RouteLookup(ifNo, ipf->IPHeader.DstIP); // 用网络序，和RouteTable一致
	if (nh == INVALID_LONG) {
		ICMPPacketProc(pIf, 3, 0, frame);
		return;
	}

	ipf->IPHeader.TTL--;
	ipf->IPHeader.Checksum = 0;
	int hlen = (ipf->IPHeader.Ver_HLen & 0x0F) * 4;
	ipf->IPHeader.Checksum = ChecksumCompute((unsigned short*)&ipf->IPHeader, hlen);

	SendOrQueuePacket(ifNo, nh, frame, frameLen);
}

void ICMPPacketProc(IfInfo_t* pIf, BYTE type, BYTE code, const u_char* pkt)
{
	// type=11: TTL超时, type=3: 目标不可达
	IPFrame_t* orig = (IPFrame_t*)pkt;
	int ipHlen = (orig->IPHeader.Ver_HLen & 0x0F) * 4;
	int origTotalLen = ntohs(orig->IPHeader.TotalLen);
	if (ipHlen < 20 || origTotalLen < ipHlen) return;

	UINT outIfNo;
	ULONG targetIP = RouteLookup(outIfNo, orig->IPHeader.SrcIP);
	if (targetIP == INVALID_LONG) {
		// 路由查找失败，回退到接收接口发送
		outIfNo = GetInterfaceNo(pIf);
		targetIP = orig->IPHeader.SrcIP;
	}
	if (outIfNo >= (UINT)IfCount) return;

	ULONG srcIP = GetInterfaceIPForTarget(outIfNo, targetIP);
	if (srcIP == 0) return;

	BYTE buf[1500] = { 0 };
	FrameHeader_t* eth = (FrameHeader_t*)buf;
	IPHeader_t* iph = (IPHeader_t*)(buf + sizeof(FrameHeader_t));
	ICMPHeader_t* icmp = (ICMPHeader_t*)((BYTE*)iph + 20);

	eth->FrameType = htons(0x0800);

	// IP头
	iph->Ver_HLen = 0x45;
	iph->TTL = 64;
	iph->Protocol = IPPROTO_ICMP;
	iph->SrcIP = srcIP;
	iph->DstIP = orig->IPHeader.SrcIP;

	// ICMP头
	icmp->Type = type;
	icmp->Code = code;
	icmp->Id = 0;
	icmp->Sequence = 0;

	// ICMP数据: 原始IP头 + 前8字节
	int icmpDataLen = origTotalLen >= ipHlen + 8 ? ipHlen + 8 : origTotalLen;
	int ipTotal = 20 + sizeof(ICMPHeader_t) + icmpDataLen;
	iph->TotalLen = htons(ipTotal);
	iph->Checksum = 0;
	iph->Checksum = ChecksumCompute((unsigned short*)iph, 20);

	memcpy((BYTE*)icmp + sizeof(ICMPHeader_t), &orig->IPHeader, icmpDataLen);

	icmp->Checksum = 0;
	icmp->Checksum = ChecksumCompute((unsigned short*)icmp, sizeof(ICMPHeader_t) + icmpDataLen);

	SendOrQueuePacket(outIfNo, targetIP, buf, sizeof(FrameHeader_t) + ipTotal);

	CString logICMP;
	logICMP.Format(_T("[ICMP] 发送: type=%d code=%d 到 %s"), type, code, IPntoa(orig->IPHeader.SrcIP));
	if (pDlg) pDlg->LogAdd(logICMP);
}

void SendICMPEchoReply(IfInfo_t* pIf, const u_char* pkt_data)
{
	IPFrame_t* orig = (IPFrame_t*)pkt_data;
	int ipHlen = (orig->IPHeader.Ver_HLen & 0x0F) * 4;
	int ipTotalLen = ntohs(orig->IPHeader.TotalLen);
	int icmpTotalLen = ipTotalLen - ipHlen;
	if (ipHlen < 20 || ipTotalLen < ipHlen + (int)sizeof(ICMPHeader_t) ||
		sizeof(FrameHeader_t) + ipTotalLen > sizeof(BYTE) * 1500) {
		return;
	}

	UINT outIfNo;
	ULONG targetIP = RouteLookup(outIfNo, orig->IPHeader.SrcIP);
	if (targetIP == INVALID_LONG) {
		// 路由查找失败，回退到接收接口发送
		outIfNo = GetInterfaceNo(pIf);
		targetIP = orig->IPHeader.SrcIP;
	}
	if (outIfNo >= (UINT)IfCount) return;

	BYTE buf[1500] = { 0 };
	FrameHeader_t* eth = (FrameHeader_t*)buf;
	IPHeader_t* iph = (IPHeader_t*)(buf + sizeof(FrameHeader_t));
	ICMPHeader_t* icmp = (ICMPHeader_t*)((BYTE*)iph + ipHlen);

	eth->FrameType = htons(0x0800);

	// IP头 - 复制原始IP头并修改
	memcpy(iph, &orig->IPHeader, ipHlen);
	iph->TTL = 64;
	iph->SrcIP = orig->IPHeader.DstIP;
	iph->DstIP = orig->IPHeader.SrcIP;
	iph->Flag_Segment = 0;
	iph->Checksum = 0;
	iph->Checksum = ChecksumCompute((unsigned short*)iph, ipHlen);

	// ICMP头和数据
	memcpy(icmp, (BYTE*)&orig->IPHeader + ipHlen, icmpTotalLen);
	icmp->Type = 0; // Echo Reply
	icmp->Code = 0;

	// ICMP校验和
	icmp->Checksum = 0;
	icmp->Checksum = ChecksumCompute((unsigned short*)icmp, icmpTotalLen);

	SendOrQueuePacket(outIfNo, targetIP, buf, sizeof(FrameHeader_t) + ipTotalLen);

	CString logICMP;
	logICMP.Format(_T("[ICMP] 回显应答: %s -> %s"), IPntoa(iph->SrcIP), IPntoa(iph->DstIP));
	if (pDlg) pDlg->LogAdd(logICMP);
}

void ARPRequest(pcap_t* ad, UCHAR* srcMac, ULONG srcIp, ULONG dstIp)
{
	CString logARP;
	logARP.Format(_T("[ARP] 请求: 谁是 %s?"), IPntoa(dstIp));
	if (pDlg) pDlg->LogAdd(logARP);

	BYTE buf[1500] = { 0 };
	ARPFrame_t* arp = (ARPFrame_t*)buf;
	memset(arp->FrameHeader.DesMAC, 0xFF, 6);
	memcpy(arp->FrameHeader.SrcMAC, srcMac, 6);
	arp->FrameHeader.FrameType = htons(0x0806);
	arp->HardwareType = htons(1);
	arp->ProtocolType = htons(0x0800);
	arp->HLen = 6;
	arp->PLen = 4;
	arp->Operation = htons(1);
	memcpy(arp->SendHa, srcMac, 6);
	arp->SendIP = srcIp;
	arp->RecvIP = dstIp;
	SendRawPacket(ad, buf, sizeof(ARPFrame_t));
}

void SendRIPPacket(pcap_t* adhandle, int ifNo, BOOL bBroadcast)
{
	std::vector<RIPRouteEntry> entries;
	int nDirect = 0, nStatic = 0, nRIP = 0, nPoison = 0;

	POSITION pos = RouteTable.GetHeadPosition();
	while (pos) {
		RouteTable_t rt = RouteTable.GetNext(pos);
		if (rt.IfNo == (UINT)ifNo) continue; // split horizon for routes whose egress is this interface

		RIPRouteEntry re = { 0 };
		re.AddressFamily = htons(2);
		re.IPAddress = rt.DstIP;
		re.SubnetMask = rt.Mask;
		re.NextHop = 0;
		UINT metric = rt.Metric;
		if (metric > RIP_INFINITY) metric = RIP_INFINITY;
		re.Metric = htonl(metric);
		entries.push_back(re);
		if (rt.bStatic) nStatic++; else nDirect++;
	}

	pos = RIPRouteTable.GetHeadPosition();
	while (pos) {
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos);
		RIPRouteEntry re = { 0 };
		re.AddressFamily = htons(2);
		re.IPAddress = e.DstIP;
		re.SubnetMask = e.Mask;
		re.NextHop = 0;

		if (e.bInvalid || e.IfNo == (UINT)ifNo) {
			// Poison reverse: explicitly advertise learned-back routes as unreachable.
			re.Metric = htonl(RIP_INFINITY);
			nPoison++;
		}
		else {
			UINT metric = e.Metric > RIP_INFINITY ? RIP_INFINITY : e.Metric;
			re.Metric = htonl(metric);
			nRIP++;
		}
		entries.push_back(re);
	}

	CString logTxStart;
	logTxStart.Format(_T("[RIP TX] 发送RIPv2更新到 224.0.0.9 (接口%d, TTL=1)"), ifNo);
	if (pDlg) pDlg->LogAdd(logTxStart);

	if (entries.empty()) {
		CString logEmpty;
		logEmpty.Format(_T("[RIP TX] 接口%d无可通告路由"), ifNo);
		if (pDlg) pDlg->LogAdd(logEmpty);
		return;
	}

	UCHAR mcast[6] = { 0x01,0x00,0x5E,0x00,0x00,0x09 };
	size_t offset = 0;
	int packetCount = 0;
	while (offset < entries.size()) {
		BYTE pkt[1500] = { 0 };
		FrameHeader_t* eth = (FrameHeader_t*)pkt;
		IPHeader_t* iph = (IPHeader_t*)(pkt + sizeof(FrameHeader_t));
		UDPHeader_t* udp = (UDPHeader_t*)((BYTE*)iph + 20);
		RIPPacket* rip = (RIPPacket*)((BYTE*)udp + sizeof(UDPHeader_t));

		size_t remain = entries.size() - offset;
		int count = (int)(remain > 25 ? 25 : remain);
		memcpy(eth->DesMAC, mcast, 6);
		memcpy(eth->SrcMAC, IfInfo[ifNo].MACAddr, 6);
		eth->FrameType = htons(0x0800);

		int udpLen = sizeof(UDPHeader_t) + sizeof(RIPHeader) + count * sizeof(RIPRouteEntry);
		int ipTotal = 20 + udpLen;

		iph->Ver_HLen = 0x45;
		iph->TotalLen = htons(ipTotal);
		iph->TTL = 1;
		iph->Protocol = IPPROTO_UDP;
		iph->SrcIP = IfInfo[ifNo].ip[0].IPAddr;
		iph->DstIP = htonl(0xE0000009);
		iph->Checksum = 0;
		iph->Checksum = ChecksumCompute((unsigned short*)iph, 20);

		udp->SrcPort = htons(RIP_PORT);
		udp->DstPort = htons(RIP_PORT);
		udp->Len = htons(udpLen);
		udp->Checksum = 0;

		rip->header.Command = 2;
		rip->header.Version = RIP_VERSION;
		rip->header.Reserved = 0;
		memcpy(rip->entries, &entries[offset], count * sizeof(RIPRouteEntry));

		if (SendRawPacket(adhandle, pkt, sizeof(FrameHeader_t) + ipTotal) == 0) {
			packetCount++;
		}
		offset += count;
	}

	CString logTxSend;
	logTxSend.Format(_T("[RIP TX] 直连:%d 静态:%d RIP:%d 毒性逆转:%d 共%d条/%d包"),
		nDirect, nStatic, nRIP, nPoison, (int)entries.size(), packetCount);
	if (pDlg) pDlg->LogAdd(logTxSend);
}

DWORD RouteLookup(UINT& ifNo, DWORD dst)
{
	// 所有路由表统一使用网络序存储，掩码比较转为主机序以正确判断最长前缀匹配
	ULONG bestMaskHost = 0;
	DWORD nh = INVALID_LONG;
	ifNo = 0;

	POSITION pos = RouteTable.GetHeadPosition();
	while (pos) {
		RouteTable_t e = RouteTable.GetNext(pos);
		ULONG eMaskHost = ntohl(e.Mask);
		if ((dst & e.Mask) == e.DstIP && eMaskHost > bestMaskHost) {
			bestMaskHost = eMaskHost;
			nh = e.NextHop == 0 ? dst : e.NextHop;
			ifNo = e.IfNo;
		}
	}

	POSITION pos2 = RIPRouteTable.GetHeadPosition();
	while (pos2) {
		RIPRouteTableEntry e = RIPRouteTable.GetNext(pos2);
		if (!e.bInvalid && e.Metric < RIP_INFINITY) {
			ULONG eMaskHost = ntohl(e.Mask);
			if ((dst & e.Mask) == e.DstIP && eMaskHost > bestMaskHost) {
				bestMaskHost = eMaskHost;
				nh = e.NextHop;
				ifNo = e.IfNo;
			}
		}
	}
	return nh;
}

bool IPLookup(ULONG ip, UCHAR* mac)
{
	mMutex.Lock();
	POSITION pos = IP_MAC.GetHeadPosition();
	while (pos) {
		IP_MAC_t im = IP_MAC.GetNext(pos);
		if (im.IPAddr == ip) {
			memcpy(mac, im.MACAddr, 6);
			mMutex.Unlock();
			return true;
		}
	}
	mMutex.Unlock();
	return false;
}

CString IPntoa(ULONG ip)
{
	ip = ntohl(ip);
	char buf[50];
	sprintf_s(buf, "%d.%d.%d.%d", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
	return CString(buf);
}

CString MACntoa(UCHAR* mac)
{
	char buf[50];
	sprintf_s(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return CString(buf);
}

bool cmpMAC(UCHAR* a, UCHAR* b) {
	for (int i = 0; i < 6; i++) if (a[i] != b[i]) return false;
	return true;
}

void cpyMAC(UCHAR* d, UCHAR* s) {
	memcpy(d, s, 6);
}

unsigned short ChecksumCompute(unsigned short* buf, int size)
{
	unsigned long sum = 0;
	while (size > 1) {
		sum += *buf++;
		size -= 2;
	}
	if (size) sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (unsigned short)~sum;
}