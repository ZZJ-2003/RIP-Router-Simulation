#pragma once
#include "stdafx.h"
#include "resource.h"

class CRouterDlg : public CDialogEx
{
public:
	CRouterDlg(CWnd* pParent = nullptr);
	virtual ~CRouterDlg() {}

	enum { IDD = IDD_RIPROUTERSIMULATOR_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	HICON m_hIcon;

	CListBox		m_Log;
	CListCtrl		m_RouteList;
	CIPAddressCtrl	m_Mask;
	CIPAddressCtrl	m_Destination;
	CIPAddressCtrl	m_NextHop;
	CListBox		mc_dev;
	CListBox		m_SelectedIf;

	pcap_if_t* m_alldevs;
	pcap_if_t* m_selectdevs;

	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();

	afx_msg void OnBnClickedStart();
	afx_msg void OnBnClickedAdd();
	afx_msg void OnBnClickedDel();
	afx_msg void OnBnClickedReturn();
	afx_msg void OnBnClickedAddIf();
	afx_msg void OnDestroy();
	afx_msg void OnSettingChange(UINT uFlags, LPCTSTR lpszSection);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);

	DECLARE_MESSAGE_MAP()

public:
	void LogAdd(const CString& msg);
	void RefreshRouteTableUI();
	void InitRIP();
	void SendRIPUpdate(int ifNo = -1, BOOL bBroadcast = TRUE);
	void RIPTimerCheck();
	BOOL RIPRouteUpdate(ULONG dst, ULONG mask, ULONG nextHop, UINT metric, UINT ifNo);
	void ProcessRIPPacket(const u_char* pkt_data, UINT pkt_len, int ifNo);
};