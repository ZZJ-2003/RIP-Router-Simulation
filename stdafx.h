#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#include "targetver.h"
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#define _AFX_ALL_WARNINGS

#include <afxwin.h>
#include <afxext.h>
#include <afxdisp.h>
#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>
#endif
#include <afxcontrolbars.h>
#include <afxsock.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <pcap.h>

#include <stdlib.h>
#include <string.h>
#include <atlconv.h>
#include <afxdlgs.h>
#include <string>
#include <afxmt.h>
#include <afxtempl.h>
#include <vector>

#pragma comment(lib, "Iphlpapi.lib")

#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

#define INVALID_LONG 0xFFFFFFFF
#define MAX_IF			8
#define RIP_PORT        520
#define RIP_VERSION     2
#define RIP_INFINITY    16
#define RIP_UPDATE_TIMER_ID 1001
#define RIP_UPDATE_INTERVAL 3000
#define RIP_INVALID_TIMER 18000
#define RIP_FLUSH_TIMER  24000
#define ARP_RETRY_INTERVAL 500
#define ARP_MAX_RETRIES 5
#define ARP_TIMER_BASE 10000