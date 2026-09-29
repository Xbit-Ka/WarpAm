/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sync"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

type ManageTunnelsWindow struct {
	walk.FormBase

	tabs        *walk.TabWidget
	tunnelsPage *TunnelsPage
	// proxyPage is the "Proxy" tab of pack 79. It follows the tunnel the
	// list on the "Tunnels" tab is standing on.
	proxyPage   *ProxyPage
	logPage     *LogPage
	updatePage  *UpdatePage
	settingsPage *SettingsPage
	updateTabIndex int

	tunnelChangedCB *manager.TunnelChangeCallback
}

const (
	manageWindowWindowClass = "AmneziaWG UI - Manage Tunnels"
	raiseMsg                = win.WM_USER + 0x3510
	aboutWireGuardCmd       = 0x37
)

var taskbarButtonCreatedMsg uint32

var initedManageTunnels sync.Once

func NewManageTunnelsWindow() (*ManageTunnelsWindow, error) {
	initedManageTunnels.Do(func() {
		walk.AppendToWalkInit(func() {
			walk.MustRegisterWindowClass(manageWindowWindowClass)
			taskbarButtonCreatedMsg = win.RegisterWindowMessage(windows.StringToUTF16Ptr("TaskbarButtonCreated"))
		})
	})

	var err error
	var disposables walk.Disposables
	defer disposables.Treat()

	font, err := walk.NewFont("Segoe UI", 9, 0)
	if err != nil {
		return nil, err
	}

	mtw := new(ManageTunnelsWindow)
	mtw.SetName("Warpam")

	err = walk.InitWindow(mtw, nil, manageWindowWindowClass, win.WS_OVERLAPPEDWINDOW, win.WS_EX_CONTROLPARENT)
	if err != nil {
		return nil, err
	}
	disposables.Add(mtw)
	win.ChangeWindowMessageFilterEx(mtw.Handle(), raiseMsg, win.MSGFLT_ALLOW, nil)
	mtw.SetPersistent(true)

	if icon, err := loadLogoIcon(32); err == nil {
		mtw.SetIcon(icon)
	}
	mtw.SetTitle("Warpam")
	mtw.SetFont(font)
	mtw.SetSize(walk.Size{675, 525})
	mtw.SetMinMaxSize(walk.Size{500, 400}, walk.Size{0, 0})
	vlayout := walk.NewVBoxLayout()
	vlayout.SetMargins(walk.Margins{5, 5, 5, 5})
	mtw.SetLayout(vlayout)
	mtw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		// "Close to tray" instead of exiting application
		*canceled = true
		if !noTrayAvailable {
			mtw.Hide()
		} else {
			win.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)
		}
	})
	mtw.VisibleChanged().Attach(func() {
		if mtw.Visible() {
			mtw.tunnelsPage.updateConfView()
			win.SetForegroundWindow(mtw.Handle())
			win.BringWindowToTop(mtw.Handle())
			mtw.logPage.scrollToBottom()
		}
	})

	if mtw.tabs, err = walk.NewTabWidget(mtw); err != nil {
		return nil, err
	}

	if mtw.tunnelsPage, err = NewTunnelsPage(); err != nil {
		return nil, err
	}
	mtw.tabs.Pages().Add(mtw.tunnelsPage.TabPage)
	mtw.tunnelsPage.CreateToolbar()

	// Pack 79: the proxy tab stands right behind the tunnels, because it
	// belongs to the tunnel that is selected there. If it cannot be built
	// the rest of the window still comes up.
	if proxyPage, proxyErr := NewProxyPage(); proxyErr == nil {
		mtw.proxyPage = proxyPage
		mtw.tabs.Pages().Add(proxyPage.TabPage)
		mtw.tunnelsPage.SetProxyPage(proxyPage)
	}

	if mtw.logPage, err = NewLogPage(); err != nil {
		return nil, err
	}
	mtw.tabs.Pages().Add(mtw.logPage.TabPage)
	if settingsPage, settingsErr := NewSettingsPage(); settingsErr == nil {
		mtw.settingsPage = settingsPage
		mtw.tabs.Pages().Add(settingsPage.TabPage)
	}

	mtw.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(mtw.onTunnelChange)
	globalState, _ := manager.IPCClientGlobalState()
	// Pack 70: seed the UI with the state the manager actually reports
	// instead of a hardcoded Unknown.
	mtw.onTunnelChange(nil, globalState, globalState, nil)

	systemMenu := win.GetSystemMenu(mtw.Handle(), false)
	if systemMenu != 0 {
		win.InsertMenuItem(systemMenu, 0, true, &win.MENUITEMINFO{
			CbSize:     uint32(unsafe.Sizeof(win.MENUITEMINFO{})),
			FMask:      win.MIIM_ID | win.MIIM_STRING | win.MIIM_FTYPE,
			FType:      win.MIIM_STRING,
			DwTypeData: windows.StringToUTF16Ptr(l18n.Sprintf("&About Warpam…")),
			WID:        uint32(aboutWireGuardCmd),
		})
		win.InsertMenuItem(systemMenu, 1, true, &win.MENUITEMINFO{
			CbSize: uint32(unsafe.Sizeof(win.MENUITEMINFO{})),
			FMask:  win.MIIM_TYPE,
			FType:  win.MFT_SEPARATOR,
		})
	}

	disposables.Spare()

	return mtw, nil
}

func (mtw *ManageTunnelsWindow) Dispose() {
	if mtw.tunnelChangedCB != nil {
		mtw.tunnelChangedCB.Unregister()
		mtw.tunnelChangedCB = nil
	}
	mtw.FormBase.Dispose()
}

func (mtw *ManageTunnelsWindow) updateProgressIndicator(globalState manager.TunnelState) {
	pi := mtw.ProgressIndicator()
	if pi == nil {
		return
	}
	switch globalState {
	case manager.TunnelStopping, manager.TunnelStarting:
		pi.SetState(walk.PIIndeterminate)
	default:
		pi.SetState(walk.PINoProgress)
	}
	if icon, err := iconForState(globalState, 16); err == nil {
		// Pack 70: Unknown clears the overlay just like Stopped, so a failed
		// state query does not leave a stale badge on the taskbar button.
		if globalState == manager.TunnelStopped || globalState == manager.TunnelUnknown {
			icon = nil
		}
		pi.SetOverlayIcon(icon, textForState(globalState, false))
	}
}

func (mtw *ManageTunnelsWindow) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	mtw.Synchronize(func() {
		mtw.updateProgressIndicator(globalState)

		if err != nil && mtw.Visible() {
			errMsg := err.Error()
			if len(errMsg) > 0 && errMsg[len(errMsg)-1] != '.' {
				errMsg += "."
			}
			showWarningCustom(mtw, l18n.Sprintf("Tunnel Error"), l18n.Sprintf("%s\n\nPlease consult the log for more information.", errMsg))
		}
	})
}

func (mtw *ManageTunnelsWindow) UpdateFound() {
	if mtw.updatePage != nil {
		return
	}
	if IsAdmin {
		mtw.SetTitle(l18n.Sprintf("%s (out of date)", mtw.Title()))
	}
	updatePage, err := NewUpdatePage()
	if err == nil {
		mtw.updatePage = updatePage
		mtw.tabs.Pages().Add(updatePage.TabPage)
		mtw.updateTabIndex = mtw.tabs.Pages().Len() - 1
	}
}

func (mtw *ManageTunnelsWindow) WndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_QUERYENDSESSION:
		if lParam == win.ENDSESSION_CLOSEAPP {
			return win.TRUE
		}
	case win.WM_ENDSESSION:
		if lParam == win.ENDSESSION_CLOSEAPP && wParam == 1 {
			walk.App().Exit(198)
		}
	case win.WM_SYSCOMMAND:
		if wParam == aboutWireGuardCmd {
			onAbout(mtw)
			return 0
		}
	case raiseMsg:
		if mtw.tunnelsPage == nil || mtw.tabs == nil {
			mtw.Synchronize(func() {
				mtw.SendMessage(msg, wParam, lParam)
			})
			return 0
		}
		if !mtw.Visible() {
			mtw.tunnelsPage.listView.SelectFirstActiveTunnel()
			if mtw.updatePage == nil {
				mtw.tabs.SetCurrentIndex(0)
			}
		}
		if mtw.updatePage != nil && mtw.updateTabIndex > 0 {
			mtw.tabs.SetCurrentIndex(mtw.updateTabIndex)
		}
		raise(mtw.Handle())
		return 0
	case taskbarButtonCreatedMsg:
		ret := mtw.FormBase.WndProc(hwnd, msg, wParam, lParam)
		go func() {
			globalState, err := manager.IPCClientGlobalState()
			if err == nil {
				mtw.Synchronize(func() {
					mtw.updateProgressIndicator(globalState)
				})
			}
		}()
		return ret
	}

	return mtw.FormBase.WndProc(hwnd, msg, wParam, lParam)
}
