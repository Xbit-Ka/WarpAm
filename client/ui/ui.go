/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows-client/l18n"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/version"
)

var (
	noTrayAvailable              = false
	shouldQuitManagerWhenExiting = false
	startTime                    = time.Now()
	IsAdmin                      = false // A global, because this really is global for the process
)

func RunUI() {
	runtime.LockOSThread()
	windows.SetProcessPriorityBoost(windows.CurrentProcess(), false)
	defer func() {
		if err := recover(); err != nil {
			showErrorCustom(nil, "Panic", fmt.Sprint(err, "\n\n", string(debug.Stack())))
			panic(err)
		}
	}()

	var (
		err  error
		mtw  *ManageTunnelsWindow
		tray *Tray
	)

	for mtw == nil {
		mtw, err = NewManageTunnelsWindow()
		if err != nil {
			time.Sleep(time.Millisecond * 400)
		}
	}

	for tray == nil {
		tray, err = NewTray(mtw)
		if err != nil {
			if version.OsIsCore() {
				noTrayAvailable = true
				break
			}
			time.Sleep(time.Millisecond * 400)
		}
	}

	manager.IPCClientRegisterManagerStopping(func() {
		mtw.Synchronize(func() {
			walk.App().Exit(0)
		})
	})

	onUpdateNotification := func(updateState manager.UpdateState) {
		if updateState == manager.UpdateStateUnknown {
			return
		}
		mtw.Synchronize(func() {
			switch updateState {
			case manager.UpdateStateFoundUpdate:
				mtw.UpdateFound()
				if tray != nil && IsAdmin {
					tray.UpdateFound()
				}
			case manager.UpdateStateUpdatesDisabledUnofficialBuild:
				mtw.SetTitle(l18n.Sprintf("%s (unsigned build, no updates)", mtw.Title()))
			}
		})
	}
	manager.IPCClientRegisterUpdateFound(onUpdateNotification)
	go func() {
		updateState, err := manager.IPCClientUpdateState()
		if err == nil {
			onUpdateNotification(updateState)
		}
	}()

	if tray == nil {
		win.ShowWindow(mtw.Handle(), win.SW_MINIMIZE)
	}

	mtw.Run()
	if tray != nil {
		tray.Dispose()
	}
	mtw.Dispose()

	if shouldQuitManagerWhenExiting {
		chainLiftLockBeforeQuit()
		_, err := manager.IPCClientQuit(true)
		if err != nil {
			// Pack 85: this one message has to be shown even though the
			// program is quitting, so it goes around the hub: the user is
			// leaving a service behind that is still running.
			walk.MsgBox(nil, l18n.Sprintf("Error Exiting Warpam"), l18n.Sprintf("Unable to exit service due to: %v. You may want to stop Warpam from the service manager.", err), walk.MsgBoxIconError)
		}
	}
}

func onQuit() {
	shouldQuitManagerWhenExiting = true
	// Pack 85: from here on the program is going away, so the errors of the
	// shutdown itself no longer open windows. That queue of identical
	// windows playing itself out after Exit, with the sound of closing
	// windows, was exactly this.
	ChainNoticeStopShowing()
	walk.App().Exit(0)
}

func showError(err error, owner walk.Form) bool {
	if err == nil {
		return false
	}

	showErrorCustom(owner, l18n.Sprintf("Error"), err.Error())

	return true
}

// Pack 85: every error and warning window of the program goes through the
// hub in chainnotice.go now. It is the hub that decides whether a window is
// worth opening, so that the same text cannot pile up twenty deep while the
// chain fails over and over.
func showErrorCustom(owner walk.Form, title, message string) {
	chainNoticeError(owner, title, message)
}

func showWarningCustom(owner walk.Form, title, message string) {
	chainNoticeWarning(owner, title, message)
}
