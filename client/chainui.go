//go:build windows

/* AwgChain - patch 8, part 2. Retires the guard from patches 4 and 6.
 *
 * Patch 4 refused to open the interface while the chain was running.
 * Patch 6 downgraded that to a question, because the manager had learnt not
 * to break a chain it did not understand.
 * Patch 8 teaches the manager the order of the hops, so the interface is now
 * a first-class way to drive the chain: one toggle on the top hop raises or
 * drops the whole thing.
 *
 * The guard therefore stays quiet. Two escape hatches remain:
 *
 *   AWGCHAIN_UI_WARN=1    ask before opening, as patch 6 did
 *   AWGCHAIN_UI_BLOCK=1   refuse outright, as patch 4 did
 */

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

var chainServiceNames = []string{
	"AwgChainTunnel$hop1-warp",
	"AwgChainTunnel$hop2-amnezia",
}

const (
	mbYesNo      = 0x00000004
	mbDefButton2 = 0x00000100
	idYes        = 6
)

func chainServiceIsRunning() (string, bool) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", false
	}
	defer windows.CloseServiceHandle(scm)
	for _, name := range chainServiceNames {
		namePtr, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		handle, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		var status windows.SERVICE_STATUS
		err = windows.QueryServiceStatus(handle, &status)
		windows.CloseServiceHandle(handle)
		if err == nil && status.CurrentState != windows.SERVICE_STOPPED {
			return name, true
		}
	}
	return "", false
}

func chainMessage(title, text string, flags uint32) int32 {
	ret, err := windows.MessageBox(0,
		windows.StringToUTF16Ptr(text),
		windows.StringToUTF16Ptr(title),
		flags)
	if err != nil {
		return 0
	}
	return ret
}

func blockUIWhenChainIsUp() {
	block := os.Getenv("AWGCHAIN_UI_BLOCK") == "1"
	warn := os.Getenv("AWGCHAIN_UI_WARN") == "1"
	if !block && !warn {
		return
	}
	name, up := chainServiceIsRunning()
	if !up {
		return
	}

	if block {
		chainMessage("AwgChain",
			"AwgChain: the VPN chain is running ("+name+").\r\n\r\n"+
				"AWGCHAIN_UI_BLOCK=1 is set, so the interface will not open.\r\n\r\n"+
				"Use awgchain.bat instead.",
			windows.MB_ICONWARNING)
		os.Exit(1)
	}

	text := "AwgChain: the VPN chain is running (" + name + ").\r\n\r\n" +
		"AWGCHAIN_UI_WARN=1 is set, so you are being asked first. Since " +
		"patch 8 the manager keeps the hops in order by itself, so this is " +
		"only here for debugging.\r\n\r\nOpen the interface anyway?"
	if chainMessage("AwgChain", text, windows.MB_ICONWARNING|mbYesNo|mbDefButton2) != idYes {
		os.Exit(1)
	}
}
