/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

//sys	internetGetConnectedState(flags *uint32, reserved uint32) (connected bool) = wininet.InternetGetConnectedState

func resolveHostname(name string) (resolvedIPString string, err error) {
	maxTries := 10
	systemJustBooted := windows.DurationSinceBoot() <= time.Minute*4
	if systemJustBooted {
		maxTries *= 4
	}
	for i := 0; i < maxTries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 4)
		}
		resolvedIPString, err = resolveHostnameOnce(name)
		if err == nil {
			chainDNSRemember(name, resolvedIPString)
			return
		}
		if err == windows.WSATRY_AGAIN {
			log.Printf("Temporary DNS error when resolving %s, sleeping for 4 seconds", name)
			continue
		}
		var state uint32
		if err == windows.WSAHOST_NOT_FOUND && systemJustBooted && !internetGetConnectedState(&state, 0) {
			log.Printf("Host not found when resolving %s, but no Internet connection available, sleeping for 4 seconds", name)
			continue
		}
		// WarpAm pack 103: "not found" is often only "not yet": the DNS of
		// the machine may point into a tunnel that is still coming up. The
		// name is asked again for about twenty seconds before giving up.
		if err == windows.WSAHOST_NOT_FOUND && i < chainDNSNotFoundTries-1 {
			log.Printf("[WarpAm] Host not found when resolving %s, the network or a tunnel may still be coming up, sleeping for 4 seconds", name)
			continue
		}
		break
	}
	// WarpAm pack 103: the address found the last time is better than no
	// tunnel at all.
	if ip := chainDNSRecall(name); len(ip) != 0 {
		log.Printf("[WarpAm] %s could not be resolved (%v), the address %s found last time is used", name, err, ip)
		return ip, nil
	}
	return
}

func resolveHostnameOnce(name string) (resolvedIPString string, err error) {
	hints := windows.AddrinfoW{
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_IP,
	}
	var result *windows.AddrinfoW
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	err = windows.GetAddrInfoW(name16, nil, &hints, &result)
	if err != nil {
		return
	}
	if result == nil {
		err = windows.WSAHOST_NOT_FOUND
		return
	}
	defer windows.FreeAddrInfoW(result)
	ipv6 := ""
	for ; result != nil; result = result.Next {
		switch result.Family {
		case windows.AF_INET:
			return (net.IP)((*syscall.RawSockaddrInet4)(unsafe.Pointer(result.Addr)).Addr[:]).String(), nil
		case windows.AF_INET6:
			if len(ipv6) != 0 {
				continue
			}
			a := (*syscall.RawSockaddrInet6)(unsafe.Pointer(result.Addr))
			ipv6 = (net.IP)(a.Addr[:]).String()
			if a.Scope_id != 0 {
				ipv6 += fmt.Sprintf("%%%d", a.Scope_id)
			}
		}
	}
	if len(ipv6) != 0 {
		return ipv6, nil
	}
	err = windows.WSAHOST_NOT_FOUND
	return
}
