/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package services

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

type Error uint32

const (
	ErrorSuccess Error = iota
	ErrorRingloggerOpen
	ErrorLoadConfiguration
	ErrorCreateWintun
	ErrorUAPIListen
	ErrorDNSLookup
	ErrorFirewall
	ErrorDeviceSetConfig
	ErrorBindSocketsToDefaultRoutes
	ErrorSetNetConfig
	ErrorDetermineExecutablePath
	ErrorTrackTunnels
	ErrorEnumerateSessions
	ErrorDropPrivileges
	ErrorRunScript
	ErrorWin32
)

func (e Error) Error() string {
	switch e {
	case ErrorSuccess:
		return "No error"
	case ErrorRingloggerOpen:
		return "Unable to open log file"
	case ErrorDetermineExecutablePath:
		return "Unable to determine path of running executable"
	case ErrorLoadConfiguration:
		return "Unable to load configuration from path"
	case ErrorCreateWintun:
		// WarpAm pack 107: said so that it is clear what to do.
		return "Windows \u043d\u0435 \u0443\u0441\u043f\u0435\u043b\u0430 \u0441\u043e\u0437\u0434\u0430\u0442\u044c \u0441\u0435\u0442\u0435\u0432\u043e\u0439 \u0430\u0434\u0430\u043f\u0442\u0435\u0440. \u041f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435 30 \u0441\u0435\u043a\u0443\u043d\u0434 \u0438 \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u0441\u043d\u043e\u0432\u0430"
	case ErrorUAPIListen:
		return "Unable to listen on named pipe"
	case ErrorDNSLookup:
		return "Unable to resolve one or more DNS hostname endpoints"
	case ErrorFirewall:
		return "Unable to enable firewall rules"
	case ErrorDeviceSetConfig:
		return "Unable to set device configuration"
	case ErrorBindSocketsToDefaultRoutes:
		return "Unable to bind sockets to default route"
	case ErrorSetNetConfig:
		return "Unable to set interface addresses, routes, dns, and/or interface settings"
	case ErrorTrackTunnels:
		return "Unable to track existing tunnels"
	case ErrorEnumerateSessions:
		return "Unable to enumerate current sessions"
	case ErrorDropPrivileges:
		return "Unable to drop privileges"
	case ErrorRunScript:
		return "An error occurred while running a configuration script command"
	case ErrorWin32:
		return "An internal Windows error has occurred"
	default:
		return "An unknown error has occurred"
	}
}

func DetermineErrorCode(err error, serviceError Error) (bool, uint32) {
	if syserr, ok := err.(syscall.Errno); ok {
		return false, uint32(syserr)
	} else if serviceError != ErrorSuccess {
		return true, uint32(serviceError)
	} else {
		return false, windows.NO_ERROR
	}
}

func CombineErrors(err error, serviceError Error) error {
	if serviceError != ErrorSuccess {
		if err != nil {
			return fmt.Errorf("%v: %w", serviceError, err)
		}
		return serviceError
	}
	return err
}
