/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var cachedConfigFileDir string
var cachedRootDir string

func tunnelConfigurationsDirectory() (string, error) {
	if cachedConfigFileDir != "" {
		return cachedConfigFileDir, nil
	}
	root, err := RootDirectory(true)
	if err != nil {
		return "", err
	}
	c := filepath.Join(root, "Configurations")
	err = os.Mkdir(c, os.ModeDir|0700)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	cachedConfigFileDir = c
	return cachedConfigFileDir, nil
}

// PresetRootDirectory causes RootDirectory() to not try any automatic deduction, and instead
// uses what's passed to it. This isn't used by amneziawg-windows, but is useful for external
// consumers of our libraries who might want to do strange things.
func PresetRootDirectory(root string) {
	cachedRootDir = root
}

func RootDirectory(create bool) (string, error) {
	if cachedRootDir != "" {
		return cachedRootDir, nil
	}
	// AwgChain pack 86: the root is the folder of the running executable and
	// nothing else. No known folder is consulted and no earlier location is
	// searched, so the program always reads the files that lie next to it and
	// a service started as SYSTEM lands in the same place as the window.
	root, err := ChainProgramDir()
	if err != nil {
		return "", err
	}
	if !create {
		return filepath.Join(root, "Data"), nil
	}
	root16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", err
	}

	// The root is the folder of the program, so it already exists and keeps
	// whatever rights it has. Only Data below it is given a descriptor of its
	// own, a few lines further down.
	err = windows.CreateDirectory(root16, nil)
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return "", err
	}

	// AwgChain pack 91: the string is not written here any more. It is the
	// one from chainseal.go, and it carries the wish of the settings, so a
	// Data folder that has to be made again while the program runs is born
	// with the rights the rest of the folder already has instead of being
	// born strict and repaired a moment later.
	dataDirectorySd, err := windows.SecurityDescriptorFromString(ChainFolderSdText(ChainAclSid()))
	if err != nil {
		return "", err
	}
	dataDirectorySa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: dataDirectorySd,
	}

	data := filepath.Join(root, "Data")
	data16, err := windows.UTF16PtrFromString(data)
	if err != nil {
		return "", err
	}
	var dataHandle windows.Handle
	for {
		err = windows.CreateDirectory(data16, dataDirectorySa)
		if err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return "", err
		}
		dataHandle, err = windows.CreateFile(data16, windows.READ_CONTROL|windows.WRITE_OWNER|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY, 0)
		if err != nil && err != windows.ERROR_FILE_NOT_FOUND {
			return "", err
		}
		if err == nil {
			break
		}
	}
	defer windows.CloseHandle(dataHandle)
	var fileInfo windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(dataHandle, &fileInfo)
	if err != nil {
		return "", err
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return "", errors.New("Data directory is actually a file")
	}
	if fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", errors.New("Data directory is reparse point")
	}
	buf := make([]uint16, windows.MAX_PATH+4)
	for {
		bufLen, err := windows.GetFinalPathNameByHandle(dataHandle, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if bufLen < uint32(len(buf)) {
			break
		}
		buf = make([]uint16, bufLen)
	}
	if !strings.EqualFold(`\\?\`+data, windows.UTF16ToString(buf[:])) {
		return "", errors.New("Data directory jumped to unexpected location")
	}
	err = windows.SetKernelObjectSecurity(dataHandle, windows.DACL_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, dataDirectorySd)
	if err != nil {
		return "", err
	}
	cachedRootDir = data
	return cachedRootDir, nil
}
