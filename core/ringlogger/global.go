/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package ringlogger

import (
	"log"
	"path/filepath"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

var Global *Ringlogger

func InitGlobalLogger(tag string) error {
	if Global != nil {
		return nil
	}
	root, err := conf.RootDirectory(true)
	if err != nil {
		return err
	}
	// AwgChain pack 91: the log file is brought into the world with the
	// same descriptor the configurations and the data folder carry. It used
	// to be opened by the plain Go call, so it kept whatever it inherited
	// at the moment it was first created, and a folder that was opened for
	// the Users group later still held a log nobody could read.
	//
	// A failure here is not fatal and it is not swallowed either: the file
	// is opened anyway, and the line is printed as soon as there is a log
	// to print it into.
	path := filepath.Join(root, "log.bin")
	ensureErr := conf.ChainEnsureFile(path)
	Global, err = NewRinglogger(path, tag)
	if err != nil {
		return err
	}
	log.SetOutput(Global)
	log.SetFlags(0)
	if ensureErr != nil {
		log.Printf("[AwgChain] The log file could not be given the rights of the data folder: %v", ensureErr)
	}
	overrideWrite = globalWrite
	return nil
}

//go:linkname overrideWrite runtime.overrideWrite
var overrideWrite func(fd uintptr, p unsafe.Pointer, n int32) int32

var globalBuffer [maxLogLineLength - 1 - maxTagLength - 3]byte
var globalBufferLocation int

//go:nosplit
func globalWrite(fd uintptr, p unsafe.Pointer, n int32) int32 {
	b := (*[1 << 30]byte)(p)[:n]
	for len(b) > 0 {
		amountAvailable := len(globalBuffer) - globalBufferLocation
		amountToCopy := len(b)
		if amountToCopy > amountAvailable {
			amountToCopy = amountAvailable
		}
		copy(globalBuffer[globalBufferLocation:], b[:amountToCopy])
		b = b[amountToCopy:]
		globalBufferLocation += amountToCopy
		foundNl := false
		for i := globalBufferLocation - amountToCopy; i < globalBufferLocation; i++ {
			if globalBuffer[i] == '\n' {
				foundNl = true
				break
			}
		}
		if foundNl || len(b) > 0 {
			Global.Write(globalBuffer[:globalBufferLocation])
			globalBufferLocation = 0
		}
	}
	return n
}
