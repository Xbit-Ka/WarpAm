/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package version

import (
	"fmt"

	"golang.zx2c4.com/wintun"
)

func WintunVersion() string {
	wintunVersion, err := wintun.RunningVersion()
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
}
