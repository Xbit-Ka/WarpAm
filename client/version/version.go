/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package version

const (
	// Number is the build version. It must stay a dotted number: the
	// Makefile greps it with a [0-9.] regex and updater/versions.go parses
	// every dot-separated part as an integer.
	Number = "1.1.0"

	// Display is the version shown to the user. Pack 68.
	Display = "1.10b"
)
