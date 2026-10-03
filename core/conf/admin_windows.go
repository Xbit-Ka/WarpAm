/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"golang.org/x/sys/windows/registry"

	"github.com/amnezia-vpn/amneziawg-windows/v3/brand"
)

// WarpAm pack 94: the key of this program, not the one of the real
// AmneziaWG client.
const adminRegKey = brand.RegistryKey

var adminKey registry.Key

func openAdminKey() (registry.Key, error) {
	if adminKey != 0 {
		return adminKey, nil
	}
	var err error
	adminKey, err = registry.OpenKey(registry.LOCAL_MACHINE, adminRegKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, err
	}
	return adminKey, nil
}

func AdminBool(name string) bool {
	key, err := openAdminKey()
	if err != nil {
		return false
	}
	val, _, err := key.GetIntegerValue(name)
	if err != nil {
		return false
	}
	return val != 0
}
