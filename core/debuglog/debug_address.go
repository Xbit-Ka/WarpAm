/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110, debug feature: when the address of a new adapter can
 * be used.
 *
 * A tunnel that rides on a freshly raised one lost about 3 seconds every
 * time, always the same 3 seconds. The suspect is the duplicate address
 * check of Windows, which keeps a new address tentative and unusable for
 * a while. This feature writes the state of every address of the adapter
 * every 100 ms until all of them are preferred, so the log shows whether
 * pack 110 really took the wait away.
 *
 * Point: "addresses-set" (family winipcfg.AddressFamily, luid winipcfg.LUID,
 * name string).
 */

package debuglog

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const (
	addressTick  = 100 * time.Millisecond
	addressWatch = 8 * time.Second
)

func init() {
	Register("address", true, func() {
		Listen("addresses-set", addressesSet)
	})
}

func dadName(s winipcfg.DadState) string {
	switch s {
	case winipcfg.DadStateInvalid:
		return "invalid"
	case winipcfg.DadStateTentative:
		return "tentative"
	case winipcfg.DadStateDuplicate:
		return "duplicate"
	case winipcfg.DadStateDeprecated:
		return "deprecated"
	case winipcfg.DadStatePreferred:
		return "preferred"
	default:
		return fmt.Sprintf("state %d", s)
	}
}

func addressesSet(args ...any) {
	if len(args) < 3 {
		return
	}
	family, ok1 := args[0].(winipcfg.AddressFamily)
	luid, ok2 := args[1].(winipcfg.LUID)
	name := fmt.Sprint(args[2])
	if !ok1 || !ok2 {
		return
	}
	fam := "v4"
	if family == windows.AF_INET6 {
		fam = "v6"
	}
	dad := "unknown"
	if ipif, err := luid.IPInterface(family); err == nil {
		dad = fmt.Sprint(ipif.DadTransmits)
	}
	Printf("address %s %s: set, duplicate address check tries: %s", name, fam, dad)
	begin := time.Now()
	Go("address watch", func() {
		seen := map[string]winipcfg.DadState{}
		for time.Since(begin) < addressWatch {
			rows, err := winipcfg.GetUnicastIPAddressTable(family)
			if err != nil {
				Printf("address %s %s: the table could not be read: %v", name, fam, err)
				return
			}
			all := true
			count := 0
			for i := range rows {
				if rows[i].InterfaceLUID != luid {
					continue
				}
				count++
				ip := rows[i].Address.IP().String()
				state := rows[i].DadState
				if old, ok := seen[ip]; !ok || old != state {
					seen[ip] = state
					Printf("address %s %s: %s is %s after %d ms", name, fam, ip, dadName(state), time.Since(begin).Milliseconds())
				}
				if state != winipcfg.DadStatePreferred {
					all = false
				}
			}
			if count > 0 && all {
				return
			}
			time.Sleep(addressTick)
		}
		var still []string
		for ip, state := range seen {
			if state != winipcfg.DadStatePreferred {
				still = append(still, ip+" "+dadName(state))
			}
		}
		Printf("address %s %s: not all preferred after %d ms: %s", name, fam, addressWatch.Milliseconds(), strings.Join(still, ", "))
	})
}
