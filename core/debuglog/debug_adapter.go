/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 110, debug feature: how long Windows makes the adapter.
 *
 * Windows sometimes takes 2 to 6 seconds to make the adapter of 100 or
 * ru-central and 0.2 seconds for the others, and the ordinary log only
 * shows "Creating adapter" and "Using Wintun" with the gap between them.
 * This feature writes what else is going on in those seconds: which
 * adapters of the program Windows still has, in what state, and whether
 * Windows is still busy installing a device.
 *
 * Points: "adapter-create-begin" (name string) and
 * "adapter-create-end" (name string, err error).
 */

package debuglog

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const adapterTick = 500 * time.Millisecond

var (
	adapterMu    sync.Mutex
	adapterBegin time.Time
	adapterDone  chan struct{}

	procNoPendingInstalls = windows.NewLazySystemDLL("cfgmgr32.dll").NewProc("CMP_WaitNoPendingInstallEvents")
)

func init() {
	Register("adapter", true, func() {
		Listen("adapter-create-begin", adapterCreateBegin)
		Listen("adapter-create-end", adapterCreateEnd)
	})
}

func adapterCreateBegin(args ...any) {
	name := fmt.Sprint(args...)
	done := make(chan struct{})
	adapterMu.Lock()
	adapterBegin = time.Now()
	adapterDone = done
	begin := adapterBegin
	adapterMu.Unlock()
	Printf("adapter %s: creating; device installs pending: %s; adapters now: %s", name, pendingInstalls(), adapterSnapshot())
	Go("adapter wait", func() {
		t := time.NewTicker(adapterTick)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				Printf("adapter %s: still creating after %d ms; device installs pending: %s; adapters now: %s", name, time.Since(begin).Milliseconds(), pendingInstalls(), adapterSnapshot())
			}
		}
	})
}

func adapterCreateEnd(args ...any) {
	name := ""
	var err error
	if len(args) > 0 {
		name = fmt.Sprint(args[0])
	}
	if len(args) > 1 {
		err, _ = args[1].(error)
	}
	adapterMu.Lock()
	begin := adapterBegin
	if adapterDone != nil {
		close(adapterDone)
		adapterDone = nil
	}
	adapterMu.Unlock()
	took := int64(-1)
	if !begin.IsZero() {
		took = time.Since(begin).Milliseconds()
	}
	if err != nil {
		Printf("adapter %s: failed after %d ms: %v; adapters now: %s", name, took, err, adapterSnapshot())
		return
	}
	Printf("adapter %s: made in %d ms; adapters now: %s", name, took, adapterSnapshot())
}

// pendingInstalls asks the device manager, without waiting, whether it is
// still installing a device. A new adapter is a new device, so a queue
// here is one possible reason for a slow adapter.
func pendingInstalls() string {
	if procNoPendingInstalls.Find() != nil {
		return "unknown"
	}
	r, _, _ := procNoPendingInstalls.Call(0)
	switch r {
	case 0:
		return "no"
	case 0x102:
		return "yes"
	default:
		return fmt.Sprintf("unknown (%d)", r)
	}
}

func operName(s winipcfg.IfOperStatus) string {
	switch s {
	case winipcfg.IfOperStatusUp:
		return "up"
	case winipcfg.IfOperStatusDown:
		return "down"
	case winipcfg.IfOperStatusNotPresent:
		return "not present"
	case winipcfg.IfOperStatusLowerLayerDown:
		return "lower layer down"
	case winipcfg.IfOperStatusDormant:
		return "dormant"
	default:
		return fmt.Sprintf("state %d", s)
	}
}

// adapterSnapshot lists the tunnel adapters Windows knows about right now.
func adapterSnapshot() string {
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryLevel(winipcfg.MibIfEntryNormalWithoutStatistics))
	if err != nil {
		return "unknown: " + err.Error()
	}
	var parts []string
	for i := range rows {
		d := strings.ToLower(rows[i].Description())
		if !strings.Contains(d, "wireguard") && !strings.Contains(d, "wintun") {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (if %d, %s)", rows[i].Alias(), rows[i].InterfaceIndex, operName(rows[i].OperStatus)))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
