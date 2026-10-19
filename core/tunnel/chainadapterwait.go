/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 113: the adapter is made only when the old one is gone.
 *
 * The GUID of the adapter comes from the name and the keys of the tunnel
 * (deterministicguid.go), so it is the same at every start. When a tunnel
 * is switched on again right after it was switched off, Windows may still
 * be removing its old adapter. Wintun then waits 15 seconds for the new
 * device and fails with "Timed out waiting for device query", and the log
 * of 8.10 shows it twice. Wintun cannot take away an adapter that another
 * process made, so the only cure is to wait until Windows is done with it.
 */

package tunnel

import (
	"log"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const (
	// chainOldAdapterLimit is how long the start waits for the old
	// adapter to go. After that the adapter is asked for as before.
	chainOldAdapterLimit = 20 * time.Second
	// chainOldAdapterStep is how often Windows is asked.
	chainOldAdapterStep = 250 * time.Millisecond
)

// chainOldAdapterPresent answers whether Windows still has an adapter
// with the name or the GUID of this tunnel, and gives its index.
func chainOldAdapterPresent(name string, guid *windows.GUID) (bool, uint32) {
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryLevel(winipcfg.MibIfEntryNormalWithoutStatistics))
	if err != nil {
		return false, 0
	}
	for i := range rows {
		if strings.EqualFold(rows[i].Alias(), name) || (guid != nil && rows[i].InterfaceGUID == *guid) {
			return true, rows[i].InterfaceIndex
		}
	}
	return false, 0
}

// chainWaitOldAdapter waits, at most chainOldAdapterLimit, until the old
// adapter of the tunnel is gone. It says false when it is still there.
func chainWaitOldAdapter(config *conf.Config) bool {
	guid := deterministicGUID(config)
	present, index := chainOldAdapterPresent(config.Name, guid)
	if !present {
		return true
	}
	log.Printf("[WarpAm] The old adapter of %s (if %d) is still being removed by Windows, waiting up to %v before making a new one", config.Name, index, chainOldAdapterLimit)
	begin := time.Now()
	for time.Since(begin) < chainOldAdapterLimit {
		time.Sleep(chainOldAdapterStep)
		if present, _ = chainOldAdapterPresent(config.Name, guid); !present {
			log.Printf("[WarpAm] The old adapter of %s is gone after %d ms, the new one is made now", config.Name, time.Since(begin).Milliseconds())
			return true
		}
	}
	log.Printf("[WarpAm] The old adapter of %s is still there after %v, the new one is asked for anyway", config.Name, chainOldAdapterLimit)
	return false
}
