/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 113: a cascade stop goes on only when the adapter is gone.
 *
 * On 8.10 100, Elena and ru-central were stopped one after another at
 * 18:57:55, and a minute later Windows still had the adapters of 100 and
 * the others. The next start of the same tunnel then waited 15 seconds
 * for Wintun and failed. Now every step of a cascade stop waits, with a
 * limit, until Windows has really taken the adapter away, and the log says
 * how long that took.
 */

package manager

import (
	"log"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

const (
	// chainAdapterGoneLimit is how long one step of a cascade stop waits
	// for the adapter to go.
	chainAdapterGoneLimit = 15 * time.Second
	// chainAdapterGoneStep is how often Windows is asked.
	chainAdapterGoneStep = 250 * time.Millisecond
)

// chainAdapterPresent answers whether Windows has an adapter by this name.
func chainAdapterPresent(name string) bool {
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryLevel(winipcfg.MibIfEntryNormalWithoutStatistics))
	if err != nil {
		return false
	}
	for i := range rows {
		if strings.EqualFold(rows[i].Alias(), name) {
			return true
		}
	}
	return false
}

// ChainWaitAdapterGone waits until the adapter of the tunnel is gone, at
// most chainAdapterGoneLimit, and writes how long it took. It says false
// when the adapter is still there. A tunnel with no adapter costs nothing.
func ChainWaitAdapterGone(name string) bool {
	if !chainAdapterPresent(name) {
		return true
	}
	begin := time.Now()
	for time.Since(begin) < chainAdapterGoneLimit {
		time.Sleep(chainAdapterGoneStep)
		if !chainAdapterPresent(name) {
			log.Printf("[WarpAm] The adapter of %s is removed in %d ms", name, time.Since(begin).Milliseconds())
			return true
		}
	}
	log.Printf("[WarpAm] The adapter of %s is still present after %v, going on anyway", name, chainAdapterGoneLimit)
	return false
}
