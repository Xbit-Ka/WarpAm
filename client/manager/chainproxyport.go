//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 80: the port of a proxy is checked before the tunnel is
 * raised.
 *
 * Until now a tunnel came up, the proxy tried to take its port, found it
 * busy and wrote one line into the log. The window said the tunnel was
 * active, the browser said "connection refused" and nothing on screen
 * connected the two. Now the answer comes before anything is raised: the
 * tunnel stays down and the refusal names the port.
 *
 * The test is an ordinary listen on the very address the proxy would use.
 * It finds our own running proxy and any foreign program alike, which is
 * the whole point: the question is not "is this port ours" but "can this
 * proxy have it".
 */

package manager

import (
	"fmt"
	"net"
	"strings"
)

// chainProxyPortFree tries to hold the address the proxy of this tunnel
// would listen on. It gives the port straight back, so the proxy itself
// can take it a moment later.
func chainProxyPortFree(settings ChainTunnelSettings) error {
	address := chainProxyBindAddress(settings)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return listener.Close()
}

// ChainProxyPortConflict answers whether the proxy of this tunnel can have
// its port. An empty answer means it can, or that this tunnel has no proxy
// at all and there is nothing to ask about.
//
// The tunnel that already holds the port is named when it is one of ours,
// because "port 1080 is busy" is a great deal less useful than "port 1080
// is already taken by 100p".
func ChainProxyPortConflict(name string) error {
	settings := ChainSettingsFor(name)
	if !settings.Proxy {
		return nil
	}
	// A proxy that is already running for this very tunnel holds the
	// port itself. Raising the tunnel again must not be refused because
	// of its own listener.
	for _, proxy := range ChainProxyState() {
		if strings.EqualFold(proxy.Leaf, name) {
			return nil
		}
	}
	if err := chainProxyPortFree(settings); err == nil {
		return nil
	}

	address := chainProxyBindAddress(settings)
	for _, proxy := range ChainProxyState() {
		if !strings.EqualFold(proxy.Address, address) {
			continue
		}
		// Pack 82: shown in a window, so Russian. The log stays English.
		return fmt.Errorf("\u041f\u043e\u0440\u0442 %d \u0443\u0436\u0435 \u0437\u0430\u043d\u044f\u0442 \u0442\u0443\u043d\u043d\u0435\u043b\u0435\u043c %s. \u0417\u0430\u0434\u0430\u0439\u0442\u0435 \u044d\u0442\u043e\u043c\u0443 \u0442\u0443\u043d\u043d\u0435\u043b\u044e \u0441\u0432\u043e\u0439 \u043f\u043e\u0440\u0442 \u043d\u0430 \u0432\u043a\u043b\u0430\u0434\u043a\u0435 \u00ab\u041f\u0440\u043e\u043a\u0441\u0438\u00bb.",
			settings.Port(), proxy.Leaf)
	}
	return fmt.Errorf("\u041f\u043e\u0440\u0442 %d \u0443\u0436\u0435 \u0437\u0430\u043d\u044f\u0442 \u0434\u0440\u0443\u0433\u043e\u0439 \u043f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u043e\u0439. \u0417\u0430\u0434\u0430\u0439\u0442\u0435 \u044d\u0442\u043e\u043c\u0443 \u0442\u0443\u043d\u043d\u0435\u043b\u044e \u0441\u0432\u043e\u0439 \u043f\u043e\u0440\u0442 \u043d\u0430 \u0432\u043a\u043b\u0430\u0434\u043a\u0435 \u00ab\u041f\u0440\u043e\u043a\u0441\u0438\u00bb.",
		settings.Port())
}
