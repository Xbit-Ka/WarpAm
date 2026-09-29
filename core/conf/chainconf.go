/* SPDX-License-Identifier: MIT
 *
 * AwgChain: plain-text configuration for chain hops.
 *
 * Upstream keeps every tunnel as <name>.conf.dpapi, encrypted with DPAPI under
 * the account of the manager service, and the manager deletes any plain .conf
 * it finds. That is fine for tunnels the interface owns, but a chain hop is
 * written and rewritten by the chain tooling (awgchain.bat, the watchdog, the
 * guard) and its services point at the plain path. Encrypting it behind our
 * back removes the very file those services load.
 *
 * A chain hop is a tunnel whose Interface section carries PinEndpointVia, the
 * field added by patch 1. For those and only those the plain file is the one
 * source of truth. Ordinary tunnels keep the upstream behaviour untouched.
 */

package conf

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// textIsChainHop reports whether wg-quick text declares PinEndpointVia.
// It works on raw text on purpose: it must stay cheap and must not fail on a
// config that the parser would reject.
func textIsChainHop(text string) bool {
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		if key == "pinendpointvia" && val != "" {
			return true
		}
	}
	return false
}

// fileIsChainHop reports whether the plain file at path belongs to a chain hop.
func fileIsChainHop(path string) bool {
	if strings.HasSuffix(path, configFileSuffix) {
		return false
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return textIsChainHop(string(bytes))
}

// chainPlainPath returns the plain path of a chain hop with the given name.
func chainPlainPath(dir, name string) (string, bool) {
	path := filepath.Join(dir, name+configFileUnencryptedSuffix)
	if fileIsChainHop(path) {
		return path, true
	}
	return "", false
}

// chainExistingConfigPath answers with the file that is really on the disk
// for this tunnel, encrypted first and plain after it.
//
// Pack 90: this is what the service of a tunnel has to be pointed at. Until
// now the path was always built with the encrypted suffix unless the plain
// file was a chain hop, so a perfectly ordinary tunnel that lies in plain
// text, which is what the button "decrypt" in the Configs section leaves
// behind, was handed to its service as <name>.conf.dpapi. The service
// answered "Unable to load configuration from path ... The system cannot
// find the file specified" and shut down at once, over and over, while the
// window showed the raise going nowhere. The list of tunnels and the loader
// both looked at both names already; only the path did not.
func chainExistingConfigPath(dir, name string) (string, bool) {
	sealed := filepath.Join(dir, name+configFileSuffix)
	if info, err := os.Stat(sealed); err == nil && info.Mode().IsRegular() {
		return sealed, true
	}
	plain := filepath.Join(dir, name+configFileUnencryptedSuffix)
	if info, err := os.Stat(plain); err == nil && info.Mode().IsRegular() {
		return plain, true
	}
	return "", false
}

// plainConfigName reports the tunnel name of a plain .conf file that has no
// encrypted counterpart, so the manager can list it like any other tunnel.
func plainConfigName(dir string, file os.DirEntry) (string, bool) {
	name := filepath.Base(file.Name())
	if len(name) <= len(configFileUnencryptedSuffix) || !strings.HasSuffix(name, configFileUnencryptedSuffix) {
		return "", false
	}
	if !file.Type().IsRegular() {
		return "", false
	}
	info, err := file.Info()
	if err != nil || info.Mode().Perm()&0444 == 0 {
		return "", false
	}
	name = strings.TrimSuffix(name, configFileUnencryptedSuffix)
	if !TunnelNameIsValid(name) {
		return "", false
	}
	if _, err := os.Stat(filepath.Join(dir, name+configFileSuffix)); err == nil {
		return "", false
	}
	return name, true
}
