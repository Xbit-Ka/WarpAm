//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 103: the last address of every server name is remembered.
 *
 * A tunnel whose server is written as a name stopped at once when the DNS
 * did not answer, for example while another tunnel was still coming up.
 * Every name that resolves is written down here, one "name address" per
 * line, and the address is used when the name does not resolve later.
 */

package conf

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// chainDNSNotFoundTries is how often "host not found" is asked again, four
// seconds apart.
const chainDNSNotFoundTries = 5

var chainDNSMemoMu sync.Mutex

func chainDNSMemoPath() (string, error) {
	root, err := RootDirectory(false)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "dnsmemo.txt"), nil
}

func chainDNSMemoRead(path string) map[string]string {
	book := make(map[string]string)
	raw, err := os.ReadFile(path)
	if err != nil {
		return book
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			book[strings.ToLower(fields[0])] = fields[1]
		}
	}
	return book
}

// chainDNSRemember writes down the address of a name that has resolved.
func chainDNSRemember(name, ip string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if len(name) == 0 || len(ip) == 0 || net.ParseIP(strings.Trim(name, "[]")) != nil {
		return
	}
	chainDNSMemoMu.Lock()
	defer chainDNSMemoMu.Unlock()
	path, err := chainDNSMemoPath()
	if err != nil {
		return
	}
	book := chainDNSMemoRead(path)
	if book[name] == ip {
		return
	}
	book[name] = ip
	var b strings.Builder
	for n, a := range book {
		b.WriteString(n + " " + a + "\r\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		log.Printf("[WarpAm] The address of %s is not remembered: %v", name, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		log.Printf("[WarpAm] The address of %s is not remembered: %v", name, err)
	}
}

// chainDNSRecall gives the address found the last time, or an empty string.
func chainDNSRecall(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	chainDNSMemoMu.Lock()
	defer chainDNSMemoMu.Unlock()
	path, err := chainDNSMemoPath()
	if err != nil {
		return ""
	}
	return chainDNSMemoRead(path)[name]
}
