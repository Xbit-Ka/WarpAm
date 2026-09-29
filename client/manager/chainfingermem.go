//go:build windows

/* AwgChain pack 86: the memory of fingerprints that answered.
 *
 * core/conf/chainfinger.go can say what a configuration agreed with the
 * server: a short digest of the keys, the endpoints, the obfuscation
 * parameters and the MTU. On its own that digest answers nothing, because
 * there is nothing to compare it with.
 *
 * This file keeps the comparison. For every server endpoint it remembers
 * the fingerprints that ever received an answering handshake, with the
 * tunnel and the day. When a tunnel then sends initiations into nothing,
 * the log can state the one fact that was missing on the weekend of 27
 * September: a configuration to this very server did answer once, and its
 * set of parameters was not this one.
 *
 * Nothing here judges a configuration, and nothing here changes one. The
 * program does not know how many versions of the protocol exist and which
 * of them a given server speaks, so it reports differences and leaves the
 * conclusion to the person reading the log.
 *
 * The file lives in the data folder, next to the settings, so a portable
 * folder carries its memory with it.
 */

package manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainFingerRecord is one fingerprint that received an answer.
type chainFingerRecord struct {
	Endpoint    string `json:"endpoint"`
	Fingerprint string `json:"fingerprint"`
	Tunnel      string `json:"tunnel"`
	Day         string `json:"day"`
}

var chainFingerMu sync.Mutex

// chainFingerPath is the file of the memory. An unreachable data folder is
// not an error worth a line of its own here: the caller is already writing
// about something else.
func chainFingerPath() string {
	root, err := conf.ChainDataDir()
	if err != nil || len(root) == 0 {
		return ""
	}
	return filepath.Join(root, "fingerprints.json")
}

func chainFingerLoad() []chainFingerRecord {
	path := chainFingerPath()
	if len(path) == 0 {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var rows []chainFingerRecord
	if json.Unmarshal(raw, &rows) != nil {
		return nil
	}
	return rows
}

func chainFingerStore(rows []chainFingerRecord) {
	path := chainFingerPath()
	if len(path) == 0 {
		return
	}
	raw, err := json.MarshalIndent(rows, "", " ")
	if err != nil {
		return
	}
	os.WriteFile(path, raw, 0o600)
}

// chainFingerEndpoints is every endpoint a configuration points at, in
// lower case, because a host name is written differently by every export.
func chainFingerEndpoints(c *conf.Config) []string {
	out := make([]string, 0, len(c.Peers))
	for i := range c.Peers {
		endpoint := strings.ToLower(strings.TrimSpace(c.Peers[i].Endpoint.String()))
		if len(endpoint) == 0 {
			continue
		}
		out = append(out, endpoint)
	}
	return out
}

// ChainFingerInitSize is the size of the initiation packet this
// configuration sends: the 148 bytes of the protocol plus the junk of S1.
// It is the number a server compares against, and a mismatch is exactly
// what the silent handshakes of 26 September were.
func ChainFingerInitSize(c *conf.Config) int {
	return 148 + int(c.Interface.InitPacketJunkSize)
}

// ChainFingerRemember writes down that this configuration was answered.
// One record per endpoint and fingerprint, so the file stays short no
// matter how often a tunnel is raised.
func ChainFingerRemember(name string, c *conf.Config) {
	if c == nil {
		return
	}
	fingerprint := c.ChainFingerprint()
	day := time.Now().Format("2006-01-02")

	chainFingerMu.Lock()
	defer chainFingerMu.Unlock()

	rows := chainFingerLoad()
	changed := false
	for _, endpoint := range chainFingerEndpoints(c) {
		found := false
		for i := range rows {
			if rows[i].Endpoint == endpoint && rows[i].Fingerprint == fingerprint {
				rows[i].Tunnel = name
				rows[i].Day = day
				found = true
				break
			}
		}
		if found {
			continue
		}
		rows = append(rows, chainFingerRecord{Endpoint: endpoint, Fingerprint: fingerprint, Tunnel: name, Day: day})
		changed = true
	}
	if changed || len(rows) != 0 {
		chainFingerStore(rows)
	}
}

// chainFingerAnswered lists what is remembered about these endpoints.
func chainFingerAnswered(endpoints []string) []chainFingerRecord {
	chainFingerMu.Lock()
	rows := chainFingerLoad()
	chainFingerMu.Unlock()

	out := make([]chainFingerRecord, 0, 2)
	for i := range rows {
		for _, endpoint := range endpoints {
			if rows[i].Endpoint == endpoint {
				out = append(out, rows[i])
				break
			}
		}
	}
	return out
}

// chainFingerNeighbours are the other configurations of this machine that
// point at the same endpoint. They are read through the store, so an
// encrypted configuration is read exactly like a plain one.
func chainFingerNeighbours(name string, endpoints []string) map[string]string {
	out := map[string]string{}
	names, err := conf.ListConfigNames()
	if err != nil {
		return out
	}
	for _, other := range names {
		if strings.EqualFold(other, name) {
			continue
		}
		stored, loadErr := conf.LoadFromName(other)
		if loadErr != nil || stored == nil {
			continue
		}
		shared := false
		for _, endpoint := range chainFingerEndpoints(stored) {
			for _, mine := range endpoints {
				if endpoint == mine {
					shared = true
					break
				}
			}
			if shared {
				break
			}
		}
		if shared {
			out[other] = stored.ChainFingerprint()
		}
	}
	return out
}

// ChainFingerCompareLines is what the log prints when a server stays
// silent. Every line is a fact: what this configuration agreed to, what
// the other configurations to the same server agreed to, and which set of
// parameters ever received an answer from it.
func ChainFingerCompareLines(name string, c *conf.Config) []string {
	if c == nil {
		return nil
	}
	fingerprint := c.ChainFingerprint()
	endpoints := chainFingerEndpoints(c)
	lines := make([]string, 0, 4)

	for other, otherPrint := range chainFingerNeighbours(name, endpoints) {
		if otherPrint == fingerprint {
			lines = append(lines, fmt.Sprintf("%s and %s point at the same server with the same fingerprint %s", name, other, fingerprint))
			continue
		}
		lines = append(lines, fmt.Sprintf("%s points at the same server as %s, and their fingerprints differ: %s against %s", name, other, fingerprint, otherPrint))
	}

	answered := chainFingerAnswered(endpoints)
	mine := false
	for i := range answered {
		if answered[i].Fingerprint == fingerprint {
			mine = true
			break
		}
	}
	switch {
	case mine:
		lines = append(lines, fmt.Sprintf("the fingerprint %s of %s did receive an answer from this server before, so the parameters are not the difference this time", fingerprint, name))
	case len(answered) != 0:
		for i := range answered {
			lines = append(lines, fmt.Sprintf("this server answered the fingerprint %s of %s on %s, and %s carries %s", answered[i].Fingerprint, answered[i].Tunnel, answered[i].Day, name, fingerprint))
		}
	default:
		lines = append(lines, fmt.Sprintf("no configuration of this machine ever received an answer from this server, so there is nothing to compare the fingerprint %s with", fingerprint))
	}
	return lines
}
