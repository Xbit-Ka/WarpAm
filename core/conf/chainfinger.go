//go:build windows

/* AwgChain pack 86: the fingerprint of a configuration.
 *
 * The weekend of 27 September was spent on a question that nothing in the
 * log could answer: is the configuration in the program still the same one
 * the server was set up for. The official client had written configurations
 * for one version of the protocol while the server spoke another, and the
 * obfuscation parameters were the only visible difference between a chain
 * that worked and a chain that sent initiations into nothing. Not one line
 * of our log said which parameters had been loaded.
 *
 * The fingerprint below is a short digest of everything that has to match
 * the server: the public part of our own key, the peer keys, the endpoints,
 * the junk and magic header parameters, and the MTU. Two configurations with
 * the same fingerprint are the same agreement with the same server; a
 * fingerprint that changed after an import is the proof that the file was
 * replaced by a different one.
 *
 * Secrets never enter the digest as themselves and never leave this file.
 * The private key is hashed, so a fingerprint can be written in a log and
 * sent to anybody without giving anything away.
 */

package conf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ChainObfuscation is the obfuscation agreement of a configuration in one
// readable line. It is what has to be identical on the server.
func (config *Config) ChainObfuscation() string {
	i := &config.Interface
	parts := []string{
		fmt.Sprintf("jc=%d", i.JunkPacketCount),
		fmt.Sprintf("jmin=%d", i.JunkPacketMinSize),
		fmt.Sprintf("jmax=%d", i.JunkPacketMaxSize),
		fmt.Sprintf("s1=%d", i.InitPacketJunkSize),
		fmt.Sprintf("s2=%d", i.ResponsePacketJunkSize),
		fmt.Sprintf("s3=%d", i.CookieReplyPacketJunkSize),
		fmt.Sprintf("s4=%d", i.TransportPacketJunkSize),
		fmt.Sprintf("h1=%s", i.InitPacketMagicHeader),
		fmt.Sprintf("h2=%s", i.ResponsePacketMagicHeader),
		fmt.Sprintf("h3=%s", i.UnderloadPacketMagicHeader),
		fmt.Sprintf("h4=%s", i.TransportPacketMagicHeader),
	}
	if len(i.IPackets) != 0 {
		keys := make([]string, 0, len(i.IPackets))
		for key := range i.IPackets {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d bytes", key, len(i.IPackets[key])))
		}
	}
	if !i.HeaderProtectionKey.IsZero() {
		parts = append(parts, "header protection key set")
	}
	if len(strings.TrimSpace(i.ContentPaddingAddition)) != 0 {
		parts = append(parts, "cpa="+strings.TrimSpace(i.ContentPaddingAddition))
	}
	return strings.Join(parts, " ")
}

// ChainFingerprint is a short digest of everything that has to match the
// server. It is safe to write into a log.
func (config *Config) ChainFingerprint() string {
	sum := sha256.New()
	fmt.Fprintf(sum, "name=%s\n", strings.ToLower(strings.TrimSpace(config.Name)))
	fmt.Fprintf(sum, "self=%s\n", config.Interface.PrivateKey.Public().String())
	for i := range config.Interface.Addresses {
		fmt.Fprintf(sum, "address=%s\n", config.Interface.Addresses[i].String())
	}
	fmt.Fprintf(sum, "mtu=%d\n", config.Interface.MTU)
	fmt.Fprintf(sum, "obfuscation=%s\n", config.ChainObfuscation())

	peers := make([]string, 0, len(config.Peers))
	for i := range config.Peers {
		peer := &config.Peers[i]
		allowed := make([]string, 0, len(peer.AllowedIPs))
		for j := range peer.AllowedIPs {
			allowed = append(allowed, peer.AllowedIPs[j].String())
		}
		sort.Strings(allowed)
		peers = append(peers, fmt.Sprintf("peer=%s endpoint=%s allowed=%s psk=%v",
			peer.PublicKey.String(), peer.Endpoint.String(),
			strings.Join(allowed, ","), !peer.PresharedKey.IsZero()))
	}
	sort.Strings(peers)
	for _, line := range peers {
		fmt.Fprintf(sum, "%s\n", line)
	}

	digest := sum.Sum(nil)
	// Twelve characters are plenty to tell two configurations apart by eye
	// and short enough to sit inside a log line.
	return hex.EncodeToString(digest)[:12]
}

// ChainFingerprintLine is the sentence written into the log.
func (config *Config) ChainFingerprintLine() string {
	return fmt.Sprintf("fingerprint %s, %d peers, MTU %d, %s",
		config.ChainFingerprint(), len(config.Peers), config.Interface.MTU, config.ChainObfuscation())
}
