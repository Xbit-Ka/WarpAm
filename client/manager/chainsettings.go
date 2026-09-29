/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 56: the settings book, second edition.
 *
 * New since pack 55:
 *   * every tunnel carries a lock mode: normal, strict or paranoid
 *   * the program remembers the last tunnel raised by hand (LastTunnel)
 *   * RaiseMode replaces the single RaiseOnStart box: none, last, selected
 *   * the "start the program with Windows" box switches the start type of
 *     the AwgChainManager service instead of writing a Run key
 *
 * The file is written by the service only, so the interface always asks the
 * manager over the pipe instead of touching it directly.
 */

package manager

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// The three lock modes. They are stored as plain text so an older build can
// still read the file and simply fall back to the normal mode.
const (
	ChainLockModeNormal   = "normal"
	ChainLockModeStrict   = "strict"
	ChainLockModeParanoid = "paranoid"
)

// AwgChain pack 68 (I1): the lock engine. Until now the choice was made
// by two hidden files in C:\ProgramData\AwgChain, no-inproc-lock and
// no-autoguard, which nobody could see and nothing reported. There are
// two engines left and they live in the settings file:
//
//   service  the manager service installs the WFP filters itself. This
//            is the default and the only engine that protects.
//   off      no kill switch at all.
//
// The separate awgchain-guard.exe engine of the early packs is gone.
const (
	ChainLockEngineService = "service"
	ChainLockEngineOff     = "off"
)

// The three ways to raise something when Windows starts.
const (
	ChainRaiseNone     = "none"
	ChainRaiseLast     = "last"
	ChainRaiseSelected = "selected"
)

// ChainTunnelSettings is what the boxes of one tunnel say.
type ChainTunnelSettings struct {
	KillSwitch bool
	BlockIPv6  bool
	AllowLAN   bool
	// LockMode is empty in files written by pack 55; empty means normal.
	LockMode string
	// ------------------------------------------------------------------
	// The local proxy. Pack 74 put it here half way and kept protocol,
	// port, binding and login in the settings of the program; pack 79
	// finished the move. Every field below belongs to this tunnel and to
	// nothing else, and none of them means anything while Proxy is false.
	// ------------------------------------------------------------------

	// Proxy asks for a local proxy while this tunnel is up.
	Proxy bool
	// ProxyProtocol is "socks5", "http" or "both". Empty means socks5.
	ProxyProtocol string
	// ProxyPort is the port the proxy of this tunnel listens on. Zero
	// means 1080. Two tunnels may carry the same number; the second one
	// to come up will not get the port and says so in the log.
	ProxyPort int
	// ProxyBind is "loopback" (only this machine) or "lan" (the machines
	// of the local network may use the proxy too). Empty means loopback.
	ProxyBind string
	// ProxyUser and ProxyPassHash are the login of the local network
	// mode. The password itself is never written down: the file keeps
	// the SHA-256 of "user:password". In the loopback mode both are
	// empty, and the proxy asks for nothing.
	ProxyUser     string
	ProxyPassHash string
	// ProxyOnDown says what happens to the port when the tunnel is not
	// there: "error" answers every request with an honest refusal,
	// "close" takes the port down so the program sees "connection
	// refused". Empty means error.
	ProxyOnDown string
	// ProxyGrace is how many seconds a lost handshake is tolerated before
	// the open connections are cut. Zero means cut at once.
	ProxyGrace int
	// ProxySplit makes the tunnel carry only the traffic of the proxy:
	// no system routes, no system DNS, the address of the machine on the
	// internet does not change. False means the tunnel works as usual and
	// the proxy is only a local door into it.
	ProxySplit bool
}

// Protocol returns the proxy protocol of this tunnel, filling in the
// default.
func (s ChainTunnelSettings) Protocol() string {
	switch strings.ToLower(strings.TrimSpace(s.ProxyProtocol)) {
	case ChainProxyProtoHTTP:
		return ChainProxyProtoHTTP
	case ChainProxyProtoBoth:
		return ChainProxyProtoBoth
	}
	return ChainProxyProtoSocks5
}

// Bind returns "loopback" or "lan".
func (s ChainTunnelSettings) Bind() string {
	if strings.EqualFold(strings.TrimSpace(s.ProxyBind), ChainProxyBindLAN) {
		return ChainProxyBindLAN
	}
	return ChainProxyBindLoopback
}

// OnDown returns "error" or "close".
func (s ChainTunnelSettings) OnDown() string {
	if strings.EqualFold(strings.TrimSpace(s.ProxyOnDown), ChainProxyDownClose) {
		return ChainProxyDownClose
	}
	return ChainProxyDownError
}

// Port is the port of this proxy, with the default filled in.
func (s ChainTunnelSettings) Port() int {
	if s.ProxyPort > 0 && s.ProxyPort < 65536 {
		return s.ProxyPort
	}
	return ChainProxyDefaultPort
}

// Normalised is the rule of pack 79: a setting that the interface greys
// out must not survive in the file. The whole proxy is derived from one
// box, and the login is derived from the binding, so a combination that
// cannot happen on screen cannot happen in the book either.
//
// This is what heals the file written by pack 74: a tunnel could be saved
// with Proxy off and ProxySplit on, the manager read that as an ordinary
// tunnel and armed the lock, while the tunnel service read the same file
// as "separate" and installed no routes at all.
func (s ChainTunnelSettings) Normalised() ChainTunnelSettings {
	s.LockMode = s.Mode()
	if !s.Proxy {
		s.ProxyProtocol = ""
		s.ProxyPort = 0
		s.ProxyBind = ""
		s.ProxyUser = ""
		s.ProxyPassHash = ""
		s.ProxyOnDown = ""
		s.ProxyGrace = 0
		s.ProxySplit = false
		return s
	}
	s.ProxyProtocol = s.Protocol()
	s.ProxyPort = s.Port()
	s.ProxyBind = s.Bind()
	s.ProxyOnDown = s.OnDown()
	if s.ProxyGrace < 0 {
		s.ProxyGrace = 0
	}
	if s.ProxyGrace > 3600 {
		s.ProxyGrace = 3600
	}
	s.ProxyUser = strings.TrimSpace(s.ProxyUser)
	s.ProxyPassHash = strings.TrimSpace(s.ProxyPassHash)
	if s.ProxyBind != ChainProxyBindLAN {
		s.ProxyUser = ""
		s.ProxyPassHash = ""
	}
	return s
}

// Mode returns the lock mode, filling in the default for old files.
func (s ChainTunnelSettings) Mode() string {
	switch strings.ToLower(s.LockMode) {
	case ChainLockModeStrict:
		return ChainLockModeStrict
	case ChainLockModeParanoid:
		return ChainLockModeParanoid
	}
	return ChainLockModeNormal
}

// ChainGlobalSettings is what the Settings tab says about the whole program.
type ChainGlobalSettings struct {
	// RaiseOnStart is kept so a settings file from pack 55 still makes sense.
	RaiseOnStart   bool
	RaiseMode      string
	RaiseTunnel    string
	LastTunnel     string
	AutoStart      bool
	// AutoStartSet tells a wish from a default. Pack 67 keeps the wish in the
	// file, because Exit deletes the service and the start type with it.
	AutoStartSet   bool
	LiftLockOnQuit bool
	// LockMode is the lock mode for the whole program. Empty means the
	// per tunnel value written by pack 56 is used instead.
	LockMode       string
	// LockEngine is "service" or "off" (pack 68). Empty means service,
	// so a settings file from an older pack keeps its protection.
	LockEngine     string

	// Pack 86, the three fields of the portable mode.
	//
	// EncryptConfigs is the "encrypt the configurations" box. It is on by
	// default, and an old settings file has no such key, which is why the
	// wish is kept in EncryptConfigsSet: without it a file written before
	// this pack would read as "the user switched encryption off".
	EncryptConfigs    bool
	EncryptConfigsSet bool

	// DpapiVerifier held the salt and the hash of a password. Pack 91
	// removed the password: it was never a key, Windows encrypts the files
	// for the system account and no password could change that, so the
	// only thing it ever did was stand between the user and his own
	// files. The field is kept so that a settings file written by pack 86
	// still reads, and the manager wipes it at the first start.
	DpapiVerifier string

	// InstallSealed is the flag of pack 91: the installation was closed
	// from changes by the button in the Configs section. Everything under
	// the data folder is encrypted and strict, the two buttons that could
	// undo that are gone from the window, and the only way back is to
	// remove the program with its installer. The flag lives in
	// settings.json inside the data folder, which is the folder the
	// installer deletes, so removing the program really does clear it.
	InstallSealed bool

	// DataAclOpen says that the strict descriptor of the Data folder has
	// been opened for the account named in DataAclSid. The folder is born
	// strict in both modes; this is the switch the button in the settings
	// flips, and the manager puts the same descriptor back at every start,
	// so the button and the folder can never tell two different stories.
	DataAclOpen bool
	DataAclSid  string
	// UpTunnels is the set of tunnels that are meant to be up, by name.
	// Pack 80: several tunnels can run at once now, so one LastTunnel is
	// not enough to put the machine back the way the user left it. The
	// list is kept by ChainNoteLastTunnel and ChainNoteTunnelDown, the
	// same two places that keep LastTunnelUp, and the start-up raise
	// walks it after it has raised the main tunnel.
	UpTunnels []string

	// LastTunnelUp says whether LastTunnel is meant to be up. Pack 69
	// (J1): it is set when a tunnel is raised and cleared when the
	// user switches one off by hand, because "raise the last tunnel"
	// used to bring back a tunnel that had deliberately been turned
	// off minutes earlier. A settings file from an older pack has the
	// field false, so the first raise after the update writes it.
	LastTunnelUp   bool

	// Pack 79: the proxy is not a setting of the program any more. The
	// protocol, the port, the binding, the login and the behaviour when
	// the tunnel falls belong to the tunnel that carries the proxy, so
	// the fields pack 74 put here are gone. An old file keeps them as
	// unknown keys, they are read by nobody and disappear with the next
	// save: every tunnel is set up once, by hand, and no combination is
	// inherited from a setting that used to be shared.
}

// The values of the proxy settings, as they are written in the file.
const (
	ChainProxyProtoSocks5 = "socks5"
	ChainProxyProtoHTTP   = "http"
	ChainProxyProtoBoth   = "both"

	ChainProxyBindLoopback = "loopback"
	ChainProxyBindLAN      = "lan"

	ChainProxyDownError = "error"
	ChainProxyDownClose = "close"

	// ChainProxyDefaultPort is the port the proxy takes when nothing has
	// been chosen. 1080 is what every program means by "a SOCKS proxy".
	ChainProxyDefaultPort = 1080
)

// Engine returns the lock engine. Pack 70: the choice is gone, the service
// is the only engine. The field is still read and written so an old
// settings file stays readable, but "off" no longer disables anything: a
// kill switch that can be switched off from the settings tab is not a kill
// switch.
func (g ChainGlobalSettings) Engine() string {
	return ChainLockEngineService
}

// Mode returns the raise mode, upgrading a pack 55 file on the fly.
func (g ChainGlobalSettings) Mode() string {
	switch strings.ToLower(g.RaiseMode) {
	case ChainRaiseLast:
		return ChainRaiseLast
	case ChainRaiseSelected:
		return ChainRaiseSelected
	case ChainRaiseNone:
		return ChainRaiseNone
	}
	if g.RaiseOnStart && len(g.RaiseTunnel) > 0 {
		return ChainRaiseSelected
	}
	return ChainRaiseNone
}

// Target returns the tunnel that should be raised at start, or "".
func (g ChainGlobalSettings) Target() string {
	switch g.Mode() {
	case ChainRaiseSelected:
		return g.RaiseTunnel
	case ChainRaiseLast:
		// Pack 69 (J1): a tunnel the user switched off is not a target.
		if !g.LastTunnelUp {
			return ""
		}
		return g.LastTunnel
	}
	return ""
}

type chainSettingsBook struct {
	Global  ChainGlobalSettings
	Tunnels map[string]ChainTunnelSettings
	// Inherited stays true until the user saves the boxes for the first time.
	// While it is true the local network is left open no matter what a stored
	// entry says, so a remote desktop into this machine cannot be cut off by
	// a setting nobody has chosen yet.
	Inherited bool
}

// chainSettingsFileStamp is what the cache was built from. Pack 68 (G3)
// adds the size: two writes inside one file system tick have the same
// write time, and such a write was missed by the old check, which is one
// of the ways the boxes looked as if they had been forgotten.
type chainSettingsFileStamp struct {
	modTime time.Time
	size    int64
	known   bool
}

var (
	chainSettingsMu    sync.Mutex
	chainSettingsCache *chainSettingsBook
	// chainSettingsStamp describes the file the cache came from.
	chainSettingsStamp chainSettingsFileStamp
)

func chainSettingsDefaults() ChainTunnelSettings {
	return ChainTunnelSettings{KillSwitch: true, BlockIPv6: true, AllowLAN: true, LockMode: ChainLockModeNormal}
}

// AwgChain pack 86: the settings book lives in the data folder of the
// program, next to the configurations and the log. ProgramData is not
// consulted any more: a folder that is carried somewhere else carries its
// settings with it, and a service running as SYSTEM reads the same file as
// the window, which the environment of that account never guaranteed.
func chainSettingsPath() string {
	root, err := conf.ChainDataDir()
	if err != nil || len(root) == 0 {
		return ""
	}
	return filepath.Join(root, "settings.json")
}

// chainSettingsFileChanged reports whether settings.json has moved on since
// we last read or wrote it ourselves.
func chainSettingsFileChanged() bool {
	info, err := os.Stat(chainSettingsPath())
	if err != nil {
		// The file is gone or unreadable. Keeping the cache is the safe
		// answer: it is what the user last saved.
		return false
	}
	if !chainSettingsStamp.known {
		return true
	}
	return !info.ModTime().Equal(chainSettingsStamp.modTime) || info.Size() != chainSettingsStamp.size
}

// chainSettingsNoteStamp remembers the write time of the file in the cache.
func chainSettingsNoteStamp() {
	info, err := os.Stat(chainSettingsPath())
	if err != nil {
		chainSettingsStamp = chainSettingsFileStamp{}
		return
	}
	chainSettingsStamp = chainSettingsFileStamp{modTime: info.ModTime(), size: info.Size(), known: true}
}

func chainSettingsLoadLocked() *chainSettingsBook {
	// AwgChain pack 67: the cache is trusted only while the file on disk has
	// not been written by somebody else. awgchain.bat writes the same file,
	// and a cache that never expired is one reason the boxes looked as if
	// they had been forgotten.
	if chainSettingsCache != nil && !chainSettingsFileChanged() {
		return chainSettingsCache
	}

	book := &chainSettingsBook{
		Global:    ChainGlobalSettings{LiftLockOnQuit: true, RaiseMode: ChainRaiseNone},
		Tunnels:   make(map[string]ChainTunnelSettings),
		Inherited: true,
	}

	// Pack 68 (G2, G7): a read that fails and a file that cannot be
	// parsed used to be the same silent "use the defaults", and the very
	// next save overwrote the file the user had, settings and all.
	path := chainSettingsPath()
	data, err := os.ReadFile(path)
	switch {
	case os.IsNotExist(err):
		// A fresh install. The defaults above are the answer.
	case err != nil:
		log.Printf("[AwgChain] The settings could not be read (%v), the defaults are used for now", err)
	default:
		stored := &chainSettingsBook{}
		if parseErr := json.Unmarshal(data, stored); parseErr != nil {
			chainSettingsKeepBroken(path, parseErr)
		} else {
			if stored.Tunnels == nil {
				stored.Tunnels = make(map[string]ChainTunnelSettings)
			}
			book = stored
		}
	}

	chainSettingsCache = book
	chainSettingsNoteStamp()
	return book
}

func chainSettingsStoreLocked() error {
	book := chainSettingsCache
	if book == nil {
		return nil
	}

	data, err := json.MarshalIndent(book, "", "  ")
	if err != nil {
		return err
	}

	path := chainSettingsPath()
	err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		return err
	}

	// Pack 68 (G1): write beside the file and rename over it. A crash, a
	// power cut or a full disk now leaves either the old file or the new
	// one, never half of one. os.WriteFile truncated first, so there was
	// a real moment in which settings.json was empty, and an empty file
	// reads back as "no settings at all".
	temp := path + ".new"
	err = os.WriteFile(temp, data, 0600)
	if err != nil {
		log.Printf("[AwgChain] The settings could not be written (%v)", err)
		os.Remove(temp)
		return err
	}
	err = os.Rename(temp, path)
	if err != nil {
		log.Printf("[AwgChain] The settings could not be put in place (%v)", err)
		os.Remove(temp)
		return err
	}
	chainSettingsNoteStamp()

	return nil
}

// ChainSettingsFor returns the boxes of one tunnel, filled in with the
// defaults when nobody has saved anything yet.
func ChainSettingsFor(name string) ChainTunnelSettings {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	book := chainSettingsLoadLocked()
	settings, ok := book.Tunnels[strings.ToLower(name)]
	if !ok {
		return chainSettingsDefaults()
	}
	if book.Inherited {
		settings.AllowLAN = true
	}
	// Pack 79: what the rest of the program sees is always a settings
	// record that could have been made on screen.
	return settings.Normalised()
}

// ChainSettingsSave writes the boxes of one tunnel.
func ChainSettingsSave(name string, settings ChainTunnelSettings) error {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	settings = settings.Normalised()
	book := chainSettingsLoadLocked()
	book.Tunnels[strings.ToLower(name)] = settings
	book.Inherited = false
	return chainSettingsStoreLocked()
}

// ChainGlobal returns the settings of the whole program.
func ChainGlobal() ChainGlobalSettings {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	global := chainSettingsLoadLocked().Global
	global.RaiseMode = global.Mode()
	// Pack 70: one source of truth. The saved wish wins; the start type of
	// the service is only asked when no wish was ever saved. The old code
	// always answered with the start type, so a moment when the service was
	// deleted or unreadable turned the box off on screen, and the next save
	// wrote that off into the file.
	if !global.AutoStartSet {
		global.AutoStart = chainManagerStartsAutomatically()
	}
	return global
}

// ChainGlobalSave writes the settings of the whole program. The autostart box
// is not a field in the file: it is the start type of the service, so it is
// applied to the service manager right here.
func ChainGlobalSave(global ChainGlobalSettings) error {
	chainSettingsMu.Lock()
	book := chainSettingsLoadLocked()
	global.RaiseMode = global.Mode()
	global.RaiseOnStart = global.Mode() != ChainRaiseNone
	// Pack 67: the autostart box is a wish, and a wish has to survive Exit.
	global.AutoStartSet = true
	// Pack 68 (G6): a caller that does not know about a field sends it
	// empty, and the old code wrote that emptiness over what was stored.
	// The Settings tab knows nothing about the lock engine, so one click
	// on any box there used to put the engine back to the default.
	if len(global.LastTunnel) == 0 {
		global.LastTunnel = book.Global.LastTunnel
	}
	if len(strings.TrimSpace(global.RaiseTunnel)) == 0 {
		global.RaiseTunnel = book.Global.RaiseTunnel
	}
	if len(strings.TrimSpace(global.LockMode)) == 0 {
		global.LockMode = book.Global.LockMode
	}
	// Pack 70: the engine is not a setting any more, so every save heals
	// the field instead of carrying an old "off" forward.
	global.LockEngine = ChainLockEngineService
	// Pack 69 (J1): nobody outside this file writes LastTunnelUp. It is
	// kept by ChainNoteLastTunnel and ChainNoteTunnelDown, so a save
	// coming from the Settings tab must never touch it.
	global.LastTunnelUp = book.Global.LastTunnelUp
	// Pack 80: the same rule for the set of tunnels that are up. The
	// Settings tab does not know the field, and the emptiness it sends
	// would wipe the set on the first click on any box.
	global.UpTunnels = book.Global.UpTunnels
	book.Global = global
	err := chainSettingsStoreLocked()
	chainSettingsMu.Unlock()

	chainSetManagerStartType(global.AutoStart)
	return err
}

// ChainNoteLastTunnel remembers the tunnel that was raised by hand, so the
// "raise the last tunnel" mode has something to raise.
func ChainNoteLastTunnel(name string) {
	if len(name) == 0 || ChainIsHiddenHop(name) {
		return
	}

	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	book := chainSettingsLoadLocked()
	// Pack 69 (J1): the same name with the "is up" flag missing still
	// has to be written, otherwise a tunnel that was switched off and
	// raised again by hand would stay marked as switched off.
	if strings.EqualFold(book.Global.LastTunnel, name) && book.Global.LastTunnelUp &&
		chainUpTunnelsHave(book.Global.UpTunnels, name) {
		// Pack 80: the set has to be checked as well, otherwise the
		// second tunnel raised by hand is never written down: the
		// name and the flag already match the first one.
		return
	}
	book.Global.LastTunnel = name
	book.Global.LastTunnelUp = true
	book.Global.UpTunnels = chainUpTunnelsWith(book.Global.UpTunnels, name)
	// Pack 85: the set is cleaned here, at the one place it is written to
	// anyway. On 26 September the machine woke up with "Meant to be up:
	// WARPv3_39, WARPm3_79, warpam, Elena" while only two of those had been
	// switched on by hand, and the start-up raise dutifully tried to bring
	// the whole list back.
	if cleaned, dropped := chainUpTunnelsPrune(book.Global.UpTunnels); len(dropped) != 0 {
		book.Global.UpTunnels = cleaned
		log.Printf("[AwgChain] These names are no longer meant to be up and were dropped from the set: %v", dropped)
	}
	// Pack 68 (G10): this write used to be the one place where a failure
	// was dropped on the floor, so "raise the last tunnel" could quietly
	// keep pointing at a tunnel from last week.
	if err := chainSettingsStoreLocked(); err != nil {
		log.Printf("[AwgChain] The last raised tunnel (%s) could not be remembered: %v", name, err)
		return
	}
	log.Printf("[AwgChain] The last raised tunnel is now %s", name)
}

// chainUpTunnelsHave says whether this name is already in the set.
func chainUpTunnelsHave(set []string, name string) bool {
	name = strings.TrimSpace(name)
	for i := range set {
		if strings.EqualFold(strings.TrimSpace(set[i]), name) {
			return true
		}
	}
	return false
}

// chainUpTunnelsWith returns the set with this name in it, once.
func chainUpTunnelsWith(set []string, name string) []string {
	name = strings.TrimSpace(name)
	if len(name) == 0 || chainUpTunnelsHave(set, name) {
		return set
	}
	return append(set, name)
}

// chainUpTunnelsPrune drops the names that cannot be raised any more: empty
// entries, hidden hops, and tunnels whose config is gone. It returns the
// cleaned set and the names that were dropped.
//
// Pack 85: ChainUpTunnels already hid such names on the way out, but the file
// kept them for ever, so the list in the log and in the doctor report showed
// tunnels that nobody had asked for.
func chainUpTunnelsPrune(set []string) ([]string, []string) {
	out := make([]string, 0, len(set))
	dropped := make([]string, 0, len(set))
	for i := range set {
		name := strings.TrimSpace(set[i])
		if len(name) == 0 {
			continue
		}
		if ChainIsHiddenHop(name) {
			dropped = append(dropped, name)
			continue
		}
		if _, err := conf.LoadFromName(name); err != nil {
			dropped = append(dropped, name)
			continue
		}
		if chainUpTunnelsHave(out, name) {
			continue
		}
		out = append(out, name)
	}
	return out, dropped
}

// chainUpTunnelsWithout returns the set with this name taken out.
func chainUpTunnelsWithout(set []string, name string) []string {
	name = strings.TrimSpace(name)
	out := make([]string, 0, len(set))
	for i := range set {
		if strings.EqualFold(strings.TrimSpace(set[i]), name) {
			continue
		}
		out = append(out, set[i])
	}
	return out
}

// ChainUpTunnels is the set of tunnels the user left up, in the order they
// were raised. Names whose config is gone are dropped on the way out, so a
// deleted tunnel cannot keep the start-up raise busy for ever.
func ChainUpTunnels() []string {
	global := ChainGlobal()
	out := make([]string, 0, len(global.UpTunnels))
	for _, name := range global.UpTunnels {
		name = strings.TrimSpace(name)
		if len(name) == 0 || ChainIsHiddenHop(name) {
			continue
		}
		if _, err := conf.LoadFromName(name); err != nil {
			continue
		}
		out = append(out, name)
	}
	return out
}

// ChainIsHiddenHop says whether this name belongs to a hidden hop, which must
// never appear in a list the user picks from.
func ChainIsHiddenHop(name string) bool {
	// Pack 67: the same rule as conf.ChainIsHiddenHopName, which also knows
	// the legacy "hop1-warp" naming of the first packs. The two answers used
	// to differ, so a legacy hop could be offered in the Settings list.
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasSuffix(lower, "-hop1") || strings.HasPrefix(lower, "hop1-")
}

//
// The lock modes.
//

// ChainLockModeOf returns the lock mode of one tunnel.
// chainGlobalLockMode reads the lock mode of the whole program, or "" when
// the setting has never been written.
// chainLockModesEnabled turns the strict and paranoid lock modes on.
//
// Pack 73: they are off. The logs of 24.09 showed that both modes promise
// more than the program can keep, and for reasons that no setting can fix:
//
//   * leaving the window tells the manager service to stop itself, and the
//     kill switch lives in a dynamic WFP session that dies with the process,
//     so a mode that promised a closed machine opened it instead;
//   * with the autostart box cleared the service is even deleted, so after a
//     reboot nothing puts the lock up at all;
//   * nothing survives a crash of the service or the boot of Windows,
//     because dynamic filters are tied to the life of a process.
//
// In plans, in this order: the service must not stop itself while a mode is
// in force, and the filters of the lock have to become persistent WFP
// objects. Until both are done every tunnel behaves as "normal": the lock
// stands while the chain is up and goes away with it.
//
// Turning the modes back on is this one line.
const chainLockModesEnabled = false

func chainGlobalLockMode() string {
	if !chainLockModesEnabled {
		// In plans, see chainLockModesEnabled above.
		return ChainLockModeNormal
	}
	switch strings.ToLower(ChainGlobal().LockMode) {
	case ChainLockModeNormal:
		return ChainLockModeNormal
	case ChainLockModeStrict:
		return ChainLockModeStrict
	case ChainLockModeParanoid:
		return ChainLockModeParanoid
	}
	return ""
}

func ChainLockModeOf(name string) string {
	if mode := chainGlobalLockMode(); len(mode) > 0 {
		return mode
	}
	return ChainSettingsFor(name).Mode()
}

// chainLockSurvivesStop reports whether the lock must stay closed after this
// tunnel is stopped on purpose. Strict and paranoid say yes; then only the
// emergency button or "awgchain.bat ks off" opens the machine again.
func chainLockSurvivesStop(leaf string) bool {
	mode := ChainLockModeOf(leaf)
	return mode == ChainLockModeStrict || mode == ChainLockModeParanoid
}

// chainDisarmLockRespectingMode is what the manager calls when a tunnel goes
// down on purpose. In strict and paranoid mode the filters stay.
func chainDisarmLockRespectingMode() bool {
	chainLockMu.Lock()
	leaf := chainLockLeaf
	on := chainLockOn
	chainLockMu.Unlock()

	if on && len(leaf) > 0 && chainLockSurvivesStop(leaf) {
		log.Printf("[AwgChain] The kill switch stays closed: %s is in %s mode, lift it with the button in the window or awgchain.bat ks off", leaf, ChainLockModeOf(leaf))
		return false
	}

	// Pack 72: when no chain is up the leaf is empty, the mode was never
	// consulted and the machine was opened anyway. That is how leaving the
	// program took the lock of the paranoid start down.
	if target, paranoid := chainParanoidWanted(); paranoid {
		if len(target) == 0 {
			target = "the whole program"
		}
		log.Printf("[AwgChain] The lock stays closed: the paranoid mode is in force for %s, lift it with the button in the window or awgchain.bat ks off", target)
		return false
	}

	return chainDisarmLockInProc()
}

// ChainLiftLockNow is the emergency exit: the lock goes away whatever the
// mode says.
func ChainLiftLockNow() {
	// Pack 68 (I7): this used to be the whole of it, and five seconds
	// later chainWatch armed the lock again, because a healthy chain is
	// armed on every round of the watch. The button looked broken: the
	// machine opened and then shut itself. The lift is remembered now
	// and holds until a tunnel is raised on purpose.
	chainLockSuppress(true)
	chainDisarmLockInProc()
	chainDropIPv6Block()
}

// chainParanoidWanted answers whether the paranoid mode is in force right
// now, and for which tunnel. Pack 71: the old code asked only about the
// tunnel chosen for the start, so with the raise mode set to "nothing" the
// mode was simply not applied, which is how a machine came up after a
// reboot with the internet wide open and no lock at all.
func chainParanoidWanted() (string, bool) {
	global := ChainGlobal()
	target := strings.TrimSpace(global.Target())
	if chainGlobalLockMode() == ChainLockModeParanoid {
		// The mode of the whole program wins over every tunnel, and it
		// holds even when nothing is going to be raised.
		return target, true
	}
	for _, name := range []string{target, strings.TrimSpace(global.LastTunnel)} {
		if len(name) == 0 {
			continue
		}
		if ChainLockModeOf(name) == ChainLockModeParanoid {
			return name, true
		}
	}
	return "", false
}

// chainBootLockIsOn says whether the machine is closed by the lock that
// stands without a tunnel.
func chainBootLockIsOn() bool {
	return firewall.BootLockIsOn()
}

// chainBootLockMu guards the description of the lock that stands right now,
// so the filters are rebuilt only when something has really changed.
var (
	chainBootLockMu  sync.Mutex
	chainBootLockSig string
)

// chainBootLockConfig works out what the lock before the start has to keep
// open. It returns the configuration and a human readable list of what stays
// reachable.
//
// Pack 72: the lock of pack 71 knew a single endpoint, the first hop of the
// tunnel chosen for the start. Two chains could not be raised from behind it:
// with the raise mode set to "nothing" there was no chosen tunnel at all and
// the lock blocked every handshake, and even with one chosen the second hop
// had nowhere to go, because neither its endpoint nor the adapter of the
// first hop was let through.
func chainBootLockConfig(leaf string) (*firewall.BootLockConfig, string) {
	cfg := &firewall.BootLockConfig{AllowedApps: chainLockApps()}
	leaf = strings.TrimSpace(leaf)

	chains := make([]string, 0, 4)
	if len(leaf) > 0 {
		chains = append(chains, leaf)
	} else if names, err := conf.ListConfigNames(); err == nil {
		// Nothing is going to be raised on its own, so the first hop of
		// every chain that exists stays reachable and any of them can
		// still be started by hand from behind the lock.
		chains = append(chains, names...)
	} else {
		log.Printf("[AwgChain] The lock before the start cannot read the list of tunnels (%v)", err)
	}

	seenEndpoint := make(map[string]bool, 8)
	seenLUID := make(map[uint64]bool, 4)
	reachable := make([]string, 0, 8)
	lanRoot, lanLeaf := "", ""

	for _, name := range chains {
		name = strings.TrimSpace(name)
		if len(name) == 0 {
			continue
		}
		hops := chainHopOrder(name)
		if len(hops) == 0 {
			continue
		}
		if len(lanLeaf) == 0 {
			lanRoot, lanLeaf = hops[0], name
		}

		for i, hop := range hops {
			// The first hop is reached over whatever interface leads
			// outside; every next one only through the adapter of the
			// hop before it.
			through := uint64(0)
			if i > 0 {
				luid, ok := chainAdapterLUID(hops[i-1])
				if !ok {
					// That adapter does not exist yet. The rule is
					// added as soon as the hop before comes up and
					// the lock is rebuilt.
					break
				}
				through = uint64(luid)
			}
			text, err := chainEndpointOf(hop)
			if err != nil {
				break
			}
			ip, port, ok := chainParseEndpoint(text)
			if !ok {
				break
			}
			key := ip.String() + ":" + strconv.FormatUint(uint64(port), 10) + "@" + strconv.FormatUint(through, 10)
			if seenEndpoint[key] {
				continue
			}
			seenEndpoint[key] = true
			cfg.Endpoints = append(cfg.Endpoints, firewall.BootLockEndpoint{
				IP:            ip,
				Port:          port,
				InterfaceLUID: through,
				Label:         "hop " + strconv.Itoa(i+1) + " of " + name + " at boot",
			})
			reachable = append(reachable, hop+" "+ip.String()+":"+strconv.FormatUint(uint64(port), 10))
		}

		// Whatever is already up has to stay open, otherwise the packets
		// of the next hop die inside the adapter of the previous one.
		for _, hop := range hops {
			luid, ok := chainAdapterLUID(hop)
			if !ok || uint64(luid) == 0 || seenLUID[uint64(luid)] {
				continue
			}
			seenLUID[uint64(luid)] = true
			cfg.TunnelLUIDs = append(cfg.TunnelLUIDs, uint64(luid))
		}
	}

	cfg.AllowedLANs = chainSettingsLANs(lanRoot, lanLeaf)
	return cfg, strings.Join(reachable, ", ")
}

// chainArmBootLock closes the machine before any tunnel exists. The endpoints
// of the hops, the adapters that are already up, the allowed executables and
// the local networks are let through, so the chain can still be built from
// behind the lock. Calling it again rebuilds the filters when the picture has
// changed, which is how the second hop is let out once the first one is up.
func chainArmBootLock(leaf string) {
	if chainLockSuppressedNow() {
		chainLogChanged("boot-lock-suppressed", "[AwgChain] The lock of the paranoid start is not put up: it was lifted by hand and no tunnel has been raised on purpose since")
		return
	}

	cfg, reachable := chainBootLockConfig(leaf)
	sig := reachable + "|" + strconv.Itoa(len(cfg.TunnelLUIDs)) + "|" + strconv.Itoa(len(cfg.AllowedLANs))
	for _, luid := range cfg.TunnelLUIDs {
		sig += "|" + strconv.FormatUint(luid, 10)
	}

	chainBootLockMu.Lock()
	unchanged := firewall.BootLockIsOn() && sig == chainBootLockSig
	chainBootLockMu.Unlock()
	if unchanged {
		return
	}

	if err := firewall.EnableBootLock(cfg); err != nil {
		log.Printf("[AwgChain] Paranoid mode: the machine could NOT be closed before the chain came up (%v)", err)
		return
	}

	chainBootLockMu.Lock()
	chainBootLockSig = sig
	chainBootLockMu.Unlock()

	if len(cfg.Endpoints) == 0 {
		log.Printf("[AwgChain] Paranoid mode: the machine is closed before any tunnel is up. No endpoint is known yet, so the lock is rebuilt as soon as one can be read")
		return
	}
	log.Printf("[AwgChain] Paranoid mode: the machine is closed before any tunnel is up, reachable: %s (open adapters: %d)", reachable, len(cfg.TunnelLUIDs))
}

// chainDropBootLock opens the machine again. It is called once the real kill
// switch stands, and by the emergency lift.
func chainDropBootLock(why string) {
	if !firewall.BootLockIsOn() {
		return
	}
	firewall.DisableBootLock()
	chainBootLockMu.Lock()
	chainBootLockSig = ""
	chainBootLockMu.Unlock()
	chainLogForget("boot-lock-suppressed")
	log.Printf("[AwgChain] The lock of the paranoid start is taken down: %s", why)
}

// chainParanoidArmOnStart closes the machine before any tunnel is up, so a
// paranoid mode leaves no open window while Windows boots.
func (s *ManagerService) chainParanoidArmOnStart() {
	target, wanted := chainParanoidWanted()
	if !wanted {
		return
	}

	chainParanoidBootMu.Lock()
	chainParanoidBootBlock = true
	chainParanoidBootMu.Unlock()

	err := firewall.EnableIPv6Block()
	if err == nil {
		log.Printf("[AwgChain] Paranoid mode: IPv6 is blocked before any tunnel is up")
	} else {
		// Pack 70: this failure used to be dropped, and the next line
		// still promised a closed machine.
		log.Printf("[AwgChain] Paranoid mode: IPv6 could NOT be blocked before the chain came up (%v)", err)
	}

	// Pack 71: IPv4 is closed here as well. Until this pack only IPv6 was
	// blocked at boot, so "paranoid" meant an open machine from the moment
	// Windows started until the chain was up, which is exactly the window
	// the mode exists to close.
	chainArmBootLock(target)
	if len(target) == 0 {
		log.Printf("[AwgChain] Paranoid mode: no tunnel is chosen, so the machine stays closed until one is raised by hand")
		return
	}
	log.Printf("[AwgChain] Paranoid mode for %s: the machine is closed from boot and stays closed until the chain is up", target)
}

//
// The autostart box: the start type of the manager service.
//

func chainManagerStartsAutomatically() bool {
	m, err := serviceManager()
	if err != nil {
		return true
	}
	service, err := m.OpenService("AwgChainManager")
	if err != nil {
		return false
	}
	defer service.Close()

	config, err := service.Config()
	if err != nil {
		return true
	}
	return config.StartType == mgr.StartAutomatic
}

func chainSetManagerStartType(automatic bool) {
	m, err := serviceManager()
	if err != nil {
		return
	}
	service, err := m.OpenService("AwgChainManager")
	if err != nil {
		log.Printf("[AwgChain] The start type cannot be changed: the service is not installed (%v)", err)
		return
	}
	defer service.Close()

	config, err := service.Config()
	if err != nil {
		return
	}
	var want uint32 = mgr.StartManual
	if automatic {
		want = mgr.StartAutomatic
	}
	if config.StartType == want {
		return
	}
	config.StartType = want
	err = service.UpdateConfig(config)
	if err != nil {
		log.Printf("[AwgChain] The start type could not be changed (%v)", err)
		return
	}
	if automatic {
		log.Printf("[AwgChain] The program starts with Windows from now on")
		return
	}
	log.Printf("[AwgChain] The program no longer starts with Windows")
}

//
// Unchanged from pack 55, apart from reading the new fields.
//

// chainSettingsLANs decides which local networks stay reachable behind the
// closed lock. The root tunnel knows the networks, the leaf tunnel carries
// the check box.
func chainSettingsLANs(root, leaf string) []net.IPNet {
	if !ChainSettingsFor(leaf).AllowLAN {
		log.Printf("[AwgChain] The local network stays closed for %s", leaf)
		return nil
	}
	return chainLockLANs(root)
}

// chainApplyIPv6For raises or drops the IPv6 filter for this tunnel.
func chainApplyIPv6For(leaf string) {
	if !ChainSettingsFor(leaf).BlockIPv6 {
		chainDropIPv6Block()
		return
	}

	err := firewall.EnableIPv6Block()
	if err != nil {
		log.Printf("[AwgChain] IPv6 could not be blocked by the filter (%v)", err)
		return
	}
	chainLogChanged("ipv6-block", "[AwgChain] IPv6 is blocked by the filter while %s is up", leaf)
	chainWarnIPv6Left()
}

// chainWarnIPv6Left looks whether a routable IPv6 address is still sitting
// on some adapter while the IPv6 filter stands.
//
// Pack 84: the filter forbids the packets, it does not take the address
// away, so programs keep preferring IPv6, keep knocking on a door that is
// shut, and every one of those waits looks to the user like a slow or dead
// site. Nothing is switched off here, because an address torn away behind
// the back of the user is worse than a slow page; the fact is written into
// the log once, with the address named, so that it can be found instead of
// guessed.
func chainWarnIPv6Left() {
	adapters, err := winipcfg.GetAdaptersAddresses(winipcfg.AddressFamily(windows.AF_INET6), winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	found := make([]string, 0, 2)
	for _, adapter := range adapters {
		if adapter.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		for address := adapter.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			if ip == nil || ip.To4() != nil || !ip.IsGlobalUnicast() {
				continue
			}
			if ip.IsPrivate() {
				// A unique local address never leaves the house.
				continue
			}
			found = append(found, fmt.Sprintf("%s on %s", ip, adapter.FriendlyName()))
		}
	}
	if len(found) == 0 {
		chainLogForget("ipv6-left")
		return
	}
	chainLogChanged("ipv6-left", "[AwgChain] IPv6 is blocked by the filter, but the machine still holds a routable IPv6 address (%s). The packets are dropped rather than refused, so a program that prefers IPv6 will wait for a timeout before it tries IPv4. Turn IPv6 off on that adapter if pages open slowly", strings.Join(found, ", "))
}

// chainParanoidBootBlock says that the IPv6 filter standing right now was
// put up by the paranoid start, before any tunnel existed.
var (
	chainParanoidBootMu    sync.Mutex
	chainParanoidBootBlock bool
)

// chainDropIPv6Block removes the IPv6 filter if it stands.
func chainDropIPv6Block() {
	// Pack 70: the block of the paranoid start belongs to the start-up
	// raise, not to whatever tunnel happens to be going down while the
	// chain is still coming up. Dropping it there opened exactly the
	// window the mode exists to close.
	chainParanoidBootMu.Lock()
	held := chainParanoidBootBlock && chainBootRaisingNow()
	if !held {
		chainParanoidBootBlock = false
	}
	chainParanoidBootMu.Unlock()
	if held {
		chainLogChanged("ipv6-boot-block", "[AwgChain] The IPv6 filter of the paranoid start stays until the start-up raise is done")
		return
	}

	chainLogForget("ipv6-block")
	chainLogForget("killswitch-off")
	chainLogForget("ipv6-boot-block")
	if !firewall.IPv6BlockIsOn() {
		return
	}
	firewall.DisableIPv6Block()
	log.Printf("[AwgChain] The IPv6 filter is removed")
}

// chainSettingsApplyNow is called right after the boxes are saved. Only the
// IPv6 filter can be changed on a running tunnel; the kill switch and the
// local network are read the next time the chain goes up.
func (s *ManagerService) chainSettingsApplyNow(name string) {
	if firewall.IPv6BlockIsOn() && !ChainSettingsFor(name).BlockIPv6 {
		chainDropIPv6Block()
	}

	// Pack 70: the kill switch was built once, when the chain came up, and
	// the local network, the DNS servers and the kill switch box itself
	// were frozen in it until the next raise. Clearing "allow the local
	// network" looked as if it had been ignored. When the tunnel being
	// saved is the one holding the lock, the filters are rebuilt now.
	chainLockMu.Lock()
	leaf := chainLockLeaf
	on := chainLockOn
	chainLockMu.Unlock()
	if !on || len(leaf) == 0 {
		return
	}
	if !strings.EqualFold(leaf, name) && !chainInOwnBranch(chainOwnBranch(leaf), name) {
		return
	}
	log.Printf("[AwgChain] The settings of %s changed while the kill switch was up, so the filters are rebuilt", name)
	chainDisarmLockInProc()
	s.chainArmGuard(leaf)
}

//
// The autostart wish (pack 67).
//
// chainAutoRaiseOnStart used to live here: one Start, five seconds after a
// window appeared. It is replaced by chainApplyStartPolicy in chainboot.go,
// which runs in the service, waits for the adapter and retries in stages.
//

// chainAutoStartWanted reports whether the program should start with Windows.
// A settings file that has never had the box saved answers yes, which is the
// start type a fresh install gets anyway.
func chainAutoStartWanted() bool {
	chainSettingsMu.Lock()
	defer chainSettingsMu.Unlock()

	global := chainSettingsLoadLocked().Global
	if !global.AutoStartSet {
		return true
	}
	return global.AutoStart
}

// chainApplyAutoStartIntent puts the saved wish back on the service. It runs
// at the end of InstallManager, because a service that Exit deleted and the
// next launch created again comes back automatic whatever the user chose.
func chainApplyAutoStartIntent() {
	chainSetManagerStartType(chainAutoStartWanted())
}
