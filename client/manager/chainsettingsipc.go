/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 56: the pipe calls of the settings, second edition.
 *
 *   101 read the boxes of one tunnel
 *   102 write the boxes of one tunnel
 *   103 read the settings of the program
 *   104 write the settings of the program
 *   105 lift the lock right now (the emergency button, any mode)
 *   106 list the tunnels the user may choose from (hidden hops left out)
 *   107 lift the lock because the program is closing (obeys the mode)
 *   108 put the lock up right now (pack 71, the other half of 105)
 *
 * Pack 56 keeps the numbers of pack 55 so a half-updated pair still talks.
 */

package manager

import (
	"encoding/gob"
	"log"
	"sort"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// chainMayChange answers whether this connection is allowed to change
// anything. Pack 70: 102, 104, 105 and 107 write settings, switch the kill
// switch off and open the machine, and none of them asked for the elevated
// token the rest of the pipe asks for. A limited-operator interface could
// therefore lift the lock and turn the protection off for everybody.
func (s *ManagerService) chainMayChange(what string) bool {
	if s.elevatedToken != 0 {
		return true
	}
	log.Printf("[AwgChain] %s was refused: the caller of the pipe is not the elevated interface", what)
	return false
}

const (
	ChainSettingsGetMethodType MethodType = 101
	ChainSettingsSetMethodType MethodType = 102
	ChainGlobalGetMethodType   MethodType = 103
	ChainGlobalSetMethodType   MethodType = 104
	ChainLiftLockMethodType    MethodType = 105
	ChainPickListMethodType    MethodType = 106
	// Pack 67: the quit lift is a different question from the button in the
	// window. The button is an emergency exit and always opens the machine;
	// this one obeys strict and paranoid mode.
	ChainLiftLockOnQuitMethodType MethodType = 107

	// Pack 71: the button in the window works both ways now. 105 opens the
	// machine, 108 closes it again without waiting for the next raise.
	ChainArmLockMethodType MethodType = 108
)

//
// The service side.
//

func (s *ManagerService) chainServeSettingsGet(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var name string
	err := decoder.Decode(&name)
	if err != nil {
		return err
	}

	err = encoder.Encode(ChainSettingsFor(name))
	if err != nil {
		return err
	}

	return encoder.Encode(errToString(nil))
}

func (s *ManagerService) chainServeSettingsSet(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var name string
	err := decoder.Decode(&name)
	if err != nil {
		return err
	}

	var settings ChainTunnelSettings
	err = decoder.Decode(&settings)
	if err != nil {
		return err
	}

	if !s.chainMayChange("A change of the settings of a tunnel") {
		return encoder.Encode(errToString(windows.ERROR_ACCESS_DENIED))
	}

	saveErr := ChainSettingsSave(name, settings)
	if saveErr == nil {
		s.chainSettingsApplyNow(name)
		log.Printf("[AwgChain] The settings of %s are saved: kill switch %v (%s mode), IPv6 blocked %v, local network %v", name, settings.KillSwitch, settings.Mode(), settings.BlockIPv6, settings.AllowLAN)
	}

	return encoder.Encode(errToString(saveErr))
}

func (s *ManagerService) chainServeGlobalGet(encoder *gob.Encoder) error {
	err := encoder.Encode(ChainGlobal())
	if err != nil {
		return err
	}

	return encoder.Encode(errToString(nil))
}

func (s *ManagerService) chainServeGlobalSet(decoder *gob.Decoder, encoder *gob.Encoder) error {
	var global ChainGlobalSettings
	err := decoder.Decode(&global)
	if err != nil {
		return err
	}

	if !s.chainMayChange("A change of the settings of the program") {
		return encoder.Encode(errToString(windows.ERROR_ACCESS_DENIED))
	}

	// AwgChain pack 86: the fields of the portable mode are carried
	// forward here, because ChainGlobalSave writes the whole book of
	// global settings and the Settings tab builds its message from the
	// few boxes it owns. Without this, one click on "start with Windows"
	// would switch encryption of the configurations off, forget the
	// password check and put the rights of the data folder back, and
	// nothing on screen would say so.
	//
	// The wish flag is what tells the two callers apart. The Configs
	// section sets it together with the box, so its message is taken as
	// written; every other caller leaves it false and keeps what is
	// stored. The state of the folder rights and the flag of a closed
	// installation are never sent by a window at all: the manager is the
	// only writer of those, so they are always carried forward.
	//
	// Pack 91: the password check is not carried forward any more, it is
	// carried away. The field exists only so that a settings file written
	// by pack 86 still reads, and every save is one more chance to leave
	// the dead value behind.
	stored := chainSecureGlobal()
	if !global.EncryptConfigsSet {
		global.EncryptConfigs = stored.EncryptConfigs
		global.EncryptConfigsSet = stored.EncryptConfigsSet
	}
	global.DpapiVerifier = ""
	global.DataAclOpen = stored.DataAclOpen
	global.DataAclSid = stored.DataAclSid
	global.InstallSealed = stored.InstallSealed

	saveErr := ChainGlobalSave(global)
	if saveErr == nil {
		// Pack 71: the lock mode is part of what was saved. Without it the
		// log could not answer "when was paranoid mode switched on", which
		// is the first question every lock report starts with.
		mode := strings.TrimSpace(global.LockMode)
		if len(mode) == 0 {
			mode = "per tunnel"
		}
		log.Printf("[AwgChain] The program settings are saved: raise %s (%s), start with Windows %v, lift the lock on quit %v, lock mode %s", global.Mode(), global.Target(), global.AutoStart, global.LiftLockOnQuit, mode)
	}

	return encoder.Encode(errToString(saveErr))
}

func (s *ManagerService) chainServeLiftLock(encoder *gob.Encoder) error {
	if !s.chainMayChange("Lifting the lock") {
		return encoder.Encode(errToString(windows.ERROR_ACCESS_DENIED))
	}
	ChainLiftLockNow()
	log.Printf("[AwgChain] The lock is lifted on request from the window")

	return encoder.Encode(errToString(nil))
}

// chainServeLiftLockOnQuit is the lift asked for on the way out of the
// program. Unlike the button it may decide to leave the lock closed.
func (s *ManagerService) chainServeLiftLockOnQuit(encoder *gob.Encoder) error {
	if !s.chainMayChange("Lifting the lock on the way out of the program") {
		return encoder.Encode(errToString(windows.ERROR_ACCESS_DENIED))
	}
	chainQuitLiftLock()

	return encoder.Encode(errToString(nil))
}

// chainServeArmLock is the other half of the button in the window: it closes
// the machine now. Pack 71: until this pack the only direction was "lift",
// and a lock taken down by hand could only come back with the next raise,
// because the flag that holds it down survives on purpose.
func (s *ManagerService) chainServeArmLock(encoder *gob.Encoder) error {
	if !s.chainMayChange("Putting the lock up") {
		return encoder.Encode(errToString(windows.ERROR_ACCESS_DENIED))
	}
	armErr := s.chainArmLockOnDemand()
	if armErr == nil {
		log.Printf("[AwgChain] The lock is put up on request from the window")
	} else {
		log.Printf("[AwgChain] The lock could not be put up on request from the window: %v", armErr)
	}

	return encoder.Encode(errToString(armErr))
}

// chainServePickList answers with the tunnel names a user may pick: the
// hidden hops of a chain are left out, because raising warpam-hop1 on its
// own is never what anybody wants.
func (s *ManagerService) chainServePickList(encoder *gob.Encoder) error {
	names := make([]string, 0, 4)
	tunnels, err := conf.ListConfigNames()
	if err == nil {
		for i := range tunnels {
			if ChainIsHiddenHop(tunnels[i]) {
				continue
			}
			names = append(names, tunnels[i])
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})

	err = encoder.Encode(names)
	if err != nil {
		return err
	}

	return encoder.Encode(errToString(nil))
}

//
// The interface side.
//

func IPCClientChainSettings(name string) (ChainTunnelSettings, error) {
	var settings ChainTunnelSettings

	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainSettingsGetMethodType)
	if err != nil {
		return settings, err
	}
	err = rpcEncoder.Encode(name)
	if err != nil {
		return settings, err
	}
	err = rpcDecoder.Decode(&settings)
	if err != nil {
		return settings, err
	}

	return settings, rpcDecodeError()
}

func IPCClientChainSettingsSave(name string, settings ChainTunnelSettings) error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainSettingsSetMethodType)
	if err != nil {
		return err
	}
	err = rpcEncoder.Encode(name)
	if err != nil {
		return err
	}
	err = rpcEncoder.Encode(settings)
	if err != nil {
		return err
	}

	return rpcDecodeError()
}

func IPCClientChainGlobal() (ChainGlobalSettings, error) {
	var global ChainGlobalSettings

	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainGlobalGetMethodType)
	if err != nil {
		return global, err
	}
	err = rpcDecoder.Decode(&global)
	if err != nil {
		return global, err
	}

	return global, rpcDecodeError()
}

func IPCClientChainGlobalSave(global ChainGlobalSettings) error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainGlobalSetMethodType)
	if err != nil {
		return err
	}
	err = rpcEncoder.Encode(global)
	if err != nil {
		return err
	}

	return rpcDecodeError()
}

func IPCClientChainLiftLock() error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainLiftLockMethodType)
	if err != nil {
		return err
	}

	return rpcDecodeError()
}

// IPCClientChainLiftLockOnQuit asks the manager to lift the lock because the
// program is closing. The manager may refuse in strict or paranoid mode.
func IPCClientChainLiftLockOnQuit() error {
	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainLiftLockOnQuitMethodType)
	if err != nil {
		return err
	}

	return rpcDecodeError()
}

// IPCClientChainPickList returns the tunnels the Settings tab may offer.
func IPCClientChainPickList() ([]string, error) {
	var names []string

	rpcMutex.Lock()
	defer rpcMutex.Unlock()

	err := rpcEncoder.Encode(ChainPickListMethodType)
	if err != nil {
		return names, err
	}
	err = rpcDecoder.Decode(&names)
	if err != nil {
		return names, err
	}

	return names, rpcDecodeError()
}
