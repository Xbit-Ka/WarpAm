/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"strings"
	"errors"
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/amnezia-vpn/amneziawg-windows-client/updater"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
)

var (
	managerServices     = make(map[*ManagerService]bool)
	managerServicesLock sync.RWMutex
	haveQuit            uint32
	quitManagersChan    = make(chan struct{}, 1)
)

type ManagerService struct {
	events        *os.File
	eventLock     sync.Mutex
	elevatedToken windows.Token
}

func (s *ManagerService) StoredConfig(tunnelName string) (*conf.Config, error) {
	conf, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	if s.elevatedToken == 0 {
		conf.Redact()
	}
	return conf, nil
}

func (s *ManagerService) RuntimeConfig(tunnelName string) (*conf.Config, error) {
	storedConfig, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	pipe, err := connectTunnelServicePipe(tunnelName)
	if err != nil {
		return nil, err
	}
	pipe.SetDeadline(time.Now().Add(time.Second * 2))
	_, err = pipe.Write([]byte("get=1\n\n"))
	if err == windows.ERROR_NO_DATA {
		// AwgChain pack 56: the window closes its pipe on purpose when a tab
		// goes away, so a clean close is no longer worth a log line.
		if !chainQuietPipeClose(err) {
			log.Println("IPC pipe closed unexpectedly, so reopening")
		}
		pipe.Unlock()
		disconnectTunnelServicePipe(tunnelName)
		pipe, err = connectTunnelServicePipe(tunnelName)
		if err != nil {
			return nil, err
		}
		pipe.SetDeadline(time.Now().Add(time.Second * 2))
		_, err = pipe.Write([]byte("get=1\n\n"))
	}
	if err != nil {
		pipe.Unlock()
		disconnectTunnelServicePipe(tunnelName)
		return nil, err
	}
	conf, err := conf.FromUAPI(pipe, storedConfig)
	pipe.Unlock()
	if err != nil {
		return nil, err
	}
	if s.elevatedToken == 0 {
		conf.Redact()
	}
	return conf, nil
}

func (s *ManagerService) Start(tunnelName string) error {
	// AwgChain pack 68 (F2): what was raised is remembered at the end of
	// this function, when the raise has actually worked. Writing it here
	// meant that a tunnel which failed to come up, or which was refused
	// two lines below, still became "the last tunnel" and was the one
	// picked up at the next boot.
	c, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return err
	}

	// WarpAm pack 112: a chain is not longer than 4 tunnels
	// (chainlength.go). Old settings and raises without a window are
	// caught here; the tab asks before the box is ticked.
	if err := chainLengthStartProblem(tunnelName); err != nil {
		return chainFinal(err)
	}
	chainIPv6ServerNote(tunnelName)

	// WarpAm pack 112: the MTU of the tunnels this raise brings up is
	// checked outside once per network, before anything is installed
	// (chainmtu.go). A tunnel with a number already checked costs nothing.
	s.chainMTUBeforeRaise(tunnelName)

	if err := s.chainStartParents(tunnelName, 0); err != nil {
		// AwgChain: a hop is useless without the hop it rides on, so bring the
		// lower ones up first and wait for each handshake.
		return err
	}

	// WarpAm pack 103: only one tunnel of a via stack may carry the machine.
	if err := s.chainViaClashError(tunnelName); err != nil {
		return err
	}

	// WarpAm pack 104: the port is asked about before the tunnel this one
	// goes through is raised. Asked only after, the tunnel below came up
	// and stayed up for nothing when the port was taken.
	if err := ChainProxyPortConflict(tunnelName); err != nil {
		log.Printf("[WarpAm] %s is not raised: %v", tunnelName, err)
		return err
	}

	// Pack 101: the tunnel this one is set to go through is raised first,
	// in the background, so the stop button stays usable meanwhile.
	if raising, err := s.chainViaRaiseFirst(tunnelName); err != nil || raising {
		return err
	}

	// Pack 69 (J3): the hops of this very chain are never candidates for
	// being stopped. A config intersects with itself, and chainSiblings
	// only knows the direct pin relation, so the loop below used to ask
	// for the stop of the tunnel it was raising. In the log that showed
	// up as a hop coming up, handshaking, and going down again two
	// milliseconds later.
	own := chainOwnBranch(tunnelName)

	// Pack 80: the port of the proxy is asked for before anything is
	// raised. A tunnel that comes up without the port it was promised
	// looks active and works for nobody.
	if err := ChainProxyPortConflict(tunnelName); err != nil {
		log.Printf("[WarpAm] %s is not raised: %v", tunnelName, err)
		return err
	}

	// Pack 80: a tunnel that carries nothing but its proxy takes no
	// default route and no system DNS, so it gets in nobody's way. It
	// neither stops anything nor is stopped by anything, and that is
	// what lets several of them run side by side with one ordinary
	// tunnel. The config of such a tunnel still says AllowedIPs
	// 0.0.0.0/0 - the routes are simply never installed - so the
	// intersection test below would otherwise stop every one of them.
	// WarpAm pack 110: chainTunnelIsSeparate, so that a hidden hop counts
	// as what its pair is (chainguard.go).
	raisingSeparate := chainTunnelIsSeparate(tunnelName)

	// Figure out which tunnels have intersecting addresses/routes and stop those.
	// WarpAm pack 111: the loop is chainStartScan (chainstartask.go), the
	// same code that tells the window beforehand what this raise stops.
	tt, maybeBusy, running := s.chainStartScan(c, tunnelName, own, raisingSeparate, false)
	// WarpAm pack 112: a tunnel with the same key the window said yes to
	// is stopped with the others instead of refusing the raise
	// (chainkeyclash.go).
	tt = append(tt, s.chainKeyClashStops(c, tunnelName, running, tt, own)...)
	if inTransition := s.chainFirstInTransition(maybeBusy); len(inTransition) != 0 {
		// Pack 68 (F1): the refusal is written down. It used to leave no
		// trace at all, so "the tunnel does not come up and the log says
		// nothing" was exactly what happened.
		log.Printf("[WarpAm] %s is not raised: %s is still changing state", tunnelName, inTransition)
		// Pack 82: shown in a window, so Russian. The log stays English.
		return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u0435\u0449\u0451 \u043f\u043e\u0434\u043d\u0438\u043c\u0430\u0435\u0442\u0441\u044f, \u043f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435 \u043d\u0435\u043c\u043d\u043e\u0433\u043e", inTransition)
	}

	// Pack 81: one account, one tunnel. A second adapter with the same
	// interface address is refused by Windows, and a second handshake with
	// the same private key throws the first one off the server, so the
	// answer comes now, while nothing has been raised or stopped yet. The
	// tunnels in tt are about to go down and are not in the way.
	if err := ChainDuplicateConflict(c, running, tt, own); err != nil {
		log.Printf("[WarpAm] %s is not raised: %v", tunnelName, err)
		// WarpAm pack 111: the same key stays the same key, so the
		// retry of a hop does not ask five times (chainrefuse.go).
		return chainFinal(err)
	}

	// Stop those intersecting tunnels asynchronously.
	go func() {
		for _, t := range tt {
			// WarpAm pack 104: what goes through t goes down with it.
			s.chainViaStopRiders(t, tunnelName, false)
			// WarpAm pack 111: and what goes through the tunnels that ride
			// on t. Stopping warpam-hop1 takes warpam down (Stop stops the
			// children), and whatever went through warpam was left up
			// with no way out.
			for _, kid := range chainChildNames(t) {
				s.chainViaStopRiders(kid, tunnelName, false)
			}
			s.Stop(t)
			// WarpAm pack 113: the next one goes only when Windows has
			// taken this adapter away (chainadaptergone.go).
			ChainWaitAdapterGone(t)
		}
		for _, t := range tt {
			state, err := s.State(t)
			if err == nil && (state == TunnelStarted || state == TunnelStarting) {
				log.Printf("[%s] Trying again to stop zombie tunnel", t)
				s.Stop(t)
				time.Sleep(time.Millisecond * 100)
			}
		}
	}()
	// After the stop process has begun, but before it's finished, we install the new one.
	path, err := c.Path()
	if err != nil {
		return err
	}
	if err := s.chainInstallAndArm(tunnelName, path); err != nil {
		return err
	}
	// WarpAm pack 112: a ping inside the new tunnel tells whether its
	// server takes packets as big as the MTU (chainmtu.go).
	s.chainMTUInnerLater(tunnelName)

	// Pack 68 (F2): now that the tunnel is really installed, it is worth
	// remembering. The start-up raise is left out on purpose: it raises
	// the tunnel the setting names, and that is not a choice the user
	// just made by hand.
	if !chainBootRaisingNow() {
		ChainNoteLastTunnel(tunnelName)
	}
	return nil
}

func (s *ManagerService) Stop(tunnelName string) error {
	// AwgChain: whatever rides on this tunnel loses its way out the moment this
	// one goes, so tear the upper hops down first.
	// AwgChain: a deliberate stop takes the watch and the kill switch with it.
	// A repair goes through UninstallTunnel directly and so leaves them armed.
	s.chainBeforeStop(tunnelName)
	// Pack 64: a plain tunnel lets its IPv6 filter go when it stops.
	chainPlainTunnelStopped(tunnelName)
	s.chainStopChildren(tunnelName, 0)
	// Pack 101: a raise still waiting for its parent is called off, and a
	// service stuck in StartPending is ended if it ignores the Stop.
	chainViaCancel(tunnelName)
	startingPid := chainStartingPid(tunnelName)
	err := UninstallTunnel(tunnelName)
	chainKillStarting(tunnelName, startingPid)

	// AwgChain patch 16: a hidden hop is of no use once the tunnel that rode on
	// it is gone, so it stands down as well.
	s.chainStopHiddenParents(tunnelName, 0)
	if err == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		_, notExistsError := conf.LoadFromName(tunnelName)
		if notExistsError == nil {
			return nil
		}
	}
	return err
}

func (s *ManagerService) WaitForStop(tunnelName string) error {
	serviceName, err := services.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return err
	}
	m, err := serviceManager()
	if err != nil {
		return err
	}
	for {
		service, err := m.OpenService(serviceName)
		if err == nil || err == windows.ERROR_SERVICE_MARKED_FOR_DELETE {
			service.Close()
			time.Sleep(time.Second / 3)
		} else {
			return nil
		}
	}
}

func (s *ManagerService) Delete(tunnelName string) error {
	if s.elevatedToken == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	err := s.Stop(tunnelName)
	if err != nil {
		return err
	}
	return conf.DeleteName(tunnelName)
}

func (s *ManagerService) State(tunnelName string) (TunnelState, error) {
	serviceName, err := services.ServiceNameOfTunnel(tunnelName)
	if err != nil {
		return 0, err
	}
	m, err := serviceManager()
	if err != nil {
		return 0, err
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return TunnelStopped, nil
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		// Pack 70: the query failure is reported instead of being laundered
		// into a silent Unknown that the UI then caches.
		return TunnelUnknown, err
	}
	switch status.State {
	case svc.Stopped:
		return TunnelStopped, nil
	case svc.StopPending:
		return TunnelStopping, nil
	case svc.Running:
		return TunnelStarted, nil
	case svc.StartPending:
		return TunnelStarting, nil
	default:
		return TunnelUnknown, nil
	}
}

func (s *ManagerService) GlobalState() TunnelState {
	return trackedTunnelsGlobalState()
}

func (s *ManagerService) Create(tunnelConfig *conf.Config) (*Tunnel, error) {
	if s.elevatedToken == 0 {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	err := tunnelConfig.Save(true)
	if err != nil {
		return nil, err
	}
	return &Tunnel{tunnelConfig.Name}, nil
	// TODO: handle already existing situation
	// TODO: handle already running and existing situation
}

func (s *ManagerService) Tunnels() ([]Tunnel, error) {
	names, err := conf.ListConfigNames()
	if err != nil {
		return nil, err
	}
	tunnels := make([]Tunnel, len(names))
	for i := 0; i < len(tunnels); i++ {
		tunnels[i].Name = names[i]
	}
	return tunnels, nil
	// TODO: account for running ones that aren't in the configuration store somehow
}

func (s *ManagerService) Quit(stopTunnelsOnQuit bool) (alreadyQuit bool, err error) {
	if s.elevatedToken == 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	if !atomic.CompareAndSwapUint32(&haveQuit, 0, 1) {
		return true, nil
	}

	// Work around potential race condition of delivering messages to the wrong process by removing from notifications.
	managerServicesLock.Lock()
	s.eventLock.Lock()
	s.events = nil
	s.eventLock.Unlock()
	delete(managerServices, s)
	managerServicesLock.Unlock()

	// AwgChain pack 67: strict and paranoid mode keep the chain running when
	// the window is closed, because those modes promise that nothing leaves
	// the machine outside the tunnel.
	if stopTunnelsOnQuit && chainQuitMayStopTunnels() {
		names, err := conf.ListConfigNames()
		if err != nil {
			return false, err
		}
		for _, name := range names {
			UninstallTunnel(name)
		}
	}

	quitManagersChan <- struct{}{}
	return false, nil
}

func (s *ManagerService) UpdateState() UpdateState {
	return updateState
}

func (s *ManagerService) Update() {
	if s.elevatedToken == 0 {
		return
	}
	progress := updater.DownloadVerifyAndExecute(uintptr(s.elevatedToken))
	go func() {
		for {
			dp := <-progress
			IPCServerNotifyUpdateProgress(dp)
			if dp.Complete || dp.Error != nil {
				return
			}
		}
	}()
}

func (s *ManagerService) ServeConn(reader io.Reader, writer io.Writer) {
	decoder := gob.NewDecoder(reader)
	encoder := gob.NewEncoder(writer)
	for {
		var methodType MethodType
		err := decoder.Decode(&methodType)
		if err != nil {
			return
		}
		switch methodType {
		case StoredConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.StoredConfig(tunnelName)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case RuntimeConfigMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			config, retErr := s.RuntimeConfig(tunnelName)
			if config == nil {
				config = &conf.Config{}
			}
			err = encoder.Encode(*config)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StartMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			// Pack 68 (I5): a raise asked for from the window is the one
			// thing that lets the lock arm again after it was lifted by
			// hand.
			chainLockSuppress(false)
			retErr := s.Start(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			// Pack 69 (J1): a stop asked for from the window is the user
			// saying "I do not want this running", and the start-up raise
			// has to know about it.
			// Pack 70: the note is written after the stop, and only when
			// the stop worked. A refused stop used to leave the tunnel
			// running and marked as "switched off by hand", so the
			// start-up raise then ignored the tunnel that was up.
			// WarpAm pack 107: whatever goes through this tunnel, directly
			// or further up, goes down first, the farthest first. The
			// window asks before; this catches a stop without the window.
			// It is only here, in the stop asked for by the user, so a
			// repair of one tunnel never takes the tunnels above with it.
			// WarpAm pack 110: true, the riders are switched off by the
			// user too and must not come back at the next boot.
			s.chainViaStopRiders(tunnelName, "", true)
			retErr := s.Stop(tunnelName)
			if retErr == nil {
				ChainNoteTunnelDown(tunnelName)
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case WaitForStopMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.WaitForStop(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case DeleteMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			retErr := s.Delete(tunnelName)
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case StateMethodType:
			var tunnelName string
			err := decoder.Decode(&tunnelName)
			if err != nil {
				return
			}
			state, retErr := s.State(tunnelName)
			err = encoder.Encode(state)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case GlobalStateMethodType:
			state := s.GlobalState()
			err = encoder.Encode(state)
			if err != nil {
				return
			}
		case CreateMethodType:
			var config conf.Config
			err := decoder.Decode(&config)
			if err != nil {
				return
			}
			tunnel, retErr := s.Create(&config)
			if tunnel == nil {
				tunnel = &Tunnel{}
			}
			err = encoder.Encode(tunnel)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case TunnelsMethodType:
			tunnels, retErr := s.Tunnels()
			err = encoder.Encode(tunnels)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case QuitMethodType:
			var stopTunnelsOnQuit bool
			err := decoder.Decode(&stopTunnelsOnQuit)
			if err != nil {
				return
			}
			alreadyQuit, retErr := s.Quit(stopTunnelsOnQuit)
			err = encoder.Encode(alreadyQuit)
			if err != nil {
				return
			}
			err = encoder.Encode(errToString(retErr))
			if err != nil {
				return
			}
		case UpdateStateMethodType:
			updateState := s.UpdateState()
			err = encoder.Encode(updateState)
			if err != nil {
				return
			}
		case ChainPickListMethodType:
                    err := s.chainServePickList(encoder)
                    if err != nil {
                        return
                    }
                case UpdateMethodType:
			s.Update()
		case ChainSettingsGetMethodType:
			if chainErr := s.chainServeSettingsGet(decoder, encoder); chainErr != nil {
				return
			}
		case ChainSettingsSetMethodType:
			if chainErr := s.chainServeSettingsSet(decoder, encoder); chainErr != nil {
				return
			}
		case ChainGlobalGetMethodType:
			if chainErr := s.chainServeGlobalGet(encoder); chainErr != nil {
				return
			}
		case ChainGlobalSetMethodType:
			if chainErr := s.chainServeGlobalSet(decoder, encoder); chainErr != nil {
				return
			}
		case ChainLiftLockMethodType:
			if chainErr := s.chainServeLiftLock(encoder); chainErr != nil {
				return
			}
		case ChainLiftLockOnQuitMethodType:
			if chainErr := s.chainServeLiftLockOnQuit(encoder); chainErr != nil {
				return
			}
		// Pack 71: the other direction of the lock button.
		case ChainArmLockMethodType:
			if chainErr := s.chainServeArmLock(encoder); chainErr != nil {
				return
			}
		case ChainStatusMethodType:
			err = s.chainServeStatus(encoder)
			if err != nil {
				return
			}
		// Pack 85: the log page can ask for the ring to be emptied. Only the
		// manager holds the mapping for writing, the windows open it read
		// only, so the button has to come through here.
		case ChainClearLogMethodType:
			if chainErr := s.chainServeClearLog(encoder); chainErr != nil {
				return
			}
		// Pack 86: the box and the two buttons of the portable mode. The files
		// are sealed for the system account, so only the manager can seal and
		// unseal them, and only the manager can change the rights of the data
		// folder.
		case ChainSecureMethodType:
			if chainErr := s.chainServeSecure(decoder, encoder); chainErr != nil {
				return
			}
		// WarpAm pack 110: the lines of the window (chainguilog.go).
		case ChainGuiLogMethodType:
			if chainErr := s.chainServeGuiLog(decoder); chainErr != nil {
				return
			}
		// WarpAm pack 111: what a raise would switch off (chainstartask.go).
		case ChainStartVictimsMethodType:
			if chainErr := s.chainServeStartVictims(decoder, encoder); chainErr != nil {
				return
			}
		// WarpAm pack 112: the same key (chainkeyclash.go), the length of
		// a chain (chainlength.go) and the MTU tab (chainmtu.go).
		case ChainKeyClashesMethodType:
			if chainErr := s.chainServeKeyClashes(decoder, encoder); chainErr != nil {
				return
			}
		case ChainKeyClashAcceptMethodType:
			if chainErr := s.chainServeKeyClashAccept(decoder, encoder); chainErr != nil {
				return
			}
		case ChainLengthCheckMethodType:
			if chainErr := s.chainServeLengthCheck(decoder, encoder); chainErr != nil {
				return
			}
		case ChainMTUTableMethodType:
			if chainErr := s.chainServeMTUTable(decoder, encoder); chainErr != nil {
				return
			}
		case ChainMTUActionMethodType:
			if chainErr := s.chainServeMTUAction(decoder, encoder); chainErr != nil {
				return
			}
		default:
			return
		}
	}
}

func IPCServerListen(reader, writer, events *os.File, elevatedToken windows.Token) {
	service := &ManagerService{
		events:        events,
		elevatedToken: elevatedToken,
	}
	// AwgChain pack 67: the start-up raise used to be started here, that is
	// once per window. It never ran when nobody logged on, and it ran again
	// every time the window was restarted. It now lives in the manager
	// service itself (chainBootOnce, called from Execute).

	go func() {
		managerServicesLock.Lock()
		managerServices[service] = true
		managerServicesLock.Unlock()
		service.ServeConn(reader, writer)
		managerServicesLock.Lock()
		service.eventLock.Lock()
		service.events = nil
		service.eventLock.Unlock()
		delete(managerServices, service)
		managerServicesLock.Unlock()
	}()
}

func notifyAll(notificationType NotificationType, adminOnly bool, ifaces ...any) {
	if len(managerServices) == 0 {
		return
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(notificationType)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		err = encoder.Encode(iface)
		if err != nil {
			return
		}
	}

	managerServicesLock.RLock()
	for m := range managerServices {
		if m.elevatedToken == 0 && adminOnly {
			continue
		}
		go func(m *ManagerService) {
			m.eventLock.Lock()
			defer m.eventLock.Unlock()
			if m.events != nil {
				m.events.SetWriteDeadline(time.Now().Add(time.Second))
				m.events.Write(buf.Bytes())
			}
		}(m)
	}
	managerServicesLock.RUnlock()
}

func errToString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func IPCServerNotifyTunnelChange(name string, state TunnelState, err error) {
	notifyAll(TunnelChangeNotificationType, false, name, state, trackedTunnelsGlobalState(), errToString(err))
}

func IPCServerNotifyTunnelsChange() {
	notifyAll(TunnelsChangeNotificationType, false)
}

func IPCServerNotifyUpdateFound(state UpdateState) {
	notifyAll(UpdateFoundNotificationType, false, state)
}

func IPCServerNotifyUpdateProgress(dp updater.DownloadProgress) {
	notifyAll(UpdateProgressNotificationType, true, dp.Activity, dp.BytesDownloaded, dp.BytesTotal, errToString(dp.Error), dp.Complete)
}

func IPCServerNotifyManagerStopping() {
	notifyAll(ManagerStoppingNotificationType, false)
	time.Sleep(time.Millisecond * 200)
}

// chainQuietPipeClose says whether this pipe error is the ordinary end of a
// conversation rather than a fault worth reporting.
func chainQuietPipeClose(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "closed") || strings.Contains(text, "broken pipe")
}