/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/debuglog"
	"github.com/amnezia-vpn/amneziawg-windows/v3/elevate"
	"github.com/amnezia-vpn/amneziawg-windows/v3/ringlogger"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
	"github.com/amnezia-vpn/amneziawg-windows/v3/version"
)

type tunnelService struct {
	Path string
}

func (service *tunnelService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	var dev *device.Device
	var uapi net.Listener
	var watcher *interfaceWatcher
	var nativeTun *tun.NativeTun
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		svcSpecificEC, exitCode = services.DetermineErrorCode(err, serviceError)
		logErr := services.CombineErrors(err, serviceError)
		if logErr != nil {
			log.Println(logErr)
		}
		changes <- svc.Status{State: svc.StopPending}

		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			for {
				select {
				case <-t.C:
					t.Stop()
					buf := make([]byte, 1024)
					for {
						n := runtime.Stack(buf, true)
						if n < len(buf) {
							buf = buf[:n]
							break
						}
						buf = make([]byte, 2*len(buf))
					}
					lines := bytes.Split(buf, []byte{'\n'})
					log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
					for _, line := range lines {
						if len(bytes.TrimSpace(line)) > 0 {
							log.Println(string(line))
						}
					}
					os.Exit(777)
					return
				case <-stopIt:
					t.Stop()
					return
				}
			}
		}()

		if logErr == nil && dev != nil && config != nil {
			logErr = runScriptCommand(config.Interface.PreDown, config.Name)
		}
		if config != nil {
			// AwgChain: the host route goes down with the tunnel that needed it.
			chainPinRoutes(config, false)
			// AwgChain pack 82: and so does the route a proxy tunnel laid on
			// the network card it chose for itself.
			ChainProxyWayForget(config)
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if uapi != nil {
			uapi.Close()
		}
		if dev != nil {
			dev.Close()
		}
		if logErr == nil && dev != nil && config != nil {
			_ = runScriptCommand(config.Interface.PostDown, config.Name)
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	err = ringlogger.InitGlobalLogger("TUN")
	if err != nil {
		serviceError = services.ErrorRingloggerOpen
		return
	}

	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	config.DeduplicateNetworkEntries()
	err = CopyConfigOwnerToIPCSecurityDescriptor(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))
	// WarpAm pack 110: the debug file of this tunnel (core/debuglog).
	debuglog.Start("TUN")

	log.Println("Starting", version.UserAgent())

	// AwgChain pack 86: the configuration this tunnel was really started
	// with is written down in one line: a short fingerprint of everything
	// that has to match the server, and the obfuscation parameters spelled
	// out. The weekend of 27 September was lost to a configuration that
	// spoke a different version of the protocol than the server, and no log
	// of ours could have shown it. Secrets are not in the line: the private
	// key enters the digest only as a hash.
	log.Printf("[WarpAm] Configuration loaded: %s", config.ChainFingerprintLine())
	// WarpAm pack 94: a size overlap between handshake and transport
	// packets is named once at every start of the tunnel.
	for _, overlap := range config.ChainSizeOverlaps() {
		log.Printf("[WarpAm] Size overlap: %s. The engine tells them apart since pack 94; another S value on both sides avoids the overlap", overlap)
	}
	// WarpAm pack 96: the inner hop of a chain gets the MTU that fits into
	// the outer one. Chains built before pack 96 carry a fixed 1360 in the
	// file, which does not count S4, so the value is checked at every start
	// and not only when a chain is built. A smaller MTU of the file is kept.
	if conf.ChainIsHiddenHopName(config.Interface.PinEndpointVia) {
		if want := conf.ChainInnerMTU(config); want != config.Interface.MTU {
			log.Printf("[WarpAm] Chain MTU: %d in the file does not fit into the outer hop (MTU %d, S4 %d), using %d", config.Interface.MTU, conf.ChainHop1MTU, config.Interface.TransportPacketJunkSize, want)
			config.Interface.MTU = want
		} else {
			log.Printf("[WarpAm] Chain MTU: %d fits into the outer hop (MTU %d, S4 %d)", want, conf.ChainHop1MTU, config.Interface.TransportPacketJunkSize)
		}
	}

	if m, err := mgr.Connect(); err == nil {
		if lockStatus, err := m.LockStatus(); err == nil && lockStatus.IsLocked {
			/* If we don't do this, then the Wintun installation will block forever, because
			 * installing a Wintun device starts a service too. Apparently at boot time, Windows
			 * 8.1 locks the SCM for each service start, creating a deadlock if we don't announce
			 * that we're running before starting additional services.
			 */
			log.Printf("SCM locked for %v by %s, marking service as started", lockStatus.Age, lockStatus.Owner)
			changes <- svc.Status{State: svc.Running}
		}
		m.Disconnect()
	}

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return
	}

	log.Println("Resolving DNS names")
	uapiConf, err := config.ToUAPI()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return
	}

	log.Println("Creating Wintun interface")
	// WarpAm pack 113: an adapter with the same GUID that Windows is still
	// removing makes Wintun wait 15 seconds and fail, so it is waited for
	// first (chainadapterwait.go).
	chainWaitOldAdapter(config)
	debuglog.Fire("adapter-create-begin", config.Name)
	var wintun tun.Device
	for i := 0; i < 5; i++ {
		if i > 0 {
			if windows.DurationSinceBoot() > time.Minute*4 {
				// WarpAm pack 107: Windows is often still removing the
				// adapters of tunnels that were just switched off, so one
				// more try after a pause is worth it.
				log.Printf("[WarpAm] Windows did not make the adapter in time (try %d of %d), trying again in %v: %v", i, chainWintunTries, chainWintunPause, err)
				time.Sleep(chainWintunPause)
			} else {
				time.Sleep(time.Second)
				log.Printf("Retrying Wintun creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
			}
		}
		wintun, err = tun.CreateTUNWithRequestedGUID(config.Name, deterministicGUID(config), 0)
		if err == nil || (windows.DurationSinceBoot() > time.Minute*4 && i+1 >= chainWintunTries) {
			break
		}
	}
	debuglog.Fire("adapter-create-end", config.Name, err)
	if err != nil {
		log.Printf("[WarpAm] Windows did not make the network adapter of %s: %v. This happens when a tunnel is switched on right after others were switched off and Windows is still removing their adapters. Wait 30 seconds and switch it on again", config.Name, err)
		serviceError = services.ErrorCreateWintun
		return
	}
	nativeTun = wintun.(*tun.NativeTun)
	wintunVersion, err := nativeTun.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine Wintun version: %v", err)
	} else {
		log.Printf("Using Wintun/%d.%d", (wintunVersion>>16)&0xffff, wintunVersion&0xffff)
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	// WarpAm pack 100: a proxy tunnel may ride over another tunnel of the
	// program. This only fills PinEndpointVia and MTU in memory, so it has
	// to come before the pinned routes below.
	chainProxyViaApply(config)

	// WarpAm pack 112: the own maximum of the MTU tab, when one is known
	// in this network, counts the stack anew (chainmtuuse.go).
	chainMTUFromBook(config)

	// AwgChain: IP_UNICAST_IF alone does not survive the routes that the hop
	// above installs, so give the endpoint of this hop a host route on the
	// adapter it is pinned to. No PinEndpointVia, nothing happens.
	chainPinRoutes(config, true)

	// WarpAm pack 100: the address swap is planned before the adapter gets
	// its address and before the engine gets the adapter. The firewall and
	// the watcher keep nativeTun, only the engine sees the wrapper.
	chainAddrSwapPlan(config)

	err = enableFirewall(config, nativeTun)
	if err != nil {
		serviceError = services.ErrorFirewall
		return
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return
	}

	log.Println("Creating interface instance")
	bind := conn.NewDefaultBind()
	dev = device.NewDevice(chainAddrSwapWrap(wintun), bind, &device.Logger{log.Printf, log.Printf})

	log.Println("Setting interface configuration")
	uapi, err = ipc.UAPIListen(config.Name)
	if err != nil {
		serviceError = services.ErrorUAPIListen
		return
	}
	err = dev.IpcSet(uapiConf)
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return
	}

	// WarpAm pack 95: the size dodge of the engine, on unless the settings
	// book says SizeDodgeOff, and the check of the config, which only logs.
	sizeDodge := chainSizeDodgeOn()
	dev.SetSizeDodge(sizeDodge)
	chainSizeCheck(config, sizeDodge)

	// Pack 101: no way out past the hop underneath. When its adapter never
	// came, the service stops with an error instead of going direct.
	if !chainWaitForPinBeforeUp(config) {
		err = fmt.Errorf("the tunnel underneath (%s) is not up, so this tunnel is not brought up", config.Interface.PinEndpointVia)
		serviceError = services.ErrorBindSocketsToDefaultRoutes
		return
	}

	log.Println("Bringing peers up")
	dev.Up()

	watcher.Configure(bind.(conn.BindSocketToInterface), config, nativeTun)
	// WarpAm pack 107: the first handshake went out before the socket was
	// pinned and was lost, which cost 5 seconds. It is sent again now.
	chainHandshakeAfterPin(dev, config)

	log.Println("Listening for UAPI requests")
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				continue
			}
			go dev.IpcHandle(conn)
		}
	}()

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return
	}

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Println("Startup complete")
	debuglog.Fire("tunnel-ready", config.Name, dev.IpcGet)

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				return
			case svc.Interrogate:
				changes <- c.CurrentStatus
			default:
				log.Printf("Unexpected service control request #%d\n", c)
			}
		case <-dev.Wait():
			return
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return
		}
	}
}

func Run(confPath string) error {
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		return err
	}
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return err
	}
	return svc.Run(serviceName, &tunnelService{confPath})
}
