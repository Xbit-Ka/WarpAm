//go:build windows

/* WarpAm pack 101: the tunnel named in "through another tunnel" is raised
 * first, by the manager, and the raise can be called off.
 *
 * Pack 100 left the parent to the user. When it was down, the service of
 * the child waited twenty seconds for its adapter and then went straight
 * out, past the parent. Now:
 *
 *   the child is asked for, the parent is down -> the manager raises the
 *       parent, waits for its handshake, and only then raises the child
 *   the parent does not come up -> the child is not raised at all and the
 *       window says why
 *   the parent is already up -> the child just uses it (a second child
 *       does the same)
 *   Stop on the child while this goes on -> the wait ends at once, the
 *       child is not raised; the parent stays up, it only goes down by hand
 *
 * The wait runs in its own goroutine and Start answers at once. The client
 * holds one lock for all its calls, so a Start that waited inside the call
 * kept the Stop of the same window waiting behind it; that was the dead
 * stop button of the log of 5 October.
 *
 * A service that hangs in StartPending ignores Stop (it accepts nothing
 * until Running). chainKillStarting ends its process instead.
 */

package manager

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/services"
)

// chainViaKillAfter is how long a stopped service may stay in StartPending
// before its process is ended.
const chainViaKillAfter = 3 * time.Second

var errChainViaCancelled = errors.New("the raise was called off by Stop")

type chainViaRaise struct {
	cancel chan struct{}
	once   sync.Once
}

var chainViaRaising = struct {
	sync.Mutex
	m map[string]*chainViaRaise
}{m: make(map[string]*chainViaRaise)}

// chainViaParentName is the tunnel this one is set to go through, or an
// empty string. The settings are normalised, so the box only counts in the
// modes where the service uses it.
func chainViaParentName(name string) string {
	st := ChainSettingsFor(name)
	if !st.ProxyVia {
		return ""
	}
	via := strings.TrimSpace(st.ProxyViaTunnel)
	if len(via) == 0 || strings.EqualFold(via, name) {
		return ""
	}
	names, err := conf.ListConfigNames()
	if err != nil {
		return ""
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimSpace(n), via) {
			return n
		}
	}
	return ""
}

// chainViaLeadsBack follows the parents of parent and reports whether the
// walk comes back to name. Such a pair would raise each other for ever.
func chainViaLeadsBack(name, parent string) bool {
	at := parent
	for i := 0; i < chainMaxDepth*2; i++ {
		if strings.EqualFold(at, name) {
			return true
		}
		next := chainViaParentName(at)
		if len(next) == 0 {
			next = chainParentName(at)
		}
		if len(next) == 0 {
			return false
		}
		at = next
	}
	return true
}

// chainViaRaiseFirst is called by Start. It answers true when the raise of
// name goes on in the background (or was refused with the error).
func (s *ManagerService) chainViaRaiseFirst(name string) (bool, error) {
	parent := chainViaParentName(name)
	if len(parent) == 0 {
		return false, nil
	}
	if chainViaLeadsBack(name, parent) {
		log.Printf("[%s] Via: %s leads back to this tunnel, not raised", name, parent)
		return true, fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435\u043b\u044c\u0437\u044f \u043f\u043e\u0434\u043d\u044f\u0442\u044c: \u0442\u0443\u043d\u043d\u0435\u043b\u044c %s, \u0447\u0435\u0440\u0435\u0437 \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u043e\u043d \u0434\u043e\u043b\u0436\u0435\u043d \u0438\u0434\u0442\u0438, \u0441\u0430\u043c \u0438\u0434\u0451\u0442 \u0447\u0435\u0440\u0435\u0437 \u043d\u0435\u0433\u043e.", name, parent)
	}
	if state, err := s.State(parent); err == nil && state == TunnelStarted && s.chainHopHandshook(parent) {
		return false, nil
	}
	key := strings.ToLower(name)
	chainViaRaising.Lock()
	if _, busy := chainViaRaising.m[key]; busy {
		chainViaRaising.Unlock()
		return true, nil
	}
	r := &chainViaRaise{cancel: make(chan struct{})}
	chainViaRaising.m[key] = r
	chainViaRaising.Unlock()

	log.Printf("[%s] Via: %s is not up yet, raising it first", name, parent)
	IPCServerNotifyTunnelChange(name, TunnelStarting, nil)
	go func() {
		err := s.chainViaRaiseRun(name, parent, r)
		chainViaRaising.Lock()
		delete(chainViaRaising.m, key)
		chainViaRaising.Unlock()
		switch {
		case err == errChainViaCancelled:
			log.Printf("[%s] Via: called off, %s stays as it is", name, parent)
			IPCServerNotifyTunnelChange(name, TunnelStopped, nil)
		case err != nil:
			log.Printf("[%s] Via: not raised: %v", name, err)
			// WarpAm pack 111: a raise waiting on this one stops at once.
			chainViaNoteFailed(name, err)
			IPCServerNotifyTunnelChange(name, TunnelStopped, err)
		}
	}()
	return true, nil
}

func (r *chainViaRaise) stopped() bool {
	select {
	case <-r.cancel:
		return true
	default:
		return false
	}
}

// chainViaRaiseRun raises the parent when it is down, waits for its
// handshake and raises the child. It never lowers the parent.
func (s *ManagerService) chainViaRaiseRun(name, parent string, r *chainViaRaise) error {
	since := time.Now()
	if state, err := s.State(parent); err == nil && state == TunnelStopped {
		if err := s.chainStartHopWithRetry(parent); err != nil {
			return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435 \u043f\u043e\u0434\u043d\u044f\u043b\u0441\u044f, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 %s \u043d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d: %v", parent, name, err)
		}
	}
	deadline := time.Now().Add(chainHopUpTimeout)
	for {
		if r.stopped() {
			return errChainViaCancelled
		}
		state, err := s.State(parent)
		if err == nil && state == TunnelStarted && s.chainHopHandshook(parent) {
			break
		}
		// WarpAm pack 111: the parent may itself be raised through another
		// tunnel, in the background. Its refusal used to reach nobody here,
		// so 100 waited the full 45 seconds for Elena, who had been refused
		// for her port in the very first second.
		if perr := chainViaFailedSince(parent, since); perr != nil {
			log.Printf("[%s] Via: %s was refused, so this tunnel is not raised either", name, parent)
			return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435 \u043f\u043e\u0434\u043d\u044f\u043b\u0441\u044f, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 %s \u043d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d: %v", parent, name, perr)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("\u0422\u0443\u043d\u043d\u0435\u043b\u044c %s \u043d\u0435 \u043f\u043e\u0434\u043d\u044f\u043b\u0441\u044f \u0437\u0430 %d \u0441\u0435\u043a\u0443\u043d\u0434, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 %s \u043d\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d.", parent, int(chainHopUpTimeout/time.Second), name)
		}
		select {
		case <-r.cancel:
			return errChainViaCancelled
		case <-time.After(chainPollInterval):
		}
	}
	log.Printf("[%s] Via: %s is up and handshook, raising this tunnel now", name, parent)
	return s.Start(name)
}

// chainViaCancel calls off a raise that waits for its parent. It reports
// whether there was one.
func chainViaCancel(name string) bool {
	chainViaRaising.Lock()
	r := chainViaRaising.m[strings.ToLower(name)]
	chainViaRaising.Unlock()
	if r == nil {
		return false
	}
	r.once.Do(func() { close(r.cancel) })
	log.Printf("[%s] Via: Stop arrived while waiting for the tunnel underneath", name)
	return true
}

// chainStartingPid is the process of a tunnel service that is still in
// StartPending, or 0.
func chainStartingPid(name string) uint32 {
	m, err := serviceManager()
	if err != nil {
		return 0
	}
	serviceName, err := services.ServiceNameOfTunnel(name)
	if err != nil {
		return 0
	}
	service, err := m.OpenService(serviceName)
	if err != nil {
		return 0
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil || status.State != svc.StartPending {
		return 0
	}
	return status.ProcessId
}

// chainKillStarting is called after a Stop. A service still in
// StartPending a few seconds later has ignored it, so its process is ended.
// The pid is checked again just before, so a process that has since gone
// (and whose number may have been reused) is left alone.
func chainKillStarting(name string, pid uint32) {
	if pid == 0 {
		return
	}
	go func() {
		time.Sleep(chainViaKillAfter)
		if chainStartingPid(name) != pid {
			return
		}
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
		if err != nil {
			log.Printf("[%s] Stop: the service is still starting and cannot be ended: %v", name, err)
			return
		}
		defer windows.CloseHandle(h)
		// WarpAm pack 111: written first, so that the error Windows reports
		// for the ended process is not shown as an error of the tunnel.
		chainNoteKilled(name)
		if err := windows.TerminateProcess(h, 1); err != nil {
			log.Printf("[%s] Stop: could not end the starting service: %v", name, err)
			return
		}
		log.Printf("[%s] Stop: the service ignored Stop while starting, its process %d was ended", name, pid)
		IPCServerNotifyTunnelChange(name, TunnelStopped, nil)
	}()
}
