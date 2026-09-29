/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 79: the "Proxy" tab.
 *
 * Every proxy setting belongs to one tunnel now, so the tab follows the
 * tunnel that is selected on the "Tunnels" tab: its title reads
 * "name - proxy" and the boxes show the settings of that tunnel only.
 *
 * The rule of this pack is "grey means not saved": the top box owns
 * everything below it, the binding owns the login, and save() derives
 * what it writes from the same boxes the screen greys out. A combination
 * that cannot be shown cannot be written.
 */

package ui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

// The values behind the lists, in the order of their texts.
var (
	chainProxyProtoValues = []string{
		manager.ChainProxyProtoSocks5,
		manager.ChainProxyProtoHTTP,
		manager.ChainProxyProtoBoth,
	}
	chainProxyProtoTexts = []string{
		chainProxyProtoSocks,
		chainProxyProtoHTTP,
		chainProxyProtoBoth,
	}
	chainProxyBindValues = []string{
		manager.ChainProxyBindLoopback,
		manager.ChainProxyBindLAN,
	}
	chainProxyBindTexts = []string{
		chainProxyBindLocal,
		chainProxyBindLAN,
	}
	chainProxyDownValues = []string{
		manager.ChainProxyDownError,
		manager.ChainProxyDownClose,
	}
	chainProxyDownTexts = []string{
		chainProxyDownError,
		chainProxyDownClose,
	}
)

// ProxyPage is the tab. One tunnel at a time, the one the tunnel list is
// standing on.
type ProxyPage struct {
	*walk.TabPage

	// tunnel is the name whose settings are on screen. Empty means the
	// tunnel list has no selection and the whole tab is grey.
	tunnel string

	enableCB *walk.CheckBox
	protoCombo *walk.ComboBox
	portNE     *walk.NumberEdit
	bindCombo  *walk.ComboBox
	userLE     *walk.LineEdit
	passLE     *walk.LineEdit
	splitCB    *walk.CheckBox
	downCombo  *walk.ComboBox
	graceNE    *walk.NumberEdit

	hintLabel  *walk.TextLabel
	stateLabel *walk.TextLabel

	// hash is the password hash that is already saved for this tunnel.
	// The box on screen is always empty, so an empty box means "keep the
	// password" and not "there is no password".
	hash string

	loading bool
	// loaded is false until reload has really read the settings of a
	// tunnel. Until then the boxes hold nothing but their defaults and
	// writing them back would erase the file.
	loaded bool

	saveMu    sync.Mutex
	saveTimer *time.Timer
}

// chainProxyRow is one line of the tab with no indent, the same strip the
// Settings tab uses.
func chainProxyRow(parent walk.Container) (*walk.Composite, error) {
	row, err := walk.NewComposite(parent)
	if err != nil {
		return nil, err
	}
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{0, 0, 0, 0})
	layout.SetSpacing(6)
	if err = row.SetLayout(layout); err != nil {
		return nil, err
	}
	return row, nil
}

func NewProxyPage() (*ProxyPage, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	pp := new(ProxyPage)
	var err error
	if pp.TabPage, err = walk.NewTabPage(); err != nil {
		return nil, err
	}
	disposables.Add(pp)

	pp.SetTitle(chainProxyTabTitle)

	layout := walk.NewVBoxLayout()
	layout.SetMargins(walk.Margins{18, 18, 18, 18})
	layout.SetSpacing(8)
	if err = pp.SetLayout(layout); err != nil {
		return nil, err
	}

	// 1. The master box. Everything below it lives and dies with it.
	enableRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	if pp.enableCB, err = walk.NewCheckBox(enableRow); err != nil {
		return nil, err
	}
	pp.enableCB.SetText(chainProxyEnableLabel)
	pp.enableCB.SetToolTipText(chainProxyEnableHint)
	pp.enableCB.CheckedChanged().Attach(func() {
		pp.follow()
		pp.queueSave()
	})
	if _, err = walk.NewHSpacer(enableRow); err != nil {
		return nil, err
	}

	// 2. Protocol and port.
	protoRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	protoLabel, err := walk.NewTextLabel(protoRow)
	if err != nil {
		return nil, err
	}
	protoLabel.SetText(chainProxyProtoLabel)
	if pp.protoCombo, err = walk.NewComboBox(protoRow); err != nil {
		return nil, err
	}
	pp.protoCombo.SetModel(chainProxyProtoTexts)
	pp.protoCombo.SetCurrentIndex(0)
	pp.protoCombo.SetToolTipText(chainProxyProtoHint)
	pp.protoCombo.CurrentIndexChanged().Attach(pp.queueSave)
	portLabel, err := walk.NewTextLabel(protoRow)
	if err != nil {
		return nil, err
	}
	portLabel.SetText(chainProxyPortLabel)
	if pp.portNE, err = walk.NewNumberEdit(protoRow); err != nil {
		return nil, err
	}
	pp.portNE.SetDecimals(0)
	pp.portNE.SetRange(1, 65535)
	pp.portNE.SetValue(float64(manager.ChainProxyDefaultPort))
	pp.portNE.SetToolTipText(chainProxyPortHint)
	pp.portNE.ValueChanged().Attach(pp.queueSave)
	if _, err = walk.NewHSpacer(protoRow); err != nil {
		return nil, err
	}

	// 3. Who may use the port.
	bindRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	bindLabel, err := walk.NewTextLabel(bindRow)
	if err != nil {
		return nil, err
	}
	bindLabel.SetText(chainProxyBindLabel)
	if pp.bindCombo, err = walk.NewComboBox(bindRow); err != nil {
		return nil, err
	}
	pp.bindCombo.SetModel(chainProxyBindTexts)
	pp.bindCombo.SetCurrentIndex(0)
	pp.bindCombo.SetToolTipText(chainProxyBindHint)
	pp.bindCombo.CurrentIndexChanged().Attach(func() {
		pp.follow()
		pp.queueSave()
	})
	if _, err = walk.NewHSpacer(bindRow); err != nil {
		return nil, err
	}

	// 4. The login of the local network mode.
	loginRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	userLabel, err := walk.NewTextLabel(loginRow)
	if err != nil {
		return nil, err
	}
	userLabel.SetText(chainProxyUserLabel)
	if pp.userLE, err = walk.NewLineEdit(loginRow); err != nil {
		return nil, err
	}
	pp.userLE.EditingFinished().Attach(pp.queueSave)
	passLabel, err := walk.NewTextLabel(loginRow)
	if err != nil {
		return nil, err
	}
	passLabel.SetText(chainProxyPassLabel)
	if pp.passLE, err = walk.NewLineEdit(loginRow); err != nil {
		return nil, err
	}
	pp.passLE.SetPasswordMode(true)
	pp.passLE.SetToolTipText(chainProxyPassHint)
	pp.passLE.EditingFinished().Attach(pp.queueSave)
	if _, err = walk.NewHSpacer(loginRow); err != nil {
		return nil, err
	}

	// 5. Split mode: the tunnel carries the proxy and nothing else.
	splitRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	if pp.splitCB, err = walk.NewCheckBox(splitRow); err != nil {
		return nil, err
	}
	pp.splitCB.SetText(chainProxySplitLabel)
	pp.splitCB.SetToolTipText(chainProxySplitHint)
	pp.splitCB.CheckedChanged().Attach(pp.queueSave)
	if _, err = walk.NewHSpacer(splitRow); err != nil {
		return nil, err
	}

	// 6. What happens when the tunnel is not there.
	downRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	downLabel, err := walk.NewTextLabel(downRow)
	if err != nil {
		return nil, err
	}
	downLabel.SetText(chainProxyDownLabel)
	if pp.downCombo, err = walk.NewComboBox(downRow); err != nil {
		return nil, err
	}
	pp.downCombo.SetModel(chainProxyDownTexts)
	pp.downCombo.SetCurrentIndex(0)
	pp.downCombo.SetToolTipText(chainProxyDownHint)
	pp.downCombo.CurrentIndexChanged().Attach(pp.queueSave)
	graceLabel, err := walk.NewTextLabel(downRow)
	if err != nil {
		return nil, err
	}
	graceLabel.SetText(chainProxyGraceLabel)
	if pp.graceNE, err = walk.NewNumberEdit(downRow); err != nil {
		return nil, err
	}
	pp.graceNE.SetDecimals(0)
	pp.graceNE.SetRange(0, 600)
	pp.graceNE.SetToolTipText(chainProxyGraceHint)
	pp.graceNE.ValueChanged().Attach(pp.queueSave)
	if _, err = walk.NewHSpacer(downRow); err != nil {
		return nil, err
	}

	// 7. The hint line: no tunnel selected, or the login the local
	// network mode insists on.
	hintRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	if pp.hintLabel, err = walk.NewTextLabel(hintRow); err != nil {
		return nil, err
	}
	pp.hintLabel.SetText(chainProxyPickTunnel)
	if _, err = walk.NewHSpacer(hintRow); err != nil {
		return nil, err
	}

	// 8. What the proxy of this tunnel is doing right now.
	stateRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	stateTitle, err := walk.NewTextLabel(stateRow)
	if err != nil {
		return nil, err
	}
	stateTitle.SetText(chainProxyStateTitle + ":")
	if pp.stateLabel, err = walk.NewTextLabel(stateRow); err != nil {
		return nil, err
	}
	pp.stateLabel.SetText(chainProxyStateOff)
	if _, err = walk.NewHSpacer(stateRow); err != nil {
		return nil, err
	}

	if _, err = walk.NewVSpacer(pp); err != nil {
		return nil, err
	}

	pp.VisibleChanged().Attach(func() {
		if pp.Visible() {
			pp.reload()
		}
	})

	pp.follow()
	pp.watchState()

	disposables.Spare()
	return pp, nil
}

// SetTunnel points the tab at another tunnel. An empty name means the
// tunnel list has no selection.
func (pp *ProxyPage) SetTunnel(name string) {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, pp.tunnel) {
		return
	}
	// The save that is still waiting belongs to the tunnel that is
	// leaving, and it must not land on the one that arrives.
	pp.flush()
	pp.tunnel = name
	pp.loaded = false
	if len(name) == 0 {
		pp.SetTitle(chainProxyTabTitle)
	} else {
		pp.SetTitle(fmt.Sprintf(chainProxyTabTitleFor, name))
	}
	pp.reload()
}

// flush writes a pending save out at once, before the page starts showing
// another tunnel.
func (pp *ProxyPage) flush() {
	pp.saveMu.Lock()
	timer := pp.saveTimer
	pp.saveTimer = nil
	pp.saveMu.Unlock()
	if timer == nil {
		return
	}
	if timer.Stop() {
		pp.save()
	}
}

// reload fills the page from the manager without writing anything back.
func (pp *ProxyPage) reload() {
	pp.loading = true
	defer func() {
		pp.loading = false
		pp.follow()
		pp.showState()
	}()

	if len(pp.tunnel) == 0 {
		pp.loaded = false
		pp.enableCB.SetChecked(false)
		pp.splitCB.SetChecked(false)
		pp.userLE.SetText("")
		pp.passLE.SetText("")
		pp.hash = ""
		return
	}

	settings, err := manager.IPCClientChainSettings(pp.tunnel)
	if err != nil {
		// The pipe is not there - the boxes hold whatever was on
		// screen, and that must not be written back.
		pp.loaded = false
		return
	}

	pp.enableCB.SetChecked(settings.Proxy)
	chainProxyPick(pp.protoCombo, chainProxyProtoValues, settings.Protocol())
	chainProxyPick(pp.bindCombo, chainProxyBindValues, settings.Bind())
	chainProxyPick(pp.downCombo, chainProxyDownValues, settings.OnDown())
	pp.portNE.SetValue(float64(settings.Port()))
	pp.graceNE.SetValue(float64(settings.ProxyGrace))
	pp.userLE.SetText(settings.ProxyUser)
	pp.passLE.SetText("")
	pp.hash = settings.ProxyPassHash
	pp.splitCB.SetChecked(settings.ProxySplit)

	pp.loaded = true
}

// follow is the rule of this pack on screen: the top box owns everything
// below it, and the binding owns the login.
func (pp *ProxyPage) follow() {
	has := len(pp.tunnel) > 0
	on := has && pp.enableCB.Checked()

	pp.enableCB.SetEnabled(has)
	pp.protoCombo.SetEnabled(on)
	pp.portNE.SetEnabled(on)
	pp.bindCombo.SetEnabled(on)
	pp.splitCB.SetEnabled(on)
	pp.downCombo.SetEnabled(on)
	pp.graceNE.SetEnabled(on)

	lan := on && chainProxyPicked(pp.bindCombo, chainProxyBindValues, manager.ChainProxyBindLoopback) == manager.ChainProxyBindLAN
	pp.userLE.SetEnabled(lan)
	pp.passLE.SetEnabled(lan)
	if !lan && !pp.loading {
		// Grey means not kept: the login of the loopback mode is
		// cleared on screen as well, so what is shown is what is
		// saved.
		pp.userLE.SetText("")
		pp.passLE.SetText("")
		pp.hash = ""
	}

	switch {
	case !has:
		pp.hintLabel.SetText(chainProxyPickTunnel)
	case lan:
		pp.hintLabel.SetText(chainProxyLoginNeed)
	default:
		pp.hintLabel.SetText("")
	}
}

// queueSave writes the page back once, a short moment after the last
// change, so one click is one write.
func (pp *ProxyPage) queueSave() {
	if pp.loading {
		return
	}

	pp.saveMu.Lock()
	if pp.saveTimer != nil {
		pp.saveTimer.Stop()
	}
	pp.saveTimer = time.AfterFunc(400*time.Millisecond, func() {
		pp.Synchronize(pp.save)
	})
	pp.saveMu.Unlock()
}

// save writes the boxes back into the settings of this tunnel. Everything
// that is grey on screen is derived here and not read from its box, so a
// setting the interface hides can never reach the file.
func (pp *ProxyPage) save() {
	if pp.loading || !pp.loaded || len(pp.tunnel) == 0 {
		return
	}

	settings, err := manager.IPCClientChainSettings(pp.tunnel)
	if err != nil {
		showErrorCustom(nil, chainProxyTabTitle, chainProxySaveError+err.Error())
		return
	}

	settings.Proxy = pp.enableCB.Checked()
	if settings.Proxy {
		settings.ProxyProtocol = chainProxyPicked(pp.protoCombo, chainProxyProtoValues, manager.ChainProxyProtoSocks5)
		settings.ProxyPort = int(pp.portNE.Value())
		settings.ProxyBind = chainProxyPicked(pp.bindCombo, chainProxyBindValues, manager.ChainProxyBindLoopback)
		settings.ProxyOnDown = chainProxyPicked(pp.downCombo, chainProxyDownValues, manager.ChainProxyDownError)
		settings.ProxyGrace = int(pp.graceNE.Value())
		settings.ProxySplit = pp.splitCB.Checked()
		if settings.ProxyBind == manager.ChainProxyBindLAN {
			settings.ProxyUser = strings.TrimSpace(pp.userLE.Text())
			settings.ProxyPassHash = pp.passwordHash(settings.ProxyUser)
		} else {
			settings.ProxyUser = ""
			settings.ProxyPassHash = ""
			pp.hash = ""
		}
	}
	// Whatever is left over from an older file is wiped by Normalised on
	// the other side of the pipe when Proxy is off.

	if err = manager.IPCClientChainSettingsSave(pp.tunnel, settings); err != nil {
		showErrorCustom(nil, chainProxyTabTitle, chainProxySaveError+err.Error())
		return
	}
	// Pack 81: the mark of this tunnel has just changed, in the list and
	// in the tray menu. The background poll would find it in two seconds
	// anyway, but a box that was ticked by hand deserves an answer at
	// once.
	ChainMarksChangedNow()
}

// passwordHash turns the password box into what the settings keep. An
// empty box means the password is not being changed.
func (pp *ProxyPage) passwordHash(user string) string {
	password := pp.passLE.Text()
	if len(password) == 0 {
		return pp.hash
	}
	hash := manager.ChainProxyPassHash(user, password)
	pp.hash = hash
	return hash
}

// showState writes what the proxy of this tunnel is doing right now.
func (pp *ProxyPage) showState() {
	if pp.stateLabel == nil {
		return
	}
	if len(pp.tunnel) == 0 || !pp.enableCB.Checked() {
		pp.stateLabel.SetText(chainProxyStateOff)
		return
	}

	info, err := manager.IPCClientChainStatus()
	if err != nil {
		pp.stateLabel.SetText(chainProxyStateWait)
		return
	}
	for _, proxy := range info.Proxies {
		if !strings.EqualFold(proxy.Leaf, pp.tunnel) {
			continue
		}
		text := fmt.Sprintf(chainProxyStateDead, proxy.Address)
		if proxy.Alive {
			text = fmt.Sprintf(chainProxyStateAlive, proxy.Address, proxy.Protocol, proxy.Conns)
		}
		if proxy.Split {
			text += " " + chainProxyStateSplit
		} else {
			text += " " + chainProxyStateWith
		}
		// Pack 84: the manager knows why a proxy refuses and used to keep
		// it to itself. The note is a short word, and the window turns it
		// into a sentence of its own language.
		if note := chainProxyNoteText(proxy.Note); len(note) > 0 {
			text += " " + note
		}
		pp.stateLabel.SetText(text)
		return
	}
	pp.stateLabel.SetText(chainProxyStateWait)
}

// chainProxyNoteText turns the short word of the manager into the sentence
// the window shows. An unknown word is shown as nothing at all, so that an
// older manager beside a newer window never prints a bare code.
func chainProxyNoteText(note string) string {
	switch note {
	case "tunnel-down":
		return chainProxyNoteDown
	case "dns-none":
		return chainProxyNoteNoDNS
	case "dns-blocked":
		return chainProxyNoteDNSBlocked
	}
	return ""
}

// watchState keeps the state line fresh while the tab is on screen.
func (pp *ProxyPage) watchState() {
	go func() {
		for {
			time.Sleep(2 * time.Second)
			pp.Synchronize(func() {
				if pp.Visible() {
					pp.showState()
				}
			})
		}
	}()
}

// chainProxyPick puts a list on the value it carries.
func chainProxyPick(combo *walk.ComboBox, values []string, want string) {
	if combo == nil {
		return
	}
	combo.SetCurrentIndex(0)
	for i := range values {
		if strings.EqualFold(values[i], want) {
			combo.SetCurrentIndex(i)
			return
		}
	}
}

// chainProxyPicked reads the value behind what a list shows.
func chainProxyPicked(combo *walk.ComboBox, values []string, fallback string) string {
	if combo == nil {
		return fallback
	}
	index := combo.CurrentIndex()
	if index < 0 || index >= len(values) {
		return fallback
	}
	return values[index]
}
