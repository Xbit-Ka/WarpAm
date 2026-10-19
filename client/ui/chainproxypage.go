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
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"

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
	// WarpAm pack 100: the tunnel this one rides over. viaNames are the
	// names behind the list, in the order shown.
	viaCB    *walk.CheckBox
	viaCombo *walk.ComboBox
	viaNames []string
	// WarpAm pack 112: the memo under the list, and the tunnel the list
	// stood on last, so a pick that makes the chain too long goes back.
	viaMemo *walk.TextLabel
	viaWas  string
	// WarpAm pack 112: the second proxy of a double tunnel, through its
	// first link. hop is the hidden hop of the tunnel on screen, "" for a
	// single tunnel; the row is only shown for a double one.
	proxy2Row   *walk.Composite
	proxy2CB    *walk.CheckBox
	proxy2NE    *walk.NumberEdit
	proxy2State *walk.Composite
	proxy2Label *walk.TextLabel
	hop         string
	// savedProxy is whether the saved settings have the proxy on, that
	// is whether the port on screen is a port of this tunnel already.
	savedProxy bool
	downCombo  *walk.ComboBox
	graceNE    *walk.NumberEdit

	hintLabel  *walk.TextLabel
	stateLabel *walk.TextLabel
	// Pack 97: the address the other machines should type.
	addrLabel *walk.TextLabel

	// placeholder is true while the password box holds the asterisks put
	// there by reload and nobody has touched them. savedUser is the login
	// the saved hash belongs to.
	placeholder bool
	savedUser   string

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
		// WarpAm pack 112: a tunnel that had no port of its own gets the
		// first free one, not 1080 that may already belong to another.
		if !pp.loading && pp.enableCB.Checked() && !pp.savedProxy {
			avoid := 0
			if pp.hop != "" && pp.proxy2CB.Checked() {
				avoid = int(pp.proxy2NE.Value())
			}
			if port := pp.freePort(avoid); port > 0 {
				pp.portNE.SetValue(float64(port))
			}
		}
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
	// WarpAm pack 104: small arrows up and down, one port per click.
	pp.portNE.SetIncrement(1)
	pp.portNE.SetSpinButtonsVisible(true)
	pp.portNE.SetValue(float64(manager.ChainProxyDefaultPort))
	pp.portNE.SetToolTipText(chainProxyPortHint)
	pp.portNE.ValueChanged().Attach(pp.queueSave)
	// WarpAm pack 105: six digits fit in the port field.
	pp.fitPortWidth()
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
		// Pack 97: browsers cannot send a SOCKS5 login, so the local
		// network mode starts with both protocols on one port.
		if !pp.loading && chainProxyPicked(pp.bindCombo, chainProxyBindValues, manager.ChainProxyBindLoopback) == manager.ChainProxyBindLAN &&
			chainProxyPicked(pp.protoCombo, chainProxyProtoValues, manager.ChainProxyProtoSocks5) == manager.ChainProxyProtoSocks5 {
			chainProxyPick(pp.protoCombo, chainProxyProtoValues, manager.ChainProxyProtoBoth)
		}
		pp.follow()
		pp.queueSave()
		pp.showState()
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
	// Pack 97: asterisks instead of the dots of Windows, EM_SETPASSWORDCHAR.
	win.SendMessage(pp.passLE.Handle(), 0x00CC, uintptr('*'), 0)
	pp.passLE.SetToolTipText(chainProxyPassHint)
	pp.passLE.TextChanged().Attach(func() {
		if !pp.loading {
			pp.placeholder = false
		}
	})
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
	pp.splitCB.CheckedChanged().Attach(func() {
		pp.follow()
		pp.queueSave()
	})
	if _, err = walk.NewHSpacer(splitRow); err != nil {
		return nil, err
	}

	// 5b. WarpAm pack 112: the second proxy, through the first link of a
	// double tunnel. Hidden for a single tunnel.
	if pp.proxy2Row, err = chainProxyRow(pp); err != nil {
		return nil, err
	}
	if pp.proxy2CB, err = walk.NewCheckBox(pp.proxy2Row); err != nil {
		return nil, err
	}
	pp.proxy2CB.SetText(chainProxy2Label)
	pp.proxy2CB.SetToolTipText(chainProxy2Hint)
	pp.proxy2CB.CheckedChanged().Attach(func() {
		if !pp.loading && pp.proxy2CB.Checked() {
			avoid := 0
			if pp.enableCB.Checked() {
				avoid = int(pp.portNE.Value())
			}
			if port := pp.freePort(avoid); port > 0 {
				pp.proxy2NE.SetValue(float64(port))
			}
		}
		pp.follow()
		pp.queueSave()
	})
	proxy2PortLabel, err := walk.NewTextLabel(pp.proxy2Row)
	if err != nil {
		return nil, err
	}
	proxy2PortLabel.SetText(chainProxy2PortLabel)
	if pp.proxy2NE, err = walk.NewNumberEdit(pp.proxy2Row); err != nil {
		return nil, err
	}
	pp.proxy2NE.SetDecimals(0)
	pp.proxy2NE.SetRange(1, 65535)
	pp.proxy2NE.SetIncrement(1)
	pp.proxy2NE.SetSpinButtonsVisible(true)
	pp.proxy2NE.SetValue(float64(manager.ChainProxyDefaultPort + 1))
	pp.proxy2NE.SetToolTipText(chainProxy2Hint)
	pp.proxy2NE.ValueChanged().Attach(pp.queueSave)
	pp.proxy2NE.SetMinMaxSizePixels(walk.Size{pp.proxy2NE.IntFrom96DPI(6*8 + 18 + 10), 0}, walk.Size{0, 0})
	if _, err = walk.NewHSpacer(pp.proxy2Row); err != nil {
		return nil, err
	}

	// 5a. WarpAm pack 100: through another tunnel of the program. It only
	// lives while the split box is ticked.
	viaGroup, err := walk.NewGroupBox(pp)
	if err != nil {
		return nil, err
	}
	viaGroup.SetTitle(chainProxyViaGroup)
	// WarpAm pack 112: the box and the list are one row, the memo about
	// the length of a chain is under them.
	viaLayout := walk.NewVBoxLayout()
	viaLayout.SetMargins(walk.Margins{10, 5, 10, 5})
	viaLayout.SetSpacing(4)
	if err = viaGroup.SetLayout(viaLayout); err != nil {
		return nil, err
	}
	viaRow, err := chainProxyRow(viaGroup)
	if err != nil {
		return nil, err
	}
	if pp.viaCB, err = walk.NewCheckBox(viaRow); err != nil {
		return nil, err
	}
	pp.viaCB.SetText(chainProxyViaLabel)
	pp.viaCB.SetToolTipText(chainProxyViaHint)
	pp.viaCB.CheckedChanged().Attach(func() {
		// WarpAm pack 113: the box takes the first tunnel of the list that
		// fits instead of refusing because of the one the list happened to
		// stand on.
		if !pp.loading && pp.viaCB.Checked() && !pp.viaPickOK() {
			pp.loading = true
			pp.viaCB.SetChecked(false)
			pp.loading = false
		}
		pp.follow()
		pp.queueSave()
	})
	if pp.viaCombo, err = walk.NewComboBox(viaRow); err != nil {
		return nil, err
	}
	pp.viaCombo.SetToolTipText(chainProxyViaHint)
	pp.viaCombo.CurrentIndexChanged().Attach(func() {
		if !pp.loading && pp.viaCB.Checked() && !pp.viaLengthOK() {
			pp.loading = true
			chainProxyPick(pp.viaCombo, pp.viaNames, pp.viaWas)
			if len(pp.viaWas) == 0 {
				pp.viaCB.SetChecked(false)
			}
			pp.loading = false
			pp.follow()
		}
		pp.queueSave()
	})
	if _, err = walk.NewHSpacer(viaRow); err != nil {
		return nil, err
	}
	if pp.viaMemo, err = walk.NewTextLabel(viaGroup); err != nil {
		return nil, err
	}
	pp.viaMemo.SetText(chainProxyViaMemo)

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

	// 8a. WarpAm pack 112: what the second proxy is doing, for a double
	// tunnel only.
	if pp.proxy2State, err = chainProxyRow(pp); err != nil {
		return nil, err
	}
	proxy2Title, err := walk.NewTextLabel(pp.proxy2State)
	if err != nil {
		return nil, err
	}
	proxy2Title.SetText(chainProxy2StateTitle + ":")
	if pp.proxy2Label, err = walk.NewTextLabel(pp.proxy2State); err != nil {
		return nil, err
	}
	pp.proxy2Label.SetText(chainProxy2StateOff)
	if _, err = walk.NewHSpacer(pp.proxy2State); err != nil {
		return nil, err
	}

	// 9. Pack 97: the address for the other machines of the local network.
	addrRow, err := chainProxyRow(pp)
	if err != nil {
		return nil, err
	}
	addrTitle, err := walk.NewTextLabel(addrRow)
	if err != nil {
		return nil, err
	}
	addrTitle.SetText(chainProxyAddrTitle + ":")
	if pp.addrLabel, err = walk.NewTextLabel(addrRow); err != nil {
		return nil, err
	}
	pp.addrLabel.SetText(chainProxyAddrLocal)
	if _, err = walk.NewHSpacer(addrRow); err != nil {
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
		pp.viaCB.SetChecked(false)
		pp.fillVia("")
		pp.viaWas = ""
		pp.hop = ""
		pp.savedProxy = false
		pp.proxy2CB.SetChecked(false)
		pp.userLE.SetText("")
		pp.passLE.SetText("")
		pp.hash = ""
		pp.placeholder = false
		pp.savedUser = ""
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
	pp.hash = settings.ProxyPassHash
	pp.savedUser = strings.TrimSpace(settings.ProxyUser)
	pp.showMask()
	pp.splitCB.SetChecked(settings.ProxySplit)
	pp.fillVia(settings.ProxyViaTunnel)
	// WarpAm pack 105: a hidden hop written earlier is shown as off.
	pp.viaCB.SetChecked(settings.ProxyVia && !manager.ChainIsHiddenHop(settings.ProxyViaTunnel))
	pp.viaWas = ""
	if pp.viaCB.Checked() {
		pp.viaWas = settings.ProxyViaTunnel
	}
	// WarpAm pack 112: the second proxy, and whether there is a first
	// link to carry it at all.
	pp.savedProxy = settings.Proxy
	pp.hop = chainProxyHopOf(pp.tunnel)
	pp.proxy2CB.SetChecked(settings.Proxy2 && pp.hop != "")
	port2 := settings.Proxy2Port
	if port2 <= 0 {
		port2 = manager.ChainProxyDefaultPort + 1
	}
	pp.proxy2NE.SetValue(float64(port2))

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

	// WarpAm pack 102: the box works in every mode, so it only needs a
	// tunnel to pick; grey means not kept here as well.
	viaOn := has && len(pp.viaNames) != 0
	if !viaOn && !pp.loading && pp.viaCB.Checked() {
		pp.viaCB.SetChecked(false)
	}
	pp.viaCB.SetEnabled(viaOn)
	pp.viaCombo.SetEnabled(viaOn && pp.viaCB.Checked())

	// WarpAm pack 112: the second proxy lives on its own box.
	double := has && pp.hop != ""
	pp.proxy2Row.SetVisible(double)
	pp.proxy2State.SetVisible(double)
	pp.proxy2CB.SetEnabled(double)
	pp.proxy2NE.SetEnabled(double && pp.proxy2CB.Checked())

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
		pp.placeholder = false
		pp.savedUser = ""
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

	// WarpAm pack 102: the box "through a tunnel" is saved in every mode.
	settings.ProxyVia = false
	settings.ProxyViaTunnel = ""
	if pp.viaCB.Checked() {
		if index := pp.viaCombo.CurrentIndex(); index >= 0 && index < len(pp.viaNames) {
			settings.ProxyVia = true
			settings.ProxyViaTunnel = pp.viaNames[index]
		}
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

	// WarpAm pack 112: the second proxy, only for a double tunnel.
	settings.Proxy2 = pp.hop != "" && pp.proxy2CB.Checked()
	settings.Proxy2Port = 0
	if settings.Proxy2 {
		settings.Proxy2Port = int(pp.proxy2NE.Value())
	}

	if err = manager.IPCClientChainSettingsSave(pp.tunnel, settings); err != nil {
		showErrorCustom(nil, chainProxyTabTitle, chainProxySaveError+err.Error())
		// WarpAm pack 112: the manager may refuse (a chain too long), and
		// the screen shows again what is really saved.
		pp.reload()
		return
	}
	pp.savedProxy = settings.Proxy
	pp.viaWas = settings.ProxyViaTunnel
	// Pack 81: the mark of this tunnel has just changed, in the list and
	// in the tray menu. The background poll would find it in two seconds
	// anyway, but a box that was ticked by hand deserves an answer at
	// once.
	ChainMarksChangedNow()
}

// passwordHash turns the password box into what the settings keep. An
// empty box, or the untouched asterisks, mean the password is not being
// changed. Pack 97: the new hash does not hold the login, so a new login
// keeps the password; only a hash of the old kind needs it typed again.
func (pp *ProxyPage) passwordHash(user string) string {
	password := pp.passLE.Text()
	if pp.placeholder || len(password) == 0 {
		if len(pp.hash) != 0 && manager.ChainProxyPassIsOld(pp.hash) && !strings.EqualFold(user, pp.savedUser) {
			showErrorCustom(nil, chainProxyTabTitle, chainProxyPassAgain)
			pp.hash = ""
			pp.savedUser = user
			pp.showMask()
			return ""
		}
		pp.savedUser = user
		return pp.hash
	}
	hash := manager.ChainProxyPassHash(user, password)
	pp.hash = hash
	pp.savedUser = user
	pp.showMask()
	return hash
}

// showMask puts the asterisks into the password box when a password is
// saved, and empties it when there is none. Pack 97.
func (pp *ProxyPage) showMask() {
	was := pp.loading
	pp.loading = true
	if len(pp.hash) != 0 {
		pp.passLE.SetText(chainProxyPassMask)
		pp.placeholder = true
	} else {
		pp.passLE.SetText("")
		pp.placeholder = false
	}
	pp.loading = was
}

// showAddress fills the line with the address for the other machines.
// Pack 97.
func (pp *ProxyPage) showAddress() {
	if pp.addrLabel == nil {
		return
	}
	lan := len(pp.tunnel) > 0 && pp.enableCB.Checked() &&
		chainProxyPicked(pp.bindCombo, chainProxyBindValues, manager.ChainProxyBindLoopback) == manager.ChainProxyBindLAN
	if !lan {
		pp.addrLabel.SetText(chainProxyAddrLocal)
		return
	}
	addresses := manager.ChainProxyLANAddresses()
	if len(addresses) == 0 {
		pp.addrLabel.SetText(chainProxyAddrMissing)
		return
	}
	port := int(pp.portNE.Value())
	with := make([]string, len(addresses))
	for i := range addresses {
		with[i] = fmt.Sprintf("%s:%d", addresses[i], port)
	}
	pp.addrLabel.SetText(strings.Join(with, ", "))
}

// showState writes what the proxy of this tunnel is doing right now.
func (pp *ProxyPage) showState() {
	if pp.stateLabel == nil {
		return
	}
	pp.showAddress()
	// WarpAm pack 112: the second proxy runs keyed by the hidden hop.
	pp.showProxy2()
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
		// Pack 97: the password and the wrong logins of the last minutes.
		if chainProxyPicked(pp.bindCombo, chainProxyBindValues, manager.ChainProxyBindLoopback) == manager.ChainProxyBindLAN {
			if len(pp.hash) != 0 {
				text += " " + chainProxyPassSet
			} else {
				text += " " + chainProxyPassUnset
			}
		}
		if proxy.LoginFails > 0 {
			text += " " + fmt.Sprintf(chainProxyLoginFails, proxy.LoginFails, proxy.LoginFrom)
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

// fitPortWidth (WarpAm pack 105) makes the port field wide enough for six
// digits next to its arrows.
//
// WarpAm pack 106: only the port field is touched. The protocol list and
// the label "Port" stay where they were before pack 105, the field only
// grows to the right into the free room of the row.
func (pp *ProxyPage) fitPortWidth() {
	// Six digits of 8 points, the arrows and the frame, at 96 DPI.
	width := pp.portNE.IntFrom96DPI(6*8 + 18 + 10)
	if old := pp.portNE.SizeHint().Width; old > width {
		width = old
	}
	pp.portNE.SetMinMaxSizePixels(walk.Size{width, 0}, walk.Size{0, 0})
}

// fillVia (WarpAm pack 100) fills the list of tunnels this one may ride
// over: the tunnels of WarpAm only, not this one, and not a tunnel that
// already rides over this one. A saved name that is gone stays in the list
// so the screen shows what the file says.
//
// WarpAm pack 113: "rides over this one" is followed all the way down. On
// 8.10 100 went through Elena and Elena through ru-central, so 100 led
// back to ru-central and was still offered to it, first in the list.
func (pp *ProxyPage) fillVia(want string) {
	want = strings.TrimSpace(want)
	// WarpAm pack 105: a hidden hop is never in the list, not even when it
	// was written earlier.
	if manager.ChainIsHiddenHop(want) {
		want = ""
	}
	names := []string{}
	if len(pp.tunnel) != 0 {
		if tunnels, err := manager.IPCClientTunnels(); err == nil {
			parents := make(map[string]string, len(tunnels))
			for _, t := range tunnels {
				if other, err := manager.IPCClientChainSettings(t.Name); err == nil && other.ProxyVia {
					parents[strings.ToLower(t.Name)] = strings.TrimSpace(other.ProxyViaTunnel)
				}
			}
			for _, t := range tunnels {
				if strings.EqualFold(t.Name, pp.tunnel) || manager.ChainIsHiddenHop(t.Name) {
					continue
				}
				if chainProxyLeadsBack(t.Name, pp.tunnel, parents) {
					continue
				}
				names = append(names, t.Name)
			}
		}
	}
	found := len(want) == 0
	for _, n := range names {
		if strings.EqualFold(n, want) {
			found = true
		}
	}
	if !found && !strings.EqualFold(want, pp.tunnel) {
		names = append(names, want)
	}
	pp.viaNames = names
	if len(names) == 0 {
		pp.viaCombo.SetModel([]string{chainProxyViaNone})
		pp.viaCombo.SetCurrentIndex(0)
		return
	}
	pp.viaCombo.SetModel(names)
	chainProxyPick(pp.viaCombo, names, want)
}

// chainProxyLeadsBack answers whether from, or a tunnel under it, goes
// through name by the "via" box (pack 113).
func chainProxyLeadsBack(from, name string, parents map[string]string) bool {
	seen := make(map[string]bool)
	for at := parents[strings.ToLower(from)]; len(at) != 0 && !seen[strings.ToLower(at)]; at = parents[strings.ToLower(at)] {
		if strings.EqualFold(at, name) {
			return true
		}
		seen[strings.ToLower(at)] = true
	}
	return false
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

// WarpAm pack 112: the helpers of the second proxy and of the length of a
// chain.

// chainProxyHopOf is the hidden hop of a double tunnel, "" for a single one.
func chainProxyHopOf(name string) string {
	if len(name) == 0 {
		return ""
	}
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return ""
	}
	for _, t := range tunnels {
		if manager.ChainIsHiddenHop(t.Name) &&
			(strings.EqualFold(t.Name, name+"-hop1") || strings.EqualFold(t.Name, "hop1-"+name)) {
			return t.Name
		}
	}
	return ""
}

// freePort is the first port from 1080 that no tunnel is set to, the
// second proxies included, that nothing listens on and that is not avoid.
func (pp *ProxyPage) freePort(avoid int) int {
	for _, port := range chainViaFreePorts(chainViaMembersUI("", nil), 3) {
		if port != avoid {
			return port
		}
	}
	return 0
}

// viaLengthOK asks the manager whether the tunnel on screen may go through
// the tunnel the list stands on. A No is shown in a window.
func (pp *ProxyPage) viaLengthOK() bool {
	index := pp.viaCombo.CurrentIndex()
	if len(pp.tunnel) == 0 || index < 0 || index >= len(pp.viaNames) {
		return true
	}
	problem, err := manager.IPCClientChainLengthCheck(pp.tunnel, pp.viaNames[index])
	if err != nil {
		// An older manager does not know the question; the save asks
		// again on the other side of the pipe.
		return true
	}
	if len(problem) == 0 {
		return true
	}
	walk.MsgBox(pp.Form(), chainTitle, problem, walk.MsgBoxOK|walk.MsgBoxIconWarning)
	return false
}

// viaPickOK is asked when the box is ticked (pack 113). The tunnel the
// list stands on is asked first; when it does not fit, the list moves to
// the first tunnel that does, and the length is counted for that one. Only
// when none fits is the answer for the first one shown and the box goes
// back.
func (pp *ProxyPage) viaPickOK() bool {
	index := pp.viaCombo.CurrentIndex()
	if len(pp.tunnel) == 0 || index < 0 || index >= len(pp.viaNames) {
		return true
	}
	first := ""
	for k := 0; k < len(pp.viaNames); k++ {
		i := (index + k) % len(pp.viaNames)
		problem, err := manager.IPCClientChainLengthCheck(pp.tunnel, pp.viaNames[i])
		if err != nil {
			// An older manager does not know the question; the save asks
			// again on the other side of the pipe.
			return true
		}
		if len(problem) == 0 {
			if i != index {
				log.Printf("[%s] Via: %s does not fit, %s is picked instead", pp.tunnel, pp.viaNames[index], pp.viaNames[i])
				was := pp.loading
				pp.loading = true
				pp.viaCombo.SetCurrentIndex(i)
				pp.loading = was
			}
			return true
		}
		if k == 0 {
			first = problem
		}
	}
	walk.MsgBox(pp.Form(), chainTitle, first, walk.MsgBoxOK|walk.MsgBoxIconWarning)
	return false
}

// showProxy2 writes what the second proxy is doing right now.
func (pp *ProxyPage) showProxy2() {
	if pp.proxy2Label == nil || pp.hop == "" {
		return
	}
	if !pp.proxy2CB.Checked() {
		pp.proxy2Label.SetText(chainProxy2StateOff)
		return
	}
	info, err := manager.IPCClientChainStatus()
	if err != nil {
		pp.proxy2Label.SetText(chainProxy2StateWait)
		return
	}
	for _, proxy := range info.Proxies {
		if !strings.EqualFold(proxy.Leaf, pp.hop) {
			continue
		}
		text := fmt.Sprintf(chainProxyStateDead, proxy.Address)
		if proxy.Alive {
			text = fmt.Sprintf(chainProxyStateAlive, proxy.Address, proxy.Protocol, proxy.Conns)
		}
		if note := chainProxyNoteText(proxy.Note); len(note) > 0 {
			text += " " + note
		}
		pp.proxy2Label.SetText(text)
		return
	}
	pp.proxy2Label.SetText(chainProxy2StateWait)
}
