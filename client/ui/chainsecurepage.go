/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 86: the Configs section of the Settings tab.
 * AwgChain pack 91: it tells the truth now, and it can close the door.
 *
 * The window draws four controls:
 *
 *   * the box "encrypt new configs", which decides how the next
 *     configuration is written and nothing else;
 *   * one button that is called "encrypt" or "decrypt" depending on what
 *     lies in the folder right now, so a folder somebody copied files into
 *     by hand is described honestly;
 *   * one button that opens or closes the rights of the data folder and of
 *     every file inside it, named after what the folder carries at this
 *     moment;
 *   * one button that closes the installation from changes for good.
 *
 * Above them stands one reference line, and it is the point of this pack.
 * It is built from numbers the manager reads off the disk at the moment it
 * answers, and it is asked again on a timer, so the section cannot keep
 * showing a state that stopped being true. The complaint that started this
 * was exactly that: the window said four configurations had been decrypted
 * while one of them was still encrypted, and it went on saying so until the
 * program was restarted.
 *
 * Every answer the window shows about work that was done comes from the
 * count of files that really changed, together with the count of files that
 * could not be changed. There is no message here that says "done" because
 * a call returned without an error.
 *
 * The password is gone, see client/manager/chainsecure.go.
 */

package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/lxn/walk"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
)

// chainSecureBeat is how often the section asks the manager again while it
// is on screen. The folder can change without this window doing anything:
// a tunnel is added, a tool writes a file, another copy of the settings
// page presses a button.
const chainSecureBeat = 4 * time.Second

type chainSecureSection struct {
	page *SettingsPage

	encryptCB  *walk.CheckBox
	stateLabel *walk.TextLabel
	cryptPB    *walk.PushButton
	aclPB      *walk.PushButton
	finishPB   *walk.PushButton
	releasePB  *walk.PushButton
	rootLabel  *walk.TextLabel

	// loading is up while the section is being filled from the manager, so
	// that setting the box does not save it straight back.
	loading bool
	// answered says the manager replied at least once. Until it does, the
	// controls are grey: acting on numbers we do not have is how a page
	// ends up encrypting nothing and reporting success.
	answered bool
	// state is the last answer of the manager. It is kept for the handlers
	// of the buttons, which have to know what the folder looks like before
	// they can ask the right question, and it is replaced by every answer.
	state manager.ChainSecureReply
	// stop ends the timer when the page goes away.
	stop chan struct{}
}

// chainSecureBuild adds the section to the Settings tab. It is called from
// NewSettingsPage and returns only the errors of building the widgets.
func chainSecureBuild(sp *SettingsPage) error {
	cs := &chainSecureSection{page: sp, stop: make(chan struct{})}

	header, err := chainFlatRow(sp)
	if err != nil {
		return err
	}
	headerLabel, err := walk.NewTextLabel(header)
	if err != nil {
		return err
	}
	headerLabel.SetText(chainSecureHeader)
	if _, err = walk.NewHSpacer(header); err != nil {
		return err
	}

	boxRow, err := chainFlatRow(sp)
	if err != nil {
		return err
	}
	if cs.encryptCB, err = walk.NewCheckBox(boxRow); err != nil {
		return err
	}
	cs.encryptCB.SetText(chainSecureEncryptLabel)
	cs.encryptCB.SetToolTipText(chainSecureEncryptHint)
	cs.encryptCB.CheckedChanged().Attach(cs.saveBox)
	if _, err = walk.NewHSpacer(boxRow); err != nil {
		return err
	}

	// The reference line stands alone above the buttons: it is a sentence
	// about the disk, not a caption of any one control.
	stateRow, err := chainFlatRow(sp)
	if err != nil {
		return err
	}
	if cs.stateLabel, err = walk.NewTextLabel(stateRow); err != nil {
		return err
	}
	cs.stateLabel.SetText(chainSecureNoService)
	if _, err = walk.NewHSpacer(stateRow); err != nil {
		return err
	}

	buttonRow, err := chainFlatRow(sp)
	if err != nil {
		return err
	}
	if cs.cryptPB, err = walk.NewPushButton(buttonRow); err != nil {
		return err
	}
	cs.cryptPB.SetText(chainSecureSealButton)
	cs.cryptPB.SetToolTipText(chainSecureSealHint)
	cs.cryptPB.SetEnabled(false)
	cs.cryptPB.Clicked().Attach(cs.crypt)

	if cs.aclPB, err = walk.NewPushButton(buttonRow); err != nil {
		return err
	}
	cs.aclPB.SetText(chainSecureAclOpenButton)
	cs.aclPB.SetToolTipText(chainSecureAclOpenHint)
	cs.aclPB.SetEnabled(false)
	cs.aclPB.Clicked().Attach(cs.acl)

	if cs.finishPB, err = walk.NewPushButton(buttonRow); err != nil {
		return err
	}
	cs.finishPB.SetText(chainSecureFinishButton)
	cs.finishPB.SetToolTipText(chainSecureFinishOffHint)
	cs.finishPB.SetEnabled(false)
	cs.finishPB.Clicked().Attach(cs.finish)

	// Pack 92: the button of the portable copy. It stands next to the one
	// that closes an installation, because the two are opposites: one nails
	// the folder to this machine, the other lets it go.
	if cs.releasePB, err = walk.NewPushButton(buttonRow); err != nil {
		return err
	}
	cs.releasePB.SetText(chainSecureReleaseButton)
	cs.releasePB.SetToolTipText(chainSecureReleaseHint)
	cs.releasePB.SetEnabled(false)
	cs.releasePB.Clicked().Attach(cs.release)
	if _, err = walk.NewHSpacer(buttonRow); err != nil {
		return err
	}

	rootRow, err := chainFlatRow(sp)
	if err != nil {
		return err
	}
	if cs.rootLabel, err = walk.NewTextLabel(rootRow); err != nil {
		return err
	}
	cs.rootLabel.SetText(chainSecureRootLabel + chainSecureRootUnknown)
	if _, err = walk.NewHSpacer(rootRow); err != nil {
		return err
	}

	// The tab is filled when it comes on screen, because the folder can
	// change under us while another window is in front.
	sp.VisibleChanged().Attach(func() {
		if sp.Visible() {
			cs.show(cs.read())
		}
	})
	sp.Disposing().Attach(func() {
		close(cs.stop)
	})
	go cs.beat()
	cs.show(cs.read())
	return nil
}

// beat asks the manager again while the section is on screen. Until pack 91
// the only refreshes were the first one and the ones a button caused, so a
// folder that changed elsewhere was described by this window from memory
// until the program was restarted.
func (cs *chainSecureSection) beat() {
	ticker := time.NewTicker(chainSecureBeat)
	defer ticker.Stop()
	for {
		select {
		case <-cs.stop:
			return
		case <-ticker.C:
			cs.page.Synchronize(func() {
				if !cs.page.Visible() || cs.loading {
					return
				}
				cs.show(cs.read())
			})
		}
	}
}

// read asks the manager for the state of the folder without changing
// anything.
func (cs *chainSecureSection) read() (manager.ChainSecureReply, bool) {
	reply, err := manager.IPCClientChainSecure(manager.ChainSecureRequest{Action: manager.ChainSecureActionStatus})
	if err != nil {
		return reply, false
	}
	return reply, true
}

// line is the one reference sentence over the buttons. Every number in it
// comes from the disk.
func chainSecureLine(reply manager.ChainSecureReply) string {
	text := chainSecureLineNone
	if reply.Sealed != 0 || reply.Plain != 0 {
		text = fmt.Sprintf(chainSecureLineConfigs, reply.Sealed, reply.Plain)
	}
	if reply.AclOpen {
		text += fmt.Sprintf(chainSecureLineOpen, reply.RightsDirs, reply.RightsFiles)
	} else {
		text += fmt.Sprintf(chainSecureLineStrict, reply.RightsDirs, reply.RightsFiles)
	}
	if reply.RightsWrong != 0 {
		text += fmt.Sprintf(chainSecureLineWrong, reply.RightsWrong)
	}
	if reply.InstallSealed {
		text += chainSecureLineSealed
	}
	return text
}

// show writes an answer of the manager onto the controls.
func (cs *chainSecureSection) show(reply manager.ChainSecureReply, answered bool) {
	cs.loading = true
	defer func() { cs.loading = false }()

	cs.answered = answered
	cs.state = reply
	if !answered {
		cs.stateLabel.SetText(chainSecureNoService)
		cs.rootLabel.SetText(chainSecureRootLabel + chainSecureRootUnknown)
		cs.cryptPB.SetEnabled(false)
		cs.aclPB.SetEnabled(false)
		cs.finishPB.SetEnabled(false)
		cs.releasePB.SetEnabled(false)
		return
	}

	cs.encryptCB.SetChecked(reply.Encrypt)
	// A closed installation encrypts new configurations and that is not a
	// matter of taste any more, so the box is shown as it is and locked.
	cs.encryptCB.SetEnabled(!reply.InstallSealed)
	if reply.InstallSealed {
		cs.encryptCB.SetToolTipText(chainSecureEncryptLockedHint)
	} else {
		cs.encryptCB.SetToolTipText(chainSecureEncryptHint)
	}

	cs.stateLabel.SetText(chainSecureLine(reply))

	// The name of the button is the state of the folder, not a setting:
	// one encrypted file left means the honest offer is to decrypt.
	if reply.Sealed > 0 {
		cs.cryptPB.SetText(chainSecureUnsealButton)
		cs.cryptPB.SetToolTipText(chainSecureUnsealHint)
	} else {
		cs.cryptPB.SetText(chainSecureSealButton)
		cs.cryptPB.SetToolTipText(chainSecureSealHint)
	}
	cs.cryptPB.SetEnabled(reply.Sealed > 0 || reply.Plain > 0)

	if reply.AclOpen {
		cs.aclPB.SetText(chainSecureAclStrictButton)
		cs.aclPB.SetToolTipText(chainSecureAclStrictHint)
	} else {
		cs.aclPB.SetText(chainSecureAclOpenButton)
		cs.aclPB.SetToolTipText(chainSecureAclOpenHint)
	}
	cs.aclPB.SetEnabled(true)

	// A closed installation has no buttons that could open it again. They
	// are taken away and not greyed out: a grey button invites pressing.
	cs.cryptPB.SetVisible(!reply.InstallSealed)
	cs.aclPB.SetVisible(!reply.InstallSealed)

	// Outside an installed copy the last button is grey, and the reason
	// stands in its tooltip only. Writing it next to the button would put
	// a paragraph about installers into a settings tab that has nothing to
	// do with them.
	cs.finishPB.SetEnabled(reply.CanSeal && !reply.InstallSealed)
	switch {
	case reply.InstallSealed:
		cs.finishPB.SetToolTipText(chainSecureFinishSealedHint)
	case reply.CanSeal:
		cs.finishPB.SetToolTipText(chainSecureFinishHint)
	default:
		cs.finishPB.SetToolTipText(chainSecureFinishOffHint)
	}

	// The button that releases the folder belongs to a copy that was
	// unpacked, and it is shown only there: an installed copy is moved by
	// its installer, and a paragraph about that would say nothing to the
	// user of an installed copy who never asked to move anything.
	cs.releasePB.SetVisible(!reply.CanSeal)
	cs.releasePB.SetEnabled(reply.CanRelease)
	switch {
	case reply.InstallSealed:
		cs.releasePB.SetToolTipText(chainSecureReleaseSealedHint)
	case reply.CanRelease:
		cs.releasePB.SetToolTipText(chainSecureReleaseHint)
	default:
		cs.releasePB.SetToolTipText(chainSecureReleaseOffHint)
	}

	root := strings.TrimSpace(reply.Root)
	if len(root) == 0 {
		cs.rootLabel.SetText(chainSecureRootLabel + chainSecureRootUnknown)
	} else {
		cs.rootLabel.SetText(chainSecureRootLabel + root)
	}
}

// saveBox writes the box back. It goes through the book of global settings
// and sets the wish flag with it, which is what tells the manager that this
// value was really chosen and not left out by a caller that knows nothing
// about the field.
func (cs *chainSecureSection) saveBox() {
	if cs.loading || !cs.answered {
		return
	}

	global, err := manager.IPCClientChainGlobal()
	if err != nil {
		showErrorCustom(cs.page.Form(), chainSecureHeader, chainSecureError+err.Error())
		return
	}
	global.EncryptConfigs = cs.encryptCB.Checked()
	global.EncryptConfigsSet = true
	if err = manager.IPCClientChainGlobalSave(global); err != nil {
		showErrorCustom(cs.page.Form(), chainSecureHeader, chainSecureError+err.Error())
	}
	cs.show(cs.read())
}

// chainSecureAsk is every question this section puts. The confirming button
// is never the chosen one: none of these steps is something a stray press
// of the space bar should be able to start.
func (cs *chainSecureSection) chainSecureAsk(text string) bool {
	return walk.DlgCmdYes == walk.MsgBox(cs.page.Form(), chainTitle, text,
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning|walk.MsgBoxDefButton2)
}

// chainSecureReport is the one place a result is put into words. It counts
// what changed and what did not, and it says both.
func (cs *chainSecureSection) chainSecureReport(done, failed int, whole, partly string, err error) {
	if failed != 0 {
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		showErrorCustom(cs.page.Form(), chainSecureHeader,
			fmt.Sprintf(partly, done, failed, reason))
		return
	}
	if err != nil {
		showErrorCustom(cs.page.Form(), chainSecureHeader, chainSecureError+err.Error())
		return
	}
	text := chainSecureNothing
	if done != 0 {
		text = fmt.Sprintf(whole, done)
	}
	walk.MsgBox(cs.page.Form(), chainTitle, text, walk.MsgBoxIconInformation)
}

// crypt is the one button. What it does is decided by the folder: an
// encrypted file present means decrypt, otherwise encrypt.
func (cs *chainSecureSection) crypt() {
	if !cs.answered {
		return
	}

	unseal := cs.state.Sealed > 0
	action := manager.ChainSecureActionSeal
	ask, whole, partly := chainSecureSealAsk, chainSecureSealDone, chainSecureSealPartly
	if unseal {
		action = manager.ChainSecureActionUnseal
		ask, whole, partly = chainSecureUnsealAsk, chainSecureUnsealDone, chainSecureUnsealPartly
	}
	if !cs.chainSecureAsk(ask) {
		return
	}

	reply, err := manager.IPCClientChainSecure(manager.ChainSecureRequest{Action: action})
	cs.show(reply, true)
	cs.chainSecureReport(reply.Done, reply.Failed, whole, partly, err)
}

// acl is the rights button. The name it carries is the state of the folder,
// so the question it asks is always the one the button promises.
func (cs *chainSecureSection) acl() {
	if !cs.answered {
		return
	}

	action := manager.ChainSecureActionOpen
	ask := chainSecureAclOpenAsk
	if cs.state.AclOpen {
		action = manager.ChainSecureActionStrict
		ask = chainSecureAclStrictAsk
	}
	if !cs.chainSecureAsk(ask) {
		return
	}

	reply, err := manager.IPCClientChainSecure(manager.ChainSecureRequest{Action: action})
	cs.show(reply, err == nil)
	if err != nil {
		showErrorCustom(cs.page.Form(), chainSecureHeader, chainSecureError+err.Error())
	}
}

// finish closes the installation from changes. The question names all four
// consequences, because this is the one button in the program whose effect
// the program itself cannot undo.
func (cs *chainSecureSection) finish() {
	if !cs.answered || !cs.state.CanSeal || cs.state.InstallSealed {
		return
	}
	if !cs.chainSecureAsk(chainSecureFinishAsk) {
		return
	}

	reply, err := manager.IPCClientChainSecure(manager.ChainSecureRequest{Action: manager.ChainSecureActionSealInstall})
	cs.show(reply, true)
	if err != nil {
		showErrorCustom(cs.page.Form(), chainSecureHeader, chainSecureError+err.Error())
		return
	}
	walk.MsgBox(cs.page.Form(), chainTitle,
		fmt.Sprintf(chainSecureFinishDone, reply.Sealed, reply.RightsDirs, reply.RightsFiles),
		walk.MsgBoxIconInformation)
}

// release prepares the folder to be carried away and then closes the
// program, because the exit is the step that deletes the manager service.
//
// Two questions come first and both of them matter. The encrypted
// configurations are the trap of this whole button: they are sealed for
// the system account of this machine and they are unreadable anywhere
// else, so a folder carried away with them is a folder of tunnels that
// will not start. The answer is not decided here, because a folder that
// goes onto a stick and comes back to this same machine is better left
// encrypted, and only the user knows which of the two it is.
func (cs *chainSecureSection) release() {
	if !cs.answered || !cs.state.CanRelease {
		return
	}

	unseal := false
	if cs.state.Sealed > 0 {
		switch walk.MsgBox(cs.page.Form(), chainTitle,
			fmt.Sprintf(chainSecureReleaseSealedAsk, cs.state.Sealed),
			walk.MsgBoxYesNoCancel|walk.MsgBoxIconWarning|walk.MsgBoxDefButton1) {
		case walk.DlgCmdYes:
			unseal = true
		case walk.DlgCmdNo:
		default:
			return
		}
	}

	if !cs.chainSecureAsk(chainSecureReleaseAsk) {
		return
	}

	reply, err := manager.IPCClientChainSecure(manager.ChainSecureRequest{
		Action: manager.ChainSecureActionRelease,
		Unseal: unseal,
	})
	cs.show(reply, err == nil)

	// A release that did not go through leaves the program running. Saying
	// how far it got is the whole point: the folder now has some services
	// gone and some still there, and the line above the buttons says which.
	if err != nil {
		tunnels, left := 0, 0
		if reply.Release != nil {
			tunnels, left = reply.Release.Tunnels, reply.Release.Left
		}
		showErrorCustom(cs.page.Form(), chainSecureHeader,
			fmt.Sprintf(chainSecureReleaseFailed, tunnels, left, err.Error()))
		return
	}

	text := fmt.Sprintf(chainSecureReleaseDone, 0, 0)
	if reply.Release != nil {
		text = fmt.Sprintf(chainSecureReleaseDone, reply.Release.Tunnels, reply.Release.Unsealed)
		if reply.Release.Adapters != 0 {
			text += fmt.Sprintf(chainSecureReleaseAdapters, reply.Release.Adapters)
		}
	}
	walk.MsgBox(cs.page.Form(), chainTitle, text, walk.MsgBoxIconInformation)

	// The ordinary exit of the program: it stops the manager service and,
	// now that the wish to start with Windows is cleared, deletes it.
	onQuit()
}
