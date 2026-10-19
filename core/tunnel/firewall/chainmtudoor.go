//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * WarpAm pack 112: the door for the MTU check.
 *
 * The own maximum of a tunnel is found with a ping to its server straight
 * out of the network card (core/chainmtu/probe.go), and the check runs
 * right before a raise, often while another tunnel is up with its kill
 * switch. Both walls of this program, the one of an ordinary tunnel
 * (blocker.go) and the one of a chain (chainfirewall.go), stopped that
 * ping, and the check found "no answer" every time a wall stood.
 *
 * The door is as narrow as a ping can be: ICMP and ICMPv6 only, and only
 * for WarpAm.exe, which sends nothing over ICMP but the echo requests of
 * this check. No other protocol and no other program gets through it.
 */

package firewall

import (
	"runtime"
	"unsafe"
)

// permitChainMTUProbe lets the given executables send and receive ICMP and
// ICMPv6 on any interface.
func permitChainMTUProbe(session uintptr, baseObjects *baseObjects, weight uint8, appIDs []*wtFwpByteBlob) error {
	for _, appID := range appIDs {
		for _, layer := range chainLayersBoth() {
			proto := cIPPROTO_ICMP
			if layer.key == cFWPM_LAYER_ALE_AUTH_CONNECT_V6 || layer.key == cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 {
				proto = cIPPROTO_ICMPV6
			}
			conditions := []wtFwpmFilterCondition0{
				{
					fieldKey:  cFWPM_CONDITION_ALE_APP_ID,
					matchType: cFWP_MATCH_EQUAL,
					conditionValue: wtFwpConditionValue0{
						_type: cFWP_BYTE_BLOB_TYPE,
						value: uintptr(unsafe.Pointer(appID)),
					},
				},
				{
					fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
					matchType: cFWP_MATCH_EQUAL,
					conditionValue: wtFwpConditionValue0{
						_type: cFWP_UINT8,
						value: uintptr(proto),
					},
				},
			}
			filter := wtFwpmFilter0{
				providerKey:         &baseObjects.provider,
				subLayerKey:         baseObjects.filters,
				weight:              filterWeight(weight),
				numFilterConditions: uint32(len(conditions)),
				filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
				action: wtFwpmAction0{
					_type: cFWP_ACTION_PERMIT,
				},
			}
			displayData, err := createWtFwpmDisplayData0("Permit the MTU check of WarpAm ("+layer.name+")", "")
			if err != nil {
				return wrapErr(err)
			}
			filter.displayData = *displayData
			filter.layerKey = layer.key
			filterID := uint64(0)
			err = fwpmFilterAdd0(session, &filter, 0, &filterID)
			runtime.KeepAlive(conditions)
			if err != nil {
				return wrapErr(err)
			}
		}
	}
	return nil
}

// permitChainMTUProbeSelf is the same door for the program that owns the
// session, which is WarpAm.exe for every tunnel service.
func permitChainMTUProbeSelf(session uintptr, baseObjects *baseObjects, weight uint8) error {
	appID, err := getCurrentProcessAppID()
	if err != nil {
		return wrapErr(err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))
	return permitChainMTUProbe(session, baseObjects, weight, []*wtFwpByteBlob{appID})
}
