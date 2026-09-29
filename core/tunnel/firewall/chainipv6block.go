/* SPDX-License-Identifier: MIT
 *
 * AwgChain pack 55: blocking IPv6 with a filter instead of unbinding it.
 *
 * The old way turned IPv6 off on the adapters and wrote into the Windows
 * settings, which is heavy handed and hard to undo. Here a small dynamic WFP
 * session drops every IPv6 packet except loopback. When the session closes,
 * the machine is exactly as it was.
 */

package firewall

var ipv6Session uintptr

// EnableIPv6Block raises the IPv6 filter. Calling it twice is harmless.
func EnableIPv6Block() error {
	if ipv6Session != 0 {
		return nil
	}

	session, err := createChainWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerChainBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}

		err = permitLoopback(session, baseObjects, 11)
		if err != nil {
			return wrapErr(err)
		}

		err = blockIPv6(session, baseObjects, 0)
		if err != nil {
			return wrapErr(err)
		}

		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}

	ipv6Session = session
	return nil
}

// DisableIPv6Block drops the filter. Closing the dynamic session removes
// every object that was added inside it.
func DisableIPv6Block() {
	if ipv6Session == 0 {
		return
	}
	fwpmEngineClose0(ipv6Session)
	ipv6Session = 0
}

// IPv6BlockIsOn says whether the filter is standing right now.
func IPv6BlockIsOn() bool {
	return ipv6Session != 0
}

func blockIPv6(session uintptr, baseObjects *baseObjects, weight uint8) error {
	filter := wtFwpmFilter0{
		providerKey: &baseObjects.provider,
		subLayerKey: baseObjects.filters,
		weight:      filterWeight(weight),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	filterID := uint64(0)

	//
	// #1 Outbound IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("AwgChain: block outbound IPv6", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_CONNECT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	//
	// #2 Inbound IPv6.
	//
	{
		displayData, err := createWtFwpmDisplayData0("AwgChain: block inbound IPv6", "")
		if err != nil {
			return wrapErr(err)
		}

		filter.displayData = *displayData
		filter.layerKey = cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6

		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}

	return nil
}
