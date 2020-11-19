/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
.macro APPLY_TUNABLES
	/***** Tunables that apply to all cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to all P cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to all E cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to specific cores, all revisions *****/
	EXEC_COREEQ_REVALL MIDR_CEBU_LIGHTNING, $0, $1
	// rdar://53907283 ([Cebu ACC Errata] Sibling Merge in LLC can cause UC load to violate ARM Memory Ordering Rules.)
	HID_SET_BITS ARM64_REG_HID5, ARM64_REG_HID5_DisFill2cMerge, $1

	// rdar://problem/54615539: [Cebu ACC Tunable]Cross-beat Crypto(AES/PMUL) ICache fusion is not disabled for branch uncondtional recoded instruction.
	HID_SET_BITS ARM64_REG_HID0, ARM64_REG_HID0_CacheFusionDisable, $1

	// rdar://problem/50664291: [Cebu B0/B1 Tunables][PerfVerif][LSU] Post-silicon tuning of STNT widget contiguous counter threshold
	HID_INSERT_BITS	ARM64_REG_HID4, ARM64_REG_HID4_CnfCntrThresh_mask, ARM64_REG_HID4_CnfCntrThresh_VALUE, $1

	// rdar://problem/47744434: Barrier Load Ordering property is not satisfied for x64-loads
	HID_SET_BITS ARM64_REG_HID9, ARM64_REG_HID9_EnableFixBug47221499, $1

	// rdar://problem/50664291: [Cebu B0/B1 Tunables][PerfVerif][LSU] Post-silicon tuning of STNT widget contiguous counter threshold
	HID_SET_BITS ARM64_REG_HID9, ARM64_REG_HID9_DisSTNTWidgetForUnalign, $1

	// rdar://problem/47865629: RF bank and Multipass conflict forward progress widget does not handle 3+ cycle livelock
	HID_SET_BITS ARM64_REG_HID16, ARM64_REG_HID16_EnRs4Sec, $1
	HID_CLEAR_BITS ARM64_REG_HID16, ARM64_REG_HID16_DisxPickRs45, $1
	HID_SET_BITS ARM64_REG_HID16, ARM64_REG_HID16_EnMPxPick45, $1
	HID_SET_BITS ARM64_REG_HID16, ARM64_REG_HID16_EnMPCyc7, $1

	// Prevent ordered loads from being dispatched from LSU until all prior loads have completed.
	// rdar://problem/34095873: AF2 ordering rules allow ARM device ordering violations
	HID_SET_BITS ARM64_REG_HID4, ARM64_REG_HID4_ForceNsOrdLdReqNoOlderLd, $1

	// rdar://problem/51690962: Disable Store-Non-Temporal downgrade widget
	HID_SET_BITS ARM64_REG_HID4, ARM64_REG_HID4_DisSTNTWidget, $1

	// rdar://problem/41056604: disable faster launches of uncacheable unaligned stores to workaround load/load ordering violation
	HID_SET_BITS ARM64_REG_HID11, ARM64_REG_HID11_DisX64NTLnchOpt, $1

	// rdar://problem/45024523: enable aggressive LEQ throttling to work around LEQ credit leak
	HID_SET_BITS ARM64_REG_HID16, ARM64_REG_HID16_leqThrottleAggr, $1

	// rdar://problem/41029832: configure dummy cycles to work around incorrect temp sensor readings on NEX power gating
	HID_INSERT_BITS	ARM64_REG_HID13, ARM64_REG_HID13_PreCyc_mask, ARM64_REG_HID13_PreCyc_VALUE, $1
	EXEC_END

	EXEC_COREEQ_REVALL MIDR_CEBU_THUNDER, $0, $1
	// rdar://53907283 ([Cebu ACC Errata] Sibling Merge in LLC can cause UC load to violate ARM Memory Ordering Rules.)
	HID_SET_BITS ARM64_REG_HID5, ARM64_REG_HID5_DisFill2cMerge, $1

	// rdar://problem/48476033: Prevent store-to-load forwarding for UC memory to avoid barrier ordering violation
	HID_SET_BITS ARM64_REG_EHID10, ARM64_REG_EHID10_ForceWStDrainUc, $1

	// Prevent ordered loads from being dispatched from LSU until all prior loads have completed.
	// rdar://problem/34095873: AF2 ordering rules allow ARM device ordering violations
	HID_SET_BITS ARM64_REG_EHID4, ARM64_REG_HID4_ForceNsOrdLdReqNoOlderLd, $1

	// rdar://problem/37949166: Disable the extension of prefetcher training pipe clock gating, revert to default gating
	HID_SET_BITS ARM64_REG_EHID10, ARM64_REG_EHID10_rccDisPwrSavePrfClkOff, $1
	EXEC_END

	EXEC_COREEQ_REVALL MIDR_TURKS, $0, $1
	// rdar://problem/53506680: [MP_CHECKER] Load STLFs from a completed UC/NC/NT store causing barrier ordering violation
	HID_SET_BITS ARM64_REG_EHID10, ARM64_REG_EHID10_ForceWStDrainUc, $1
	EXEC_END

	/***** Tunables that apply to specific cores and revisions *****/
	/* N/A */
.endmacro