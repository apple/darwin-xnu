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

	// <rdar://problem/28512310> SW WAR/eval: WKdm write ack lost when bif_wke_colorWrAck_XXaH asserts concurrently for both colors
	HID_SET_BITS ARM64_REG_HID8, ARM64_REG_HID8_WkeForceStrictOrder, $1

	/***** Tunables that apply to all P cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to all E cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to specific cores, all revisions *****/
	EXEC_COREEQ_REVALL MIDR_SKYE_MISTRAL, $0, $1
	// <rdar://problem/30423928>: Atomic launch eligibility is erroneously taken away when a store at SMB gets invalidated
	HID_CLEAR_BITS ARM64_REG_EHID11, ARM64_REG_EHID11_SmbDrainThresh_mask, $1
	EXEC_END

	/***** Tunables that apply to specific cores and revisions *****/
	EXEC_COREEQ_REVLO MIDR_SKYE_MISTRAL, CPU_VERSION_B0, $0, $1

	// Disable downstream fill bypass logic
	// <rdar://problem/28545159> [Tunable] Skye - L2E fill bypass collision from both pipes to ecore
	HID_SET_BITS ARM64_REG_EHID5, ARM64_REG_EHID5_DisFillByp, $1

	// Disable forwarding of return addresses to the NFP
	// <rdar://problem/30387067> Skye: FED incorrectly taking illegal va exception
	HID_SET_BITS ARM64_REG_EHID0, ARM64_REG_EHID0_nfpRetFwdDisb, $1

	EXEC_END

	EXEC_COREALL_REVLO CPU_VERSION_B0, $0, $1

	// Disable clock divider gating
	// <rdar://problem/30854420> [Tunable/Errata][cpu_1p_1e] [CPGV2] ACC power down issue when link FSM switches from GO_DN to CANCEL and at the same time upStreamDrain request is set.
	HID_SET_BITS ARM64_REG_HID6, ARM64_REG_HID6_DisClkDivGating, $1

	// Disable clock dithering
	// <rdar://problem/29022199> [Tunable] Skye A0: Linux: LLC PIO Errors
	HID_SET_BITS ARM64_REG_ACC_OVRD, ARM64_REG_ACC_OVRD_dsblClkDtr, $1
	HID_SET_BITS ARM64_REG_ACC_EBLK_OVRD, ARM64_REG_ACC_OVRD_dsblClkDtr, $1

	EXEC_END

	EXEC_COREALL_REVHS CPU_VERSION_B0, $0, $1
	// <rdar://problem/32512836>: Disable refcount syncing between E and P
	HID_INSERT_BITS	ARM64_REG_CYC_OVRD, ARM64_REG_CYC_OVRD_dsblSnoopTime_mask, ARM64_REG_CYC_OVRD_dsblSnoopPTime, $1
	EXEC_END
.endmacro