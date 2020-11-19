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

	// Disable LSP flush with context switch to work around bug in LSP
	// that can cause Typhoon to wedge when CONTEXTIDR is written.
	// <rdar://problem/12387704>
	HID_SET_BITS ARM64_REG_HID0, ARM64_REG_HID0_LoopBuffDisb, $1
	HID_SET_BITS ARM64_REG_HID1, ARM64_REG_HID1_rccDisStallInactiveIexCtl, $1
	HID_SET_BITS ARM64_REG_HID3, ARM64_REG_HID3_DisXmonSnpEvictTriggerL2StarvationMode, $1
	HID_CLEAR_BITS ARM64_REG_HID5, (ARM64_REG_HID5_DisHwpLd | ARM64_REG_HID5_DisHwpSt), $1

	// Change the default memcache data set ID from 0 to 15 for all agents
	HID_SET_BITS ARM64_REG_HID8, (ARM64_REG_HID8_DataSetID0_VALUE | ARM64_REG_HID8_DataSetID1_VALUE), $1

	/***** Tunables that apply to all P cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to all E cores, all revisions *****/
	/* N/A */

	/***** Tunables that apply to specific cores, all revisions *****/
	EXEC_COREEQ_REVALL MIDR_CAPRI, $0, $1
	HID_SET_BITS ARM64_REG_HID8, ARM64_REG_HID8_DataSetID2_VALUE, $1
	EXEC_END

	/***** Tunables that apply to specific cores and revisions *****/
	/* N/A */

	isb		sy
.endmacro