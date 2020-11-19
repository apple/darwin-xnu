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
	EXEC_PCORE_REVALL $0, $1
	// rdar://problem/34435356: segfaults due to IEX clock-gating
	HID_SET_BITS ARM64_REG_HID1, ARM64_REG_HID1_rccForceAllIexL3ClksOn, $1

	// Prevent ordered loads from being dispatched from LSU until all prior loads have completed.
	// rdar://problem/34095873: AF2 ordering rules allow ARM device ordering violations
	HID_SET_BITS ARM64_REG_HID4, ARM64_REG_HID4_ForceNsOrdLdReqNoOlderLd, $1

	// rdar://problem/38482968: [Cyprus Tunable] Poisoned cache line crossing younger load is not redirected by older load-barrier
	HID_SET_BITS ARM64_REG_HID3, ARM64_REG_HID3_DisColorOpt, $1

	// rdar://problem/41056604: disable faster launches of uncacheable unaligned stores to workaround load/load ordering violation
	HID_SET_BITS ARM64_REG_HID11, ARM64_REG_HID11_DisX64NTLnchOpt, $1

	EXEC_END

	/***** Tunables that apply to all E cores, all revisions *****/
	EXEC_ECORE_REVALL $0, $1
	// Prevent ordered loads from being dispatched from LSU until all prior loads have completed.
	// rdar://problem/34095873: AF2 ordering rules allow ARM device ordering violations
	HID_SET_BITS ARM64_REG_EHID4, ARM64_REG_HID4_ForceNsOrdLdReqNoOlderLd, $1

	// rdar://problem/36595004: Poisoned younger load is not redirected by older load-acquire
	HID_SET_BITS ARM64_REG_EHID3, ARM64_REG_EHID3_DisColorOpt, $1

	// rdar://problem/37949166: Disable the extension of prefetcher training pipe clock gating, revert to default gating
	HID_SET_BITS ARM64_REG_EHID10, ARM64_REG_EHID10_rccDisPwrSavePrfClkOff, $1

	EXEC_END

	/***** Tunables that apply to specific cores, all revisions *****/
	// Should be applied to all Aruba variants, but only Cyprus variants B0 and later
	EXEC_COREEQ_REVALL MIDR_ARUBA_VORTEX, $0, $1
	// rdar://problem/36716477: data corruption due to incorrect branch predictor resolution
	HID_SET_BITS ARM64_REG_HID1, ARM64_REG_HID1_enaBrKillLimit, $1
	EXEC_END

	/***** Tunables that apply to specific cores and revisions *****/
	EXEC_COREEQ_REVHS MIDR_CYPRUS_VORTEX, CPU_VERSION_A1, $0, $1
	// rdar://problem/36716477: data corruption due to incorrect branch predictor resolution
	HID_SET_BITS ARM64_REG_HID1, ARM64_REG_HID1_enaBrKillLimit, $1
	EXEC_END

	EXEC_COREEQ_REVEQ MIDR_ARUBA_VORTEX, CPU_VERSION_A1, $0, $1
	// rdar://problem/40695685: Enable BIF fill buffer stall logic to prevent skid buffer overflow (Aruba A1 only)
	HID_SET_BITS ARM64_REG_HID5, ARM64_REG_HID5_EnableDnFIFORdStall, $1
	EXEC_END
.endmacro