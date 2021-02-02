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

#ifndef _ARM64_PAC_ASM_H_
#define _ARM64_PAC_ASM_H_

#ifndef __ASSEMBLER__
#error "This header should only be used in .s files"
#endif

#include <pexpert/arm64/board_config.h>
#include <arm64/proc_reg.h>
#include "assym.s"

#if defined(HAS_APPLE_PAC)

#if defined(APPLEFIRESTORM)
/* H13 may use either fast or slow A-key switching, depending on CPU model and revision */
#define HAS_PAC_FAST_A_KEY_SWITCHING    1
#define HAS_PAC_SLOW_A_KEY_SWITCHING    1

/* BEGIN IGNORE CODESTYLE */

/**
 * IF_PAC_FAST_A_KEY_SWITCHING
 *
 * Branch to a specified label if this H13 model + revision supports fast A-key switching.
 *
 *   label - label to branch to
 *   tmp - scratch register
 */
.macro IF_PAC_FAST_A_KEY_SWITCHING	label, tmp
	/**
	 * start.s attempts to set APCTL_EL1.UserKeyEn.  If this H13 CPU doesn't
	 * actually support this bit, it will be RaZ.
	 */
	mrs		\tmp, APCTL_EL1
	tbnz	\tmp, #APCTL_EL1_UserKeyEn_OFFSET, \label
.endmacro

/**
 * IF_PAC_SLOW_A_KEY_SWITCHING
 *
 * Branch to a specified label if this H13 model + revision doesn't support fast A-key switching.
 *
 *   label - label to branch to
 *   tmp - scratch register
 */
.macro IF_PAC_SLOW_A_KEY_SWITCHING	label, tmp
	mrs		\tmp, APCTL_EL1
	tbz		\tmp, #APCTL_EL1_UserKeyEn_OFFSET, \label
.endmacro

/* END IGNORE CODESTYLE */

#elif defined(HAS_APCTL_EL1_USERKEYEN)
#define HAS_PAC_FAST_A_KEY_SWITCHING    1
#define HAS_PAC_SLOW_A_KEY_SWITCHING    0

.macro IF_PAC_FAST_A_KEY_SWITCHING      label, tmp
.error "This macro should never need to be used on this CPU family."
.endmacro

/* We know at compile time that this CPU family definitely doesn't need slow A-key switching */
.macro IF_PAC_SLOW_A_KEY_SWITCHING      label, tmp
.endmacro

#else /* !defined(APPLEFIRESTORM) && !defined(HAS_APCTL_EL1_USERKEYEN) */
#define HAS_PAC_FAST_A_KEY_SWITCHING    0
#define HAS_PAC_SLOW_A_KEY_SWITCHING    1

/* We know at compile time that this CPU family definitely doesn't support fast A-key switching */
.macro IF_PAC_FAST_A_KEY_SWITCHING      label, tmp
.endmacro

.macro IF_PAC_SLOW_A_KEY_SWITCHING      label, tmp
.error "This macro should never need to be used on this CPU family."
.endmacro

#endif /* defined(APPLEFIRESTORM) */

/* BEGIN IGNORE CODESTYLE */

/**
 * REPROGRAM_JOP_KEYS
 *
 * Reprograms the A-key registers if needed, and updates current_cpu_datap()->jop_key.
 *
 * On CPUs where fast A-key switching is implemented, this macro reprograms KERNKey_EL1.
 * On other CPUs, it reprograms AP{D,I}AKey_EL1.
 *
 *   skip_label - branch to this label if new_jop_key is already loaded into CPU
 *   new_jop_key - new APIAKeyLo value
 *   cpudatap - current cpu_data_t *
 *   tmp - scratch register
 */
.macro REPROGRAM_JOP_KEYS	skip_label, new_jop_key, cpudatap, tmp
	ldr		\tmp, [\cpudatap, CPU_JOP_KEY]
	cmp		\new_jop_key, \tmp
	b.eq	\skip_label
	SET_JOP_KEY_REGISTERS	\new_jop_key, \tmp
	str		\new_jop_key, [\cpudatap, CPU_JOP_KEY]
.endmacro

/**
 * SET_JOP_KEY_REGISTERS
 *
 * Unconditionally reprograms the A-key registers.  The caller is responsible for
 * updating current_cpu_datap()->jop_key as needed.
 *
 *   new_jop_key - new APIAKeyLo value
 *   tmp - scratch register
 */
.macro SET_JOP_KEY_REGISTERS	new_jop_key, tmp
#if HAS_PAC_FAST_A_KEY_SWITCHING
	IF_PAC_SLOW_A_KEY_SWITCHING	Lslow_reprogram_jop_keys_\@, \tmp
	msr		KERNKeyLo_EL1, \new_jop_key
	add		\tmp, \new_jop_key, #1
	msr		KERNKeyHi_EL1, \tmp
#endif /* HAS_PAC_FAST_A_KEY_SWITCHING */
#if HAS_PAC_FAST_A_KEY_SWITCHING && HAS_PAC_SLOW_A_KEY_SWITCHING
	b		Lset_jop_key_registers_done_\@
#endif /* HAS_PAC_FAST_A_KEY_SWITCHING && HAS_PAC_SLOW_A_KEY_SWITCHING */

#if HAS_PAC_SLOW_A_KEY_SWITCHING
Lslow_reprogram_jop_keys_\@:
	msr		APIAKeyLo_EL1, \new_jop_key
	add		\tmp, \new_jop_key, #1
	msr		APIAKeyHi_EL1, \tmp
	add		\tmp, \tmp, #1
	msr		APDAKeyLo_EL1, \tmp
	add		\tmp, \tmp, #1
	msr		APDAKeyHi_EL1, \tmp
#endif /* HAS_PAC_SLOW_A_KEY_SWITCHING */

Lset_jop_key_registers_done_\@:
.endmacro

/* END IGNORE CODESTYLE */

#endif /* defined(HAS_APPLE_PAC) */

#endif /* _ARM64_PAC_ASM_H_ */

/* vim: set ts=4 ft=asm: */
