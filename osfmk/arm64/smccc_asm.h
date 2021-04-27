/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef _ARM64_SMCCC_ASM_H_
#define _ARM64_SMCCC_ASM_H_

#ifndef __ASSEMBLER__
#error "This header should only be used in .s files"
#endif

/*
 * SAVE_SMCCC_CLOBBERED_REGISTERS
 *
 * Saves x0-x3 to stack in preparation for an hvc/smc call.
 */

.macro  SAVE_SMCCC_CLOBBERED_REGISTERS
stp             x0, x1, [sp, #- 16]!
stp             x2, x3, [sp, #- 16]!
.endmacro

/*
 * LOAD_SMCCC_CLOBBERED_REGISTERS
 *
 * Loads x0-x3 from stack after an hvc/smc call.
 */

.macro  LOAD_SMCCC_CLOBBERED_REGISTERS
ldp             x2, x3, [sp], #16
ldp             x0, x1, [sp], #16
.endmacro

#endif /* _ARM64_SMCCC_ASM_H_ */

/* vim: set ts=4 ft=asm: */
