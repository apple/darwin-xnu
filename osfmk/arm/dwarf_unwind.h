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


#ifndef _ARM_DWARF_UNWIND_H_
#define _ARM_DWARF_UNWIND_H_

/*
 * This file contains the architecture specific DWARF definitions needed for unwind
 * information added to trap handlers.
 */

#define DWARF_ARM_R0 0
#define DWARF_ARM_R1 1
#define DWARF_ARM_R2 2
#define DWARF_ARM_R3 3
#define DWARF_ARM_R4 4
#define DWARF_ARM_R5 5
#define DWARF_ARM_R6 6
#define DWARF_ARM_R7 7
#define DWARF_ARM_R8 8
#define DWARF_ARM_R9 9
#define DWARF_ARM_R10 10
#define DWARF_ARM_R11 11
#define DWARF_ARM_R12 12
#define DWARF_ARM_SP 13
#define DWARF_ARM_LR 14
#define DWARF_ARM_PC 15

#define DW_OP_breg0       0x70
#define DW_OP_breg8       0x78
#define DW_OP_breg13      0x7d
#define DW_CFA_expression 0x10
#define DW_OP_deref       0x06
#define DW_OP_constu      0x10
#define DW_OP_plus        0x22

#define DW_FORM_LENGTH 6
#define DWARF_OFFSET_0 0

#define DWARF_ARM_R0_OFFSET 0
#define DWARF_ARM_R1_OFFSET 4
#define DWARF_ARM_R2_OFFSET 8
#define DWARF_ARM_R3_OFFSET 12
#define DWARF_ARM_R4_OFFSET 16
#define DWARF_ARM_R5_OFFSET 20
#define DWARF_ARM_R6_OFFSET 24
#define DWARF_ARM_R7_OFFSET 28
#define DWARF_ARM_R8_OFFSET 32
#define DWARF_ARM_R9_OFFSET 36
#define DWARF_ARM_R10_OFFSET 40
#define DWARF_ARM_R11_OFFSET 44
#define DWARF_ARM_R12_OFFSET 48
#define DWARF_ARM_SP_OFFSET 52
#define DWARF_ARM_LR_OFFSET 56
#define DWARF_ARM_PC_OFFSET 60

/* The actual unwind directives added to trap handlers to let the debugger know where the register state is stored */

/* Unwind Prologue added to each function to indicate the start of the unwind information. */

#define UNWIND_PROLOGUE \
.cfi_sections .eh_frame ;\
.cfi_startproc          ;\
.cfi_signal_frame       ;\


/* Unwind Epilogue added to each function to indicate the end of the unwind information */

#define UNWIND_EPILOGUE .cfi_endproc



#define UNWIND_DIRECTIVES \
.cfi_escape DW_CFA_expression, DWARF_ARM_R0,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R0_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R1,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R1_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R2,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R2_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R3,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R3_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R4,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R4_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R5,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R5_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R6,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R6_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R7,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R7_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R8,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R8_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R9,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R9_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R10,  DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R10_OFFSET, DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R11,  DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R11_OFFSET, DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_R12,  DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_R12_OFFSET, DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_SP,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_SP_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_LR,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_LR_OFFSET,  DW_OP_plus ;\
.cfi_escape DW_CFA_expression, DWARF_ARM_PC,   DW_FORM_LENGTH, DW_OP_breg13, DWARF_OFFSET_0, DW_OP_deref, DW_OP_constu, DWARF_ARM_PC_OFFSET,  DW_OP_plus ;\

#endif /* _ARM_DWARF_UNWIND_H_ */
