/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef	_MACH_PPC_SYSCALL_SW_H_
#define _MACH_PPC_SYSCALL_SW_H_

#include <mach/machine/asm.h>

#define kernel_trap(trap_name,trap_number,number_args) \
ENTRY(trap_name, TAG_NO_FRAME_USED) @\
	li	r0,	trap_number @\
	sc	@\
	blr

#define rpc_trap(trap_name,trap_number,number_args) \
ENTRY(trap_name, TAG_NO_FRAME_USED) @\
	li	r0,	trap_number @\
	sc	@\
	blr

	/* CHECKME! What is this supposed to do? */
#define rpc_return_trap(trap_name,trap_number,number_args) \
ENTRY(trap_name, TAG_NO_FRAME_USED) @\
	li	r0,	trap_number @\
	sc	@\
	blr
	
#define ppc_trap(trap_name,trap_number) \
ENTRY(trap_name, TAG_NO_FRAME_USED) @\
	li	r0,	trap_number @\
	sc	@\
	blr
	
/*
 *	Put any definitions for PPC-only system calls in here (only if
 *	this file is being included from the one that instantiates the
 *	mach system calls).
 *
 *	Note: PPC-only system calls are in the 0x6000 to 0x6FFF range
 */
#ifdef _MACH_SYSCALL_SW_H_	
ppc_trap(diagCall,0x6000)	
ppc_trap(vmm_get_version,0x6001)
ppc_trap(vmm_get_features,0x6002)
ppc_trap(vmm_init_context,0x6003)	
ppc_trap(vmm_dispatch,0x6004)	
ppc_trap(bb_enable_bluebox,0x6005)	
ppc_trap(bb_disable_bluebox,0x6006)	
ppc_trap(bb_settaskenv,0x6007)	
ppc_trap(vmm_stop_vm,0x6008)	
ppc_trap(CHUDCall,0x6009)	
ppc_trap(ppcNull,0x600A)	
ppc_trap(perfmon_control,0x600B)	
ppc_trap(ppcNullinst,0x600C)	
#endif /* _MACH_SYSCALL_SW_H_ */

#endif	/* _MACH_PPC_SYSCALL_SW_H_ */
