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
#ifndef _MACH_I386_RPC_H_
#define _MACH_I386_RPC_H_

/*
 * Just temporary until all vestiges of short-circuit can be
 * removed.
 */
#define CAN_SHCIRCUIT(name)	(0)

/*
 * Kernel machine dependent macros for mach rpc
 *
 * User args (argv) begin two words above the frame pointer (past saved ebp 
 * and return address) on the user stack. Return code is stored in register
 * ecx, by convention (must be a caller-saves register, to survive return
 * from server work function). The user space instruction pointer is eip,
 * and the user stack pointer is uesp.
 */
#define MACH_RPC_ARGV(act)	( (char *)(USER_REGS(act)->ebp + 8) )
#define MACH_RPC_RET(act)	( USER_REGS(act)->ecx )
#define MACH_RPC_FUNC(act)	( USER_REGS(act)->edx )
#define MACH_RPC_SIG(act)       ( USER_REGS(act)->edi ) 
#define MACH_RPC_UIP(act)	( USER_REGS(act)->eip )
#define MACH_RPC_USP(act)	( USER_REGS(act)->uesp )
#define MACH_RPC_RETADDR(sp)    ( *((int *)sp - 1) )

#endif	/* _MACH_I386_RPC_H_ */
