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
 * 
 */
#ifndef _MACH_PPC_RPC_H_
#define _MACH_PPC_RPC_H_

#include <mach/ppc/thread_status.h>

/*
 * Just temporary until all vestiges of short-curcuiting can be removed.
 */
#define CAN_SHCIRCUIT(name)	(0)

/*
 * Note, these don't quite work for PowerPC, because there are different
 * ABIs that lay the parameters out some in registers and some in memory
 * with slightly different results.  We need to change MIG to assure a
 * consistent layout regardless of ABI.
 */
#define MACH_RPC_ARGV(act)	(char*)(USER_REGS(act)->r3)  
#define MACH_RPC_RET(act)	( USER_REGS(act)->lr ) 
#define MACH_RPC_UIP(act)	( USER_REGS(act)->srr0 )
#define MACH_RPC_USP(act)	( USER_REGS(act)->r1 )
/* FIXME!! */
#define MACH_RPC_FUNC(act)	( USER_REGS(act)->r2 )
#define MACH_RPC_SIG(act)	( USER_REGS(act)->r2 )

#endif	/* _MACH_PPC_RPC_H_ */











