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
#ifndef	_MACH_PPC_VM_PARAM_H_
#define _MACH_PPC_VM_PARAM_H_

#define BYTE_SIZE	8	/* byte size in bits */

#define PPC_PGBYTES	4096	/* bytes per ppc page */
#define PPC_PGSHIFT	12	/* number of bits to shift for pages */

#define VM_MIN_ADDRESS	((vm_offset_t) 0)
#define VM_MAX_ADDRESS	((vm_offset_t) 0xfffff000U)

#define VM_MIN_KERNEL_ADDRESS	((vm_offset_t) 0x00001000)

/* We map the kernel using only SR0,SR1,SR2,SR3 leaving segments alone */
#define VM_MAX_KERNEL_ADDRESS	((vm_offset_t) 0x3fffffff)

#define USER_STACK_END  ((vm_offset_t) 0xffff0000U)

#define ppc_round_page(x)	((((unsigned)(x)) + PPC_PGBYTES - 1) & \
					~(PPC_PGBYTES-1))
#define ppc_trunc_page(x)	(((unsigned)(x)) & ~(PPC_PGBYTES-1))


#define KERNEL_STACK_SIZE	(4 * PPC_PGBYTES)
#define INTSTACK_SIZE		(5 * PPC_PGBYTES)

#endif	/* _PPC_VM_PARAM_H_ */
