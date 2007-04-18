/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#ifndef _PEXPERT_PPC_POWERMAC_H_
#define _PEXPERT_PPC_POWERMAC_H_

#ifndef ASSEMBLER

#include <mach/ppc/vm_types.h>

#include <pexpert/pexpert.h>
#include <pexpert/protos.h>
#include <pexpert/ppc/boot.h>


/* prototypes */

vm_offset_t PE_find_scc( void );

/* Some useful typedefs for accessing control registers */

typedef volatile unsigned char	v_u_char;
typedef volatile unsigned short v_u_short;
typedef volatile unsigned int	v_u_int;
typedef volatile unsigned long  v_u_long;

/* And some useful defines for reading 'volatile' structures,
 * don't forget to be be careful about sync()s and eieio()s
 */
#define reg8(reg) (*(v_u_char *)reg)
#define reg16(reg) (*(v_u_short *)reg)
#define reg32(reg) (*(v_u_int *)reg)

/* Non-cached version of bcopy */
extern void	bcopy_nc(char *from, char *to, int size);

#endif /* ASSEMBLER */

#endif /* _PEXPERT_PPC_POWERMAC_H_ */
