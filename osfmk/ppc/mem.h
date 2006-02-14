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

#ifndef _PPC_MEM_H_
#define _PPC_MEM_H_

#include <mach_kdb.h>
#include <mach_kgdb.h>

#include <ppc/proc_reg.h>
#include <ppc/pmap.h>
#include <mach/vm_types.h>

extern vm_offset_t	static_memory_end;

extern addr64_t		hash_table_base;
extern unsigned int	hash_table_size;
extern int          hash_table_shift;   /* size adjustment: bigger if >0, smaller if <0 */

void hash_table_init(vm_offset_t base, vm_offset_t size);

#define MAX_BAT		4

#pragma pack(4)							/* Make sure the structure stays as we defined it */
typedef struct ppcBAT {
	unsigned int	upper;	/* Upper half of BAT */
	unsigned int	lower;	/* Lower half of BAT */
} ppcBAT;
#pragma pack()

#pragma pack(4)							/* Make sure the structure stays as we defined it */
struct shadowBAT {
	ppcBAT	IBATs[MAX_BAT];	/* Instruction BATs */
	ppcBAT	DBATs[MAX_BAT];	/* Data BAT */
};
#pragma pack()

extern struct shadowBAT shadow_BAT;     

#endif /* _PPC_MEM_H_ */
