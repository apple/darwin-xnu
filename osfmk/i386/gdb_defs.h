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

#ifndef	_I386_GDB_DEFS_H_
#define	_I386_GDB_DEFS_H_

/*
 * GDB DEPENDENT DEFINITIONS
 *
 * The following definitions match data descriptions in the gdb source file
 * gdb/include/AT386/tm.h.  They cannot be independently modified.
 */

typedef struct {
	unsigned int	eax;
	unsigned int	ecx;
	unsigned int	edx;
	unsigned int	ebx;
	unsigned int	esp;
	unsigned int	ebp;
	unsigned int	esi;
	unsigned int	edi;
	unsigned int	eip;
	unsigned int	efl;
	unsigned int	cs;
	unsigned int	ss;
	unsigned int	ds;
	unsigned int	es;
	unsigned int	fs;
	unsigned int	gs;
	unsigned int	reason;
} kgdb_regs_t;

#define NUM_REGS 16
#define REGISTER_BYTES (NUM_REGS * 4)

#endif	/* _I386_GDB_DEFS_H_ */

