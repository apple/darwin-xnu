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
 *	Copyright (C) 1990,  NeXT, Inc.
 *
 *	File:	next/kern_machdep.c
 *	Author:	John Seamons
 *
 *	Machine-specific kernel routines.
 */

#include	<sys/types.h>
#include	<mach/machine.h>
#include	<kern/cpu_number.h>
#include	<machine/exec.h>
#include	<machine/machine_routines.h>

/**********************************************************************
 * Routine:	grade_binary()
 *
 * Function:	Keep the API the same between PPC and X86; always say
 *		any CPU subtype is OK with us, but only OK CPU types
 *		for which we are actually capable of executing the
 *		binary, either directly or via an imputed interpreter.
 **********************************************************************/
int
grade_binary(cpu_type_t exectype, cpu_subtype_t execsubtype)
{
	switch(exectype) {
	case CPU_TYPE_X86:		/* native */
	case CPU_TYPE_POWERPC:		/* via translator */
		return 1;
	case CPU_TYPE_X86_64:		/* native 64-bit */
		return (ml_is64bit() && execsubtype == CPU_SUBTYPE_X86_64_ALL) ? 2 : 0;
	default:			/* all other binary types */
		return 0;
	}
}

extern void md_prepare_for_shutdown(int, int, char *);

void
md_prepare_for_shutdown(
	__unused int paniced,
	__unused int howto,
	__unused char * command)
{
}
