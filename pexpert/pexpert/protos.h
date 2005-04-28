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
#ifndef _PEXPERT_PROTOS_H_
#define _PEXPERT_PROTOS_H_

#ifdef PEXPERT_KERNEL_PRIVATE


#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/boolean.h>
#include <stdarg.h>
#include <string.h>
#include <kern/assert.h>

#include <pexpert/machine/protos.h>

//------------------------------------------------------------------------
// from ppc/misc_protos.h
extern void printf(const char *fmt, ...);

extern void interrupt_enable(void);
extern void interrupt_disable(void);
#if __ppc__
extern void bcopy_nc(char *from, char *to, int size); /* uncached-safe */
#else
#define bcopy_nc bcopy
#endif 

//------------------------------------------------------------------------
//from kern/misc_protos.h
extern void    
_doprnt(
        register const char     *fmt,
        va_list                 *argp,
        void                    (*putc)(char),
        int                     radix);

#include <machine/io_map_entries.h>

//------------------------------------------------------------------------
// ??
//typedef int kern_return_t;
void Debugger(const char *message);

#include <kern/cpu_number.h>
#include <kern/cpu_data.h>

//------------------------------------------------------------------------
// from kgdb/kgdb_defs.h
#define kgdb_printf printf

#include <mach/machine/vm_types.h>
#include <device/device_types.h>
#include <kern/kalloc.h>

//------------------------------------------------------------------------

// from iokit/IOStartIOKit.cpp
extern int StartIOKit( void * p1, void * p2, void * p3, void * p4);

// from iokit/Families/IOFramebuffer.cpp
extern unsigned char appleClut8[ 256 * 3 ];


#endif /* PEXPERT_KERNEL_PRIVATE */

#endif /* _PEXPERT_PROTOS_H_ */
