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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Machine dependent kernel calls.
 *
 * HISTORY
 *
 * 17 June 1992 ? at NeXT
 *	Created.
 */
 
#include <mach/mach_types.h>

#include <i386/machdep_call.h>

extern kern_return_t	kern_invalid();
extern kern_return_t	thread_get_cthread_self();
extern kern_return_t	thread_set_cthread_self();
extern kern_return_t	thread_fast_set_cthread_self();
extern kern_return_t	PCcreate(), PCldt(), PCresume();
extern kern_return_t	PCcopyBIOSData(), PCmapBIOSRom();
extern kern_return_t	PCsizeBIOSExtData(), PCcopyBIOSExtData();

machdep_call_t		machdep_call_table[] = {
    {
	thread_get_cthread_self,
	0
    },
    {
	thread_set_cthread_self,
	1
    },
    {
    	kern_invalid,	/* old th_create() */
	0
    },
    {
      thread_fast_set_cthread_self,
	1
    },
#ifdef	FIXME
    {
	PCcreate,
	3
    },
    {
    	PCldt,
	3
    },
    {
    	PCresume,
	0
    },
    {
	PCcopyBIOSData,
	1
    },
    {
    	PCsizeBIOSExtData,
	0
    },
    {
    	PCcopyBIOSExtData,
	1
    },
    {
    	PCmapBIOSRom,
	3
    },
#endif
};

int	machdep_call_count =
    (sizeof (machdep_call_table) / sizeof (machdep_call_t));
