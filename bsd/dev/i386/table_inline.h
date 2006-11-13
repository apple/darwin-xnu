/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Intel386 Family:	Selector based access to descriptor tables.
 *
 * HISTORY
 *
 * 2 April 1992 ? at NeXT
 *	Created.
 */
 
#include <architecture/i386/table.h>

#include <machdep/i386/gdt.h>
#include <machdep/i386/idt.h>

static inline
gdt_entry_t *
sel_to_gdt_entry(sel)
sel_t		sel;
{
    return (&gdt[sel.index]);
}

static inline
idt_entry_t *
sel_to_idt_entry(sel)
sel_t		sel;
{
    return (&idt[sel.index]);
}

static inline
ldt_entry_t *
sel_to_ldt_entry(tbl, sel)
ldt_t *		tbl;
sel_t		sel;
{
    return (&tbl[sel.index]);
}
