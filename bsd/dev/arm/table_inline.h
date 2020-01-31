/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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

static inline gdt_entry_t *
sel_to_gdt_entry(sel_t sel)
{
	return &gdt[sel.index];
}

static inline idt_entry_t *
sel_to_idt_entry(sel_t sel)
{
	return &idt[sel.index];
}

static inline ldt_entry_t *
sel_to_ldt_entry(ldt_t *tbl, sel_t sel)
{
	return &tbl[sel.index];
}
