/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */

#ifndef	_I386_SEG_H_
#define	_I386_SEG_H_

#include <mach_kdb.h>
#include <stdint.h>
#include <architecture/i386/sel.h>

/*
 * i386 segmentation.
 */

static inline uint16_t
sel_to_selector(sel_t	sel)
{
    union {
	sel_t		sel;
	uint16_t	selector;
    } tconv;
    
    tconv.sel = sel;
    
    return (tconv.selector);
}

static inline sel_t
selector_to_sel(uint16_t selector)
{
    union {
	uint16_t	selector;
	sel_t		sel;
    } tconv;
    
    tconv.selector = selector;
    
    return (tconv.sel);
}

#define	LDTSZ		15		/* size of the kernel ldt in entries*/

#if	MACH_KDB
#ifdef MACH_BSD
#define	GDTSZ		14
#else
#define	GDTSZ		11
#endif
#else	/* MACH_KDB */
#ifdef	MACH_BSD
#define	GDTSZ		13
#else
#define	GDTSZ		10
#endif
#endif	/* MACH_KDB */

/*
 * Interrupt table is always 256 entries long.
 */
#define	IDTSZ		256

#ifndef	__ASSEMBLER__

#include <sys/cdefs.h>

/*
 * Real segment descriptor.
 */
struct real_descriptor {
	unsigned int	limit_low:16,	/* limit 0..15 */
			base_low:16,	/* base  0..15 */
			base_med:8,	/* base  16..23 */
			access:8,	/* access byte */
			limit_high:4,	/* limit 16..19 */
			granularity:4,	/* granularity */
			base_high:8;	/* base 24..31 */
};

struct real_gate {
	unsigned int	offset_low:16,	/* offset 0..15 */
			selector:16,
			word_count:8,
			access:8,
			offset_high:16;	/* offset 16..31 */
};

/*
 * We build descriptors and gates in a 'fake' format to let the
 * fields be contiguous.  We shuffle them into the real format
 * at runtime.
 */
struct fake_descriptor {
	unsigned int	offset:32;		/* offset */
	unsigned int	lim_or_seg:20;		/* limit */
						/* or segment, for gate */
	unsigned int	size_or_wdct:4;		/* size/granularity */
						/* word count, for gate */
	unsigned int	access:8;		/* access */
};

/*
 * Boot-time data for master (or only) CPU
 */
extern struct fake_descriptor	idt[IDTSZ];
extern struct fake_descriptor	gdt[GDTSZ];
extern struct fake_descriptor	ldt[LDTSZ];
extern struct i386_tss		ktss;

__BEGIN_DECLS

#if	MACH_KDB
extern char			db_stack_store[];
extern char			db_task_stack_store[];
extern struct i386_tss		dbtss;
extern void			db_task_start(void);
#endif	/* MACH_KDB */

__END_DECLS

#endif	/*__ASSEMBLER__*/

#define	SZ_32		0x4			/* 32-bit segment */
#define	SZ_G		0x8			/* 4K limit field */

#define	ACC_A		0x01			/* accessed */
#define	ACC_TYPE	0x1e			/* type field: */

#define	ACC_TYPE_SYSTEM	0x00			/* system descriptors: */

#define	ACC_LDT		0x02			    /* LDT */
#define	ACC_CALL_GATE_16 0x04			    /* 16-bit call gate */
#define	ACC_TASK_GATE	0x05			    /* task gate */
#define	ACC_TSS		0x09			    /* task segment */
#define	ACC_CALL_GATE	0x0c			    /* call gate */
#define	ACC_INTR_GATE	0x0e			    /* interrupt gate */
#define	ACC_TRAP_GATE	0x0f			    /* trap gate */

#define	ACC_TSS_BUSY	0x02			    /* task busy */

#define	ACC_TYPE_USER	0x10			/* user descriptors */

#define	ACC_DATA	0x10			    /* data */
#define	ACC_DATA_W	0x12			    /* data, writable */
#define	ACC_DATA_E	0x14			    /* data, expand-down */
#define	ACC_DATA_EW	0x16			    /* data, expand-down,
							     writable */
#define	ACC_CODE	0x18			    /* code */
#define	ACC_CODE_R	0x1a			    /* code, readable */
#define	ACC_CODE_C	0x1c			    /* code, conforming */
#define	ACC_CODE_CR	0x1e			    /* code, conforming,
						       readable */
#define	ACC_PL		0x60			/* access rights: */
#define	ACC_PL_K	0x00			/* kernel access only */
#define	ACC_PL_U	0x60			/* user access */
#define	ACC_P		0x80			/* segment present */

/*
 * Components of a selector
 */
#define	SEL_LDTS	0x04			/* local selector */
#define	SEL_PL		0x03			/* privilege level: */
#define	SEL_PL_K	0x00			    /* kernel selector */
#define	SEL_PL_U	0x03			    /* user selector */

/*
 * Convert selector to descriptor table index.
 */
#define	sel_idx(sel)	(selector_to_sel(sel).index)

#define NULL_SEG	0

/*
 * User descriptors for MACH - 32-bit flat address space
 */
#define	USER_SCALL	0x07		/* system call gate */
#define	USER_RPC	0x0f		/* mach rpc call gate */
#define	USER_CS		0x17		/* user code segment */
#define	USER_DS		0x1f		/* user data segment */
#define	USER_CTHREAD	0x27		/* user cthread area */
#define	USER_SETTABLE	0x2f		/* start of user settable ldt entries */
#define	USLDTSZ		10		/* number of user settable entries */

/*
 * Kernel descriptors for MACH - 32-bit flat address space.
 */
#define	KERNEL_CS	0x08		/* kernel code */
#define	KERNEL_DS	0x10		/* kernel data */
#define	KERNEL_LDT	0x18		/* master LDT */
#define	KERNEL_TSS	0x20		/* master TSS (uniprocessor) */
#ifdef	MACH_BSD
#define	BSD_SCALL_SEL	0x28		/* BSD System calls */
#define	MK25_SCALL_SEL	0x30		/* MK25 System Calls */
#define	MACHDEP_SCALL_SEL 0x38		/* Machdep SYstem calls */
#else
#define	USER_LDT	0x28		/* place for per-thread LDT */
#define	USER_TSS	0x30		/* place for per-thread TSS
					   that holds IO bitmap */
#define	FPE_CS		0x38		/* floating-point emulator code */
#endif
#define	USER_FPREGS	0x40		/* user-mode access to saved
					   floating-point registers */
#define	CPU_DATA_GS	0x48		/* per-cpu data */

#ifdef	MACH_BSD
#define	USER_LDT	0x58
#define	USER_TSS	0x60
#define	FPE_CS		0x68
#endif

#if	MACH_KDB
#define	DEBUG_TSS	0x50		/* debug TSS (uniprocessor) */
#endif

#endif	/* _I386_SEG_H_ */
