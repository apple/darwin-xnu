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
/* CMU_ENDHIST */
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

/*
 * Processor registers for i386 and i486.
 */
#ifndef	_I386_PROC_REG_H_
#define	_I386_PROC_REG_H_

/*
 * Model Specific Registers
 */
#define	MSR_P5_TSC		0x10	/* Time Stamp Register */
#define	MSR_P5_CESR		0x11	/* Control and Event Select Register */
#define	MSR_P5_CTR0		0x12	/* Counter #0 */
#define	MSR_P5_CTR1		0x13	/* Counter #1 */

#define	MSR_P5_CESR_PC		0x0200	/* Pin Control */
#define	MSR_P5_CESR_CC		0x01C0	/* Counter Control mask */
#define	MSR_P5_CESR_ES		0x003F	/* Event Control mask */

#define	MSR_P5_CESR_SHIFT	16		/* Shift to get Counter 1 */
#define	MSR_P5_CESR_MASK	(MSR_P5_CESR_PC|\
				 MSR_P5_CESR_CC|\
				 MSR_P5_CESR_ES) /* Mask Counter */

#define	MSR_P5_CESR_CC_CLOCK	0x0100	/* Clock Counting (otherwise Event) */
#define	MSR_P5_CESR_CC_DISABLE	0x0000	/* Disable counter */
#define	MSR_P5_CESR_CC_CPL012	0x0040	/* Count if the CPL == 0, 1, 2 */
#define	MSR_P5_CESR_CC_CPL3	0x0080	/* Count if the CPL == 3 */
#define	MSR_P5_CESR_CC_CPL	0x00C0	/* Count regardless of the CPL */

#define	MSR_P5_CESR_ES_DATA_READ       0x000000	/* Data Read */
#define	MSR_P5_CESR_ES_DATA_WRITE      0x000001	/* Data Write */
#define	MSR_P5_CESR_ES_DATA_RW	       0x101000	/* Data Read or Write */
#define	MSR_P5_CESR_ES_DATA_TLB_MISS   0x000010	/* Data TLB Miss */
#define	MSR_P5_CESR_ES_DATA_READ_MISS  0x000011	/* Data Read Miss */
#define	MSR_P5_CESR_ES_DATA_WRITE_MISS 0x000100	/* Data Write Miss */
#define	MSR_P5_CESR_ES_DATA_RW_MISS    0x101001	/* Data Read or Write Miss */
#define	MSR_P5_CESR_ES_HIT_EM	       0x000101	/* Write (hit) to M|E state */
#define	MSR_P5_CESR_ES_DATA_CACHE_WB   0x000110	/* Cache lines written back */
#define	MSR_P5_CESR_ES_EXTERNAL_SNOOP  0x000111	/* External Snoop */
#define	MSR_P5_CESR_ES_CACHE_SNOOP_HIT 0x001000	/* Data cache snoop hits */
#define	MSR_P5_CESR_ES_MEM_ACCESS_PIPE 0x001001	/* Mem. access in both pipes */
#define	MSR_P5_CESR_ES_BANK_CONFLICTS  0x001010	/* Bank conflicts */
#define	MSR_P5_CESR_ES_MISALIGNED      0x001011	/* Misaligned Memory or I/O */
#define	MSR_P5_CESR_ES_CODE_READ       0x001100	/* Code Read */
#define	MSR_P5_CESR_ES_CODE_TLB_MISS   0x001101	/* Code TLB miss */
#define	MSR_P5_CESR_ES_CODE_CACHE_MISS 0x001110	/* Code Cache miss */
#define	MSR_P5_CESR_ES_SEGMENT_LOADED  0x001111	/* Any segment reg. loaded */
#define	MSR_P5_CESR_ES_BRANCHE	       0x010010	/* Branches */
#define	MSR_P5_CESR_ES_BTB_HIT	       0x010011	/* BTB Hits */
#define	MSR_P5_CESR_ES_BRANCHE_BTB     0x010100	/* Taken branch or BTB Hit */
#define	MSR_P5_CESR_ES_PIPELINE_FLUSH  0x010101	/* Pipeline Flushes */
#define	MSR_P5_CESR_ES_INSTRUCTION     0x010110	/* Instruction executed */
#define	MSR_P5_CESR_ES_INSTRUCTION_V   0x010111	/* Inst. executed (v-pipe) */
#define	MSR_P5_CESR_ES_BUS_CYCLE       0x011000	/* Clocks while bus cycle */
#define	MSR_P5_CESR_ES_FULL_WRITE_BUF  0x011001	/* Clocks while full wrt buf. */
#define	MSR_P5_CESR_ES_DATA_MEM_READ   0x011010	/* Pipeline waiting for read */
#define	MSR_P5_CESR_ES_WRITE_EM        0x011011	/* Stall on write E|M state */
#define	MSR_P5_CESR_ES_LOCKED_CYCLE    0x011100	/* Locked bus cycles */
#define	MSR_P5_CESR_ES_IO_CYCLE	       0x011101	/* I/O Read or Write cycles */
#define	MSR_P5_CESR_ES_NON_CACHEABLE   0x011110	/* Non-cacheable Mem. read */
#define	MSR_P5_CESR_ES_AGI	       0x011111	/* Stall because of AGI */
#define	MSR_P5_CESR_ES_FLOP	       0x100010	/* Floating Point operations */
#define	MSR_P5_CESR_ES_BREAK_DR0       0x100011	/* Breakpoint matches on DR0 */
#define	MSR_P5_CESR_ES_BREAK_DR1       0x100100	/* Breakpoint matches on DR1 */
#define	MSR_P5_CESR_ES_BREAK_DR2       0x100101	/* Breakpoint matches on DR2 */
#define	MSR_P5_CESR_ES_BREAK_DR3       0x100110	/* Breakpoint matches on DR3 */
#define	MSR_P5_CESR_ES_HARDWARE_IT     0x100111	/* Hardware interrupts */

/*
 * CR0
 */
#define	CR0_PG	0x80000000	/*	 Enable paging */
#define	CR0_CD	0x40000000	/* i486: Cache disable */
#define	CR0_NW	0x20000000	/* i486: No write-through */
#define	CR0_AM	0x00040000	/* i486: Alignment check mask */
#define	CR0_WP	0x00010000	/* i486: Write-protect kernel access */
#define	CR0_NE	0x00000020	/* i486: Handle numeric exceptions */
#define	CR0_ET	0x00000010	/*	 Extension type is 80387 */
				/*	 (not official) */
#define	CR0_TS	0x00000008	/*	 Task switch */
#define	CR0_EM	0x00000004	/*	 Emulate coprocessor */
#define	CR0_MP	0x00000002	/*	 Monitor coprocessor */
#define	CR0_PE	0x00000001	/*	 Enable protected mode */

/*
 * CR4
 */
#define	CR4_MCE	0x00000040	/* p5:   Machine Check Exceptions */
#define	CR4_PSE	0x00000010	/* p5:   Page Size Extensions */
#define	CR4_DE	0x00000008	/* p5:   Debugging Extensions */
#define	CR4_TSD	0x00000004	/* p5:   Time Stamp Disable */
#define	CR4_PVI	0x00000002	/* p5:   Protected-mode Virtual Interrupts */
#define	CR4_VME	0x00000001	/* p5:   Virtual-8086 Mode Extensions */

#ifndef	ASSEMBLER
extern unsigned int	get_cr0(void);
extern void		set_cr0(
				unsigned int		value);
extern unsigned int	get_cr2(void);
extern unsigned int	get_cr3(void);
extern void		set_cr3(
				unsigned int		value);
extern unsigned int	get_cr4(void);
extern void		set_cr4(
				unsigned int		value);

#define	set_ts() \
	set_cr0(get_cr0() | CR0_TS)
extern void		clear_ts(void);

extern unsigned short	get_tr(void);
extern void		set_tr(
			       unsigned int		seg);

extern unsigned short	get_ldt(void);
extern void		set_ldt(
				unsigned int		seg);
#ifdef	__GNUC__
extern __inline__ unsigned int get_cr0(void)
{
	register unsigned int cr0; 
	__asm__ volatile("mov %%cr0, %0" : "=r" (cr0));
	return(cr0);
}

extern __inline__ void set_cr0(unsigned int value)
{
	__asm__ volatile("mov %0, %%cr0" : : "r" (value));
}

extern __inline__ unsigned int get_cr2(void)
{
	register unsigned int cr2;
	__asm__ volatile("mov %%cr2, %0" : "=r" (cr2));
	return(cr2);
}

#if	NCPUS > 1 && AT386
/*
 * get_cr3 and set_cr3 are more complicated for the MPs. cr3 is where
 * the cpu number gets stored. The MP versions live in locore.s
 */
#else	/* NCPUS > 1 && AT386 */
extern __inline__ unsigned int get_cr3(void)
{
	register unsigned int cr3;
	__asm__ volatile("mov %%cr3, %0" : "=r" (cr3));
	return(cr3);
}

extern __inline__ void set_cr3(unsigned int value)
{
	__asm__ volatile("mov %0, %%cr3" : : "r" (value));
}
#endif	/* NCPUS > 1 && AT386 */

extern __inline__ void clear_ts(void)
{
	__asm__ volatile("clts");
}

extern __inline__ unsigned short get_tr(void)
{
	unsigned short seg; 
	__asm__ volatile("str %0" : "=rm" (seg));
	return(seg);
}

extern __inline__ void set_tr(unsigned int seg)
{
	__asm__ volatile("ltr %0" : : "rm" ((unsigned short)(seg)));
}

extern __inline__ unsigned short get_ldt(void)
{
	unsigned short seg;
	__asm__ volatile("sldt %0" : "=rm" (seg));
	return(seg);
}

extern __inline__ void set_ldt(unsigned int seg)
{
	__asm__ volatile("lldt %0" : : "rm" ((unsigned short)(seg)));
}

extern __inline__ void flush_tlb(void)
{
	unsigned long	cr3_temp;
	__asm__ volatile("movl %%cr3, %0; movl %0, %%cr3" : "=r" (cr3_temp) :: "memory");
}

extern __inline__ void invlpg(unsigned long addr)
{
	__asm__  volatile("invlpg (%0)" :: "r" (addr) : "memory");
}
#endif	/* __GNUC__ */
#endif	/* ASSEMBLER */

#endif	/* _I386_PROC_REG_H_ */
