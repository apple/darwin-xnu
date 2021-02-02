/*
 * Copyright (c) 2007-2014 Apple Inc. All rights reserved.
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

#include <arm/asm.h>
#include <arm/proc_reg.h>
#include <mach_kdp.h>
#include "assym.s"

	.text
	.align 12

	.align 2
	.globl EXT(resume_idle_cpu)
LEXT(resume_idle_cpu)
	// r0 set to BootArgs phys address
	// r1 set to cpu data phys address
	LOAD_ADDR(lr, arm_init_idle_cpu)
	b		L_start_cpu_0

	.globl EXT(start_cpu)
LEXT(start_cpu)
	// r0 set to BootArgs phys address
	// r1 set to cpu data phys address
	LOAD_ADDR(lr, arm_init_cpu)
	b		L_start_cpu_0

L_start_cpu_0:
	cpsid	if									// Disable IRQ FIQ

	// Turn on L1 I-Cache, Branch prediction early
	mcr		p15, 0, r11, c7, c5, 0				// invalidate the icache
	isb											// before moving on
	mrc		p15, 0, r11, c1, c0, 0				// read mmu control into r11
	orr		r11, r11, #(SCTLR_ICACHE | SCTLR_PREDIC)	// enable i-cache, b-prediction
	mcr		p15, 0, r11, c1, c0, 0				// set mmu control
	dsb											// ensure mmu settings are inplace
	isb											// before moving on

	// Get the kernel's phys & virt addr, and size from BootArgs
	ldr		r8, [r0, BA_PHYS_BASE]				// Get the phys base in r8
	ldr		r9, [r0, BA_VIRT_BASE]				// Get the virt base in r9
	ldr		r10, [r0, BA_MEM_SIZE]				// Get the mem size in r10

	// Set the base of the translation table into the MMU
	ldr		r4, [r0, BA_TOP_OF_KERNEL_DATA]		// Get the top of kernel data
	orr		r5, r4, #(TTBR_SETUP & 0x00FF)		// Setup PTWs memory attribute
	orr		r5, r5, #(TTBR_SETUP & 0xFF00)		// Setup PTWs memory attribute
	mcr		p15, 0, r5, c2, c0, 0				// write kernel to translation table base 0
	mcr		p15, 0, r5, c2, c0, 1				// also to translation table base 1
	mov		r5, #TTBCR_N_SETUP					// identify the split between 0 and 1
	mcr		p15, 0, r5, c2, c0, 2				// and set up the translation control reg
	ldr		r2, [r1, CPU_NUMBER_GS]				// Get cpu number
	mcr		p15, 0, r2, c13, c0, 3				// Write TPIDRURO
	ldr		sp, [r1, CPU_INTSTACK_TOP]			// Get interrupt stack top
	sub		sp, sp, SS_SIZE						// Set stack pointer
	sub		r0, r1, r8							// Convert to virtual address
	add		r0, r0, r9
	b		join_start

	.align 2
	.globl EXT(_start)
LEXT(_start)
	// r0 has the boot-args pointer 
	// r1 set to zero
	mov		r1, #0
	LOAD_ADDR(lr, arm_init)
	cpsid	if									// Disable IRQ FIQ

	// Turn on L1 I-Cache, Branch prediction early
	mcr		p15, 0, r11, c7, c5, 0				// invalidate the icache
	isb											// before moving on
	mrc		p15, 0, r11, c1, c0, 0				// read mmu control into r11
	orr		r11, r11, #(SCTLR_ICACHE | SCTLR_PREDIC)	// enable i-cache, b-prediction
	mcr		p15, 0, r11, c1, c0, 0				// set mmu control
	dsb											// ensure mmu settings are inplace
	isb											// before moving on

	// Get the kernel's phys & virt addr, and size from boot_args.
	ldr		r8, [r0, BA_PHYS_BASE]				// Get the phys base in r8
	ldr		r9, [r0, BA_VIRT_BASE]				// Get the virt base in r9
	ldr		r10, [r0, BA_MEM_SIZE]				// Get the mem size in r10

#define LOAD_PHYS_ADDR(reg, label) \
	LOAD_ADDR(reg, label); \
	sub		reg, reg, r9; \
	add		reg, reg, r8

	// Take this opportunity to patch the targets for the exception vectors
	LOAD_ADDR(r4, fleh_reset)
	LOAD_PHYS_ADDR(r5, ExceptionVectorsTable)
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_undef)
	add		r5, #4
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_swi)
	add		r5, #4
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_prefabt)
	add		r5, #4
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_dataabt)
	add		r5, #4
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_addrexc)
	add		r5, #4
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_irq)
	add		r5, #4
	str		r4, [r5]
	LOAD_ADDR(r4, fleh_decirq)
	add		r5, #4
	str		r4, [r5]

	// arm_init_tramp is sensitive, so for the moment, take the opportunity to store the
	// virtual address locally, so that we don't run into issues retrieving it later.
	// This is a pretty miserable solution, but it should be enough for the moment
	LOAD_ADDR(r4, arm_init_tramp)
	adr		r5, arm_init_tramp_addr
	str		r4, [r5]

#undef LOAD_PHYS_ADDR

	// Set the base of the translation table into the MMU
	ldr		r4, [r0, BA_TOP_OF_KERNEL_DATA]		// Get the top of kernel data
	orr		r5, r4, #(TTBR_SETUP & 0x00FF)		// Setup PTWs memory attribute
	orr		r5, r5, #(TTBR_SETUP & 0xFF00)		// Setup PTWs memory attribute
	mcr		p15, 0, r5, c2, c0, 0				// write kernel to translation table base 0
	mcr		p15, 0, r5, c2, c0, 1				// also to translation table base 1
	mov		r5, #TTBCR_N_SETUP					// identify the split between 0 and 1
	mcr		p15, 0, r5, c2, c0, 2				// and set up the translation control reg
		
	// Mark the entries invalid in the 4 page trampoline translation table
	// Mark the entries invalid in the 4 page CPU translation table
	// Mark the entries invalid in the one page table for the final 1MB (if used)
	// Mark the entries invalid in the one page table for HIGH_EXC_VECTORS
	mov		r5, r4								// local copy of base
	mov		r11, #ARM_TTE_TYPE_FAULT			// invalid entry template
	mov		r2, PGBYTES >> 2					// number of ttes/page
	add		r2, r2, r2, LSL #2					// 8 ttes + 2 ptes to clear. Multiply by 5...
	mov		r2, r2, LSL #1						// ...then multiply by 2
invalidate_tte:
	str		r11, [r5]							// store the invalid tte
	add		r5, r5, #4							// increment tte pointer
	subs	r2, r2, #1							// decrement count
	bne		invalidate_tte

	// create default section tte template
	mov		r6, #ARM_TTE_TYPE_BLOCK				// use block mapping entries
	mov		r7, #(ARM_TTE_BLOCK_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0xFF)
	orr		r7, r7, #(ARM_TTE_BLOCK_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0xFF00)
	orr		r7, r7, #(ARM_TTE_BLOCK_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0xF0000)
	orr		r6, r6, r7							// with default cache attrs
	mov		r7, #ARM_TTE_BLOCK_AP(AP_RWNA)		// Set kernel rw, user no access
	orr		r7, r7, #(ARM_TTE_BLOCK_AP(AP_RWNA) & 0xFF00)
	orr		r7, r7, #(ARM_TTE_BLOCK_AP(AP_RWNA) & 0xF0000)
	orr		r6, r6, r7							// Set RWNA protection 

	orr		r6, r6, #ARM_TTE_BLOCK_AF			// Set access protection 
	orr		r6, r6, #ARM_TTE_BLOCK_SH			// Set shareability

	// Set up the V=P mapping for the 1 MB section around the current pc
	lsr		r7, pc, #ARM_TT_L1_SHIFT			// Extract tte index for pc addr
	add		r5, r4, r7, LSL #2					// convert tte index to tte pointer
	lsl		r7, r7, #ARM_TT_L1_SHIFT			// Truncate pc to 1MB aligned addr
	orr		r11, r7, r6							// make tte entry value
	str		r11, [r5]							// store tte

	// Set up the virtual mapping for the kernel using 1Mb direct section TTE entries
	mov		r7, r8								// Save original phys base
	add		r5, r4, r9, LSR #ARM_TT_L1_SHIFT-2	// convert vaddr to tte pointer
	mov		r3, #ARM_TT_L1_SIZE					// set 1MB boundary
	
mapveqp:
	cmp		r3, r10								// Check if we're beyond the last 1MB section
	bgt		mapveqpL2							// If so, a coarse entry is required

	orr		r11, r7, r6							// make tte entry value
	str		r11, [r5], #4						// store tte and move to next
	add		r7, r7, #ARM_TT_L1_SIZE				// move to next phys addr
	subs	r10, r10, #ARM_TT_L1_SIZE			// subtract tte size
	bne		mapveqp
	b		doneveqp							// end is 1MB aligned, and we're done
	
mapveqpL2:
	// The end is not 1MB aligned, so steal a page and set up L2 entries within
	
	// Coarse entry first
	add		r6, r4, PGBYTES * 8					// add L2 offset
	mov 		r11, r6
	
	orr		r6, #ARM_TTE_TYPE_TABLE				// coarse entry
	
	str		r6, [r5]							// store coarse tte entry	
	
	// Fill in the L2 entries
	mov 		r5, r11
	
	// create pte template
	mov		r2, #ARM_PTE_TYPE					// default pte type
	orr		r2, r2, #(ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0xff)	// with default cache attrs
	orr		r2, r2, #(ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0xff00)
	orr		r2, r2, #(ARM_PTE_AP(AP_RWNA) & 0xff)	// with default cache attrs
	orr		r2, r2, #(ARM_PTE_AP(AP_RWNA) & 0xff00)
	orr		r2, r2, #ARM_PTE_AF					// Set access 
	orr		r2, r2, #ARM_PTE_SH					// Set shareability 
	
storepte:
	orr		r11, r7, r2							// make pte entry value
	str		r11, [r5], #4						// store pte and move to next
	add		r7, r7,  PGBYTES					// move to next phys addr
	subs	r10, r10, PGBYTES					// subtract pte size
	bne		storepte

doneveqp:
	// Insert page table page for high address exception vectors into translation table
	mov		r5, #0xff000000						// part of virt HIGH_EXC_VECTORS (HACK!)
	orr		r5, r5, #0x00ff0000					// rest of virt HIGH_EXC_VECTORS (HACK!)
	mov		r5, r5, LSR #ARM_TT_L1_SHIFT		// convert virt addr to index
	add		r5, r4, r5, LSL #2					// convert to tte pointer

	add		r6, r4, PGBYTES * 9					// get page table base (past 4 + 4 + 1 tte/pte pages)
	add		r6, r6, #0xc00						// adjust to last 1MB section
	mov		r7, #(ARM_TTE_TABLE_MASK & 0xFFFF) 	// ARM_TTE_TABLE_MASK low halfword
	movt		r7, #(ARM_TTE_TABLE_MASK >> 16)		// ARM_TTE_TABLE_MASK top halfword 
	and		r11, r6, r7							// apply mask
	orr		r11, r11, #ARM_TTE_TYPE_TABLE		// mark it as a coarse page table
	str		r11, [r5]							// store tte entry for page table

	// create pte template
	mov		r2, #ARM_PTE_TYPE					// pte type
	orr		r2, r2, #(ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0x00ff)	// default cache attrs
	orr		r2, r2, #(ARM_PTE_ATTRINDX(CACHE_ATTRINDX_DEFAULT) & 0xff00)
	orr		r2, r2, #(ARM_PTE_AP(AP_RWNA) & 0x00ff)	// set  RWNA protection
	orr		r2, r2, #(ARM_PTE_AP(AP_RWNA) & 0xff00)
	orr		r2, r2, #ARM_PTE_AF					// Set access 
	orr		r2, r2, #ARM_PTE_SH					// Set shareability 

	// Now initialize the page table entry for the exception vectors
	mov		r5, #0xff000000						// part of HIGH_EXC_VECTORS
	orr		r5, r5, #0x00ff0000					// rest of HIGH_EXC_VECTORS
	mov		r7, #(ARM_TT_L2_INDEX_MASK & 0xFFFF) // ARM_TT_L2_INDEX_MASK low halfword
	movt	r7, #(ARM_TT_L2_INDEX_MASK >> 16)	// ARM_TT_L2_INDEX_MASK top halfword 
	and		r5, r5, r7 							// mask for getting index 
	mov		r5, r5, LSR #ARM_TT_L2_SHIFT		// get page table index
	add		r5, r6, r5, LSL #2					// convert to pte pointer

	LOAD_ADDR(r11, ExceptionVectorsBase)		// get address of vectors addr
	sub		r11, r11, r9						// convert to physical address
	add		r11, r11, r8

	mov		r7, #(ARM_PTE_PAGE_MASK & 0xFFFF) 	// ARM_PTE_PAGE_MASK low halfword
	movt	r7, #(ARM_PTE_PAGE_MASK >> 16)		// ARM_PTE_PAGE_MASK top halfword 
	and		r11, r11, r7						// insert masked address into pte
	orr		r11, r11, r2						// add template bits
	str		r11, [r5]							// store pte by base and index

	// clean the dcache
	mov		r11, #0
cleanflushway:
cleanflushline:		
	mcr		p15, 0, r11, c7, c14, 2				 // cleanflush dcache line by way/set
	add		r11, r11, #1 << MMU_I7SET			 // increment set index
	tst		r11, #1 << (MMU_NSET + MMU_I7SET)	 // look for overflow
	beq		cleanflushline
	bic		r11, r11, #1 << (MMU_NSET + MMU_I7SET) // clear set overflow
	adds	r11, r11, #1 << MMU_I7WAY			 // increment way
	bcc		cleanflushway				 		 // loop

#if	__ARM_L2CACHE__
	// Invalidate L2 cache
	mov		r11, #2
invall2flushway:
invall2flushline:		
	mcr		p15, 0, r11, c7, c14, 2				 // Invalidate dcache line by way/set
	add		r11, r11, #1 << L2_I7SET			 // increment set index
	tst		r11, #1 << (L2_NSET + L2_I7SET)		 // look for overflow
	beq		invall2flushline
	bic		r11, r11, #1 << (L2_NSET + L2_I7SET) // clear set overflow
	adds	r11, r11, #1 << L2_I7WAY			 // increment way
	bcc		invall2flushway				 		 // loop

#endif

	mov		r11, #0
	mcr		p15, 0, r11, c13, c0, 3				// Write TPIDRURO
	LOAD_ADDR(sp, intstack_top)					// Get interrupt stack top
	sub		sp, sp, SS_SIZE						// Set stack pointer
	sub		r0, r0, r8							// Convert to virtual address
	add		r0, r0, r9

join_start:
	// kernel page table is setup
	// lr set to return handler function virtual address
	// r0 set to return handler argument virtual address
	// sp set to interrupt context stack virtual address

	// Cpu specific configuration

#ifdef  ARMA7
#if	 __ARMA7_SMP__
	mrc		p15, 0, r11, c1, c0, 1
	orr		r11, r11, #(1<<6)						// SMP
	mcr		p15, 0, r11, c1, c0, 1
	isb
#endif
#endif

	mrs		r11, cpsr							// Get cpsr
	bic		r11, #0x100							// Allow async aborts
	msr		cpsr_x, r11							// Update cpsr

	mov		r11, #0
	mcr		p15, 0, r11, c8, c7, 0				// invalidate all TLB entries
	mcr		p15, 0, r11, c7, c5, 0				// invalidate the icache

	// set DACR
	mov		r11, #(ARM_DAC_SETUP & 0xFFFF) 		// ARM_DAC_SETUP low halfword
	movt	r11, #(ARM_DAC_SETUP >> 16)			// ARM_DAC_SETUP top halfword 
	mcr		p15, 0, r11, c3, c0, 0				// write to dac register

	// Set PRRR
	mov		r11, #(PRRR_SETUP & 0xFFFF) 		// PRRR_SETUP low halfword
	movt	r11, #(PRRR_SETUP >> 16)			// PRRR_SETUP top halfword 
	mcr		p15, 0, r11, c10,c2,0				// write to PRRR register

	// Set NMRR
	mov		r11, #(NMRR_SETUP & 0xFFFF)			// NMRR_SETUP low halfword
	movt	r11, #(NMRR_SETUP >> 16)			// NMRR_SETUP top halfword 
	mcr		p15, 0, r11, c10,c2,1				// write to NMRR register

	// set SCTLR
	mrc		p15, 0, r11, c1, c0, 0				// read  system control

	bic		r11, r11, #SCTLR_ALIGN				// force off alignment exceptions
	mov		r7, #(SCTLR_AFE|SCTLR_TRE)			// Access flag, TEX remap
	orr		r7, r7, #(SCTLR_HIGHVEC | SCTLR_ICACHE | SCTLR_PREDIC)
	orr		r7, r7, #(SCTLR_DCACHE | SCTLR_ENABLE)
#if  (__ARM_ENABLE_SWAP__ == 1)
	orr		r7, r7, #SCTLR_SW					// SWP/SWPB Enable
#endif
	orr		r11, r11, r7						// or in the default settings
	mcr		p15, 0, r11, c1, c0, 0				// set mmu control

	dsb											// ensure mmu settings are inplace
	isb											// before moving on

#if __ARM_VFP__
	// Initialize the VFP coprocessors.
	mrc		p15, 0, r2, c1, c0, 2				// read coprocessor control register
	mov		r3, #15								// 0xF
	orr		r2, r2, r3, LSL #20					// enable 10 and 11
	mcr		p15, 0, r2, c1, c0, 2				// write coprocessor control register
	isb
#endif	/* __ARM_VFP__ */
		
	// Running virtual.  Prepare to call init code
	cmp		r1, #0								// Test if invoked from start
	beq		join_start_1						// Branch if yes
	ldr		r7, arm_init_tramp_addr				// Load trampoline address
	bx		r7									// Branch to virtual trampoline address

	// Loading the virtual address for arm_init_tramp is a rather ugly
	// problem.  There is probably a better solution, but for the moment,
	// patch the address in locally so that loading it is trivial
arm_init_tramp_addr:
	.long	0
	.globl EXT(arm_init_tramp)
LEXT(arm_init_tramp)
	mrc		p15, 0, r5, c2, c0, 0				// Read to translation table base 0
	add		r5, r5, PGBYTES * 4 				// get kernel page table base (past 4 boot tte pages)
	mcr		p15, 0, r5, c2, c0, 0				// write kernel to translation table base 0
	mcr		p15, 0, r5, c2, c0, 1				// also to translation table base 1
	isb
	mov		r5, #0
	mcr		p15, 0, r5, c8, c7, 0				// Flush all TLB entries
	dsb											// ensure mmu settings are inplace
	isb											// before moving on

join_start_1:
#if __ARM_VFP__
	// Enable VFP for the bootstrap thread context.
	// VFP is enabled for the arm_init path as we may
	// execute VFP code before we can handle an undef.
	fmrx	r2, fpexc							// get fpexc
	orr		r2, #FPEXC_EN						// set the enable bit
	fmxr	fpexc, r2							// set fpexc
	mov		r2, #FPSCR_DEFAULT					// set default fpscr
	fmxr	fpscr, r2							// set fpscr
#endif	/* __ARM_VFP__ */

	mov		r7, #0								// Set stack frame 0
	bx		lr

LOAD_ADDR_GEN_DEF(arm_init)
LOAD_ADDR_GEN_DEF(arm_init_cpu)
LOAD_ADDR_GEN_DEF(arm_init_idle_cpu)
LOAD_ADDR_GEN_DEF(arm_init_tramp)
LOAD_ADDR_GEN_DEF(fleh_reset)
LOAD_ADDR_GEN_DEF(ExceptionVectorsTable)
LOAD_ADDR_GEN_DEF(fleh_undef)
LOAD_ADDR_GEN_DEF(fleh_swi)
LOAD_ADDR_GEN_DEF(fleh_prefabt)
LOAD_ADDR_GEN_DEF(fleh_dataabt)
LOAD_ADDR_GEN_DEF(fleh_addrexc)
LOAD_ADDR_GEN_DEF(fleh_irq)
LOAD_ADDR_GEN_DEF(fleh_decirq)

#include "globals_asm.h"

/* vim: set ts=4: */
