/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

/* Emulate64.s
 *
 * Software emulation of instructions not handled in hw, on 64-bit machines.
 */
 
#include <sys/appleapiopts.h>
#include <ppc/asm.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <mach/machine/vm_param.h>
#include <ppc/cpu_capabilities.h>
#include <assym.s>

// CR bit set if the instruction is an "update" form (LFDU, STWU, etc):
#define	kUpdate	25

// CR bit set if interrupt occured in trace mode (ie, MSR_SE_BIT):
#define kTrace	8

// CR bit set if notification on alignment interrupts is requested (notifyUnalignbit in spcFlags):
#define	kNotify	9

// CR bit distinguishes between alignment and program exceptions:
#define	kAlignment	10



// *************************************
// * P R O G R A M   I N T E R R U P T *
// *************************************
//
// These are floating pt exceptions, illegal instructions, privileged mode violations,
// and traps.  All we're interested in at this low level is illegal instructions.
// The ones we "emulate" are:
//		DCBA,  which is not implemented in the IBM 970.  The emulation is to ignore it,
//			   as it is just a hint.
//		MCRXR, which is not implemented on the IBM 970, but is in the PPC ISA.
//
// Additionally, to facilitate debugging the alignment handler, we recognize a special
// diagnostic mode that is used to simulate alignment exceptions.  When in this mode,
// if the instruction has opcode==0 and the extended opcode is one of the X-form
// instructions that can take an alignment interrupt, then we change the opcode to
// 31 and pretend it got an alignment interrupt.  This exercises paths that
// are hard to drive or perhaps never driven on this particular CPU.

        .text
        .globl	EXT(Emulate64)
        .align	5
LEXT(Emulate64)
        crclr	kAlignment						// not an alignment exception
        b		a64AlignAssistJoin				// join alignment handler
        
        
// Return from alignment handler with all the regs loaded for opcode emulation.
        
a64HandleProgramInt:
        rlwinm.	r0,r29,0,SRR1_PRG_ILL_INS_BIT,SRR1_PRG_ILL_INS_BIT	// illegal opcode?
        beq		a64PassAlong					// No, must have been trap or priv violation etc
        rlwinm	r3,r20,6,26,31					// right justify opcode field (bits 0-5)
        rlwinm	r4,r20,31,22,31					// right justify extended opcode field (bits 21-30)
        cmpwi	cr0,r3,31						// X-form?
        cmpwi	cr1,r4,758						// DCBA?
        cmpwi	cr4,r4,512						// MCRXR?
        crand	cr1_eq,cr0_eq,cr1_eq			// merge the two tests for DCBA
        crand	cr4_eq,cr0_eq,cr4_eq			// and for MCRXR
        beq++	cr1_eq,a64ExitEm				// was DCBA, so ignore
        bne--	cr4_eq,a64NotEmulated			// skip if not MCRXR
        
// Was MCRXR, so emulate.

        ld		r3,savexer(r13)					// get the XER
        lwz		r4,savecr(r13)					// and the CR
        rlwinm	r5,r20,11,27,29					// get (CR# * 4) from instruction
        rlwinm	r6,r3,0,4,31					// zero XER[32-35] (also XER[0-31])
        sld		r4,r4,r5						// move target CR field to bits 32-35
        rlwimi	r4,r3,0,0,3						// move XER[32-35] into CR field
        stw		r6,savexer+4(r13)				// update XER
        srd		r4,r4,r5						// re-position CR
        stw		r4,savecr(r13)					// update CR
        b		a64ExitEm						// done

// Not an opcode we normally emulate.  If in special diagnostic mode and opcode=0,
// emulate as an alignment exception.  This special case is for test software.

a64NotEmulated:
        lwz		r30,dgFlags(0)					// Get the flags
        rlwinm.	r0,r30,0,enaDiagEMb,enaDiagEMb	// Do we want to try to emulate something?
        beq++	a64PassAlong					// No emulation allowed
        cmpwi	r3,0							// opcode==0 ?
        bne		a64PassAlong					// not the special case
        oris	r20,r20,0x7C00					// change opcode to 31
        crset	kAlignment						// say we took alignment exception
        rlwinm	r5,r4,0,26+1,26-1				// mask Update bit (32) out of extended opcode
        rlwinm	r5,r5,0,0,31					// Clean out leftover junk from rlwinm

        cmpwi	r4,1014							// dcbz/dcbz128 ?
        crmove	cr1_eq,cr0_eq
        cmpwi	r5,21							// ldx/ldux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,599							// lfdx/lfdux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,535							// lfsx/lfsux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,343							// lhax/lhaux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,790							// lhbrx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,279							// lhzx/lhzux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,597							// lswi ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,533							// lswx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,341							// lwax/lwaux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,534							// lwbrx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,23							// lwz/lwzx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,149							// stdx/stdux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,727							// stfdx/stfdux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,983							// stfiwx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,663							// stfsx/stfsux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,918							// sthbrx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,407							// sthx/sthux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,725							// stswi ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,661							// stswx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r4,662							// stwbrx ?
        cror	cr1_eq,cr0_eq,cr1_eq
        cmpwi	r5,151							// stwx/stwux ?
        cror	cr1_eq,cr0_eq,cr1_eq
        
        beq++	cr1,a64GotInstruction			// it was one of the X-forms we handle
        crclr	kAlignment						// revert to program interrupt
        b		a64PassAlong					// not recognized extended opcode
        

// *****************************************
// * A L I G N M E N T   I N T E R R U P T *
// *****************************************
//
// We get here in exception context, ie with interrupts disabled, translation off, and
// in 64-bit mode, with:
//		r13 = save-area pointer, with general context already saved in it
//		cr6 = feature flags
// We preserve r13 and cr6.  Other GPRs and CRs, the LR and CTR are used.
//
// Current 64-bit processors (GPUL) handle almost all misaligned operations in hardware,
// so this routine usually isn't called very often.  Only floating pt ops that cross a page
// boundary and are not word aligned, and LMW/STMW can take exceptions to cacheable memory.
// However, in contrast to G3 and G4, any misaligned load/store will get an alignment
// interrupt on uncached memory.
//
// We always emulate scalar ops with a series of byte load/stores.  Doing so is no slower
// than LWZ/STW in cases where a scalar op gets an alignment exception.
//
// This routine supports all legal permutations of alignment interrupts occuring in user or
// supervisor mode, 32 or 64-bit addressing, and translation on or off.  We do not emulate
// instructions that go past the end of an address space, such as "LHZ -1(0)"; we just pass
// along the alignment exception rather than wrap around to byte 0.
//
// First, check for a few special cases such as virtual machines, etc.

        .globl	EXT(AlignAssist64)
        .align	5
LEXT(AlignAssist64)
        crset	kAlignment								// mark as alignment interrupt

a64AlignAssistJoin:										// join here from program interrupt handler
      	li		r0,0									// Get a 0
        mfsprg	r31,0									// get the per_proc data ptr
        mcrf	cr3,cr6									// save feature flags here...
        lwz		r21,spcFlags(r31)						// grab the special flags
        ld		r29,savesrr1(r13)						// get the MSR etc at the fault
        ld		r28,savesrr0(r13)						// get the EA of faulting instruction
       	stw		r0,savemisc3(r13)						// Assume we will handle this ok
        mfmsr	r26										// save MSR at entry
        rlwinm.	r0,r21,0,runningVMbit,runningVMbit		// Are we running a VM?
        lwz		r19,dgFlags(0)							// Get the diagnostics flags
        bne--	a64PassAlong							// yes, let the virtual machine monitor handle


// Set up the MSR shadow regs.  We turn on FP in this routine, and usually set DR and RI
// when accessing user space (the SLB is still set up with all the user space translations.)
// However, if the interrupt occured in the kernel with DR off, we keep it off while
// accessing the "target" address space.  If we set DR to access the target space, we also
// set RI.  The RI bit tells the exception handlers to clear cr0 beq and return if we get an
// exception accessing the user address space.  We are careful to test cr0 beq after every such
// access.  We keep the following "shadows" of the MSR in global regs across this code:
//		r25 = MSR at entry, plus FP and probably DR and RI (used to access target space)
//		r26 = MSR at entry
//		r27 = free
//		r29 = SRR1 (ie, MSR at interrupt)
// Note that EE and IR are always off, and SF is always on in this code.

		rlwinm	r3,r29,0,MSR_DR_BIT,MSR_DR_BIT			// was translation on at fault?
        rlwimi	r3,r3,32-MSR_RI_BIT+MSR_DR_BIT,MSR_RI_BIT,MSR_RI_BIT	// if DR was set, set RI too
        or		r25,r26,r3								// assemble MSR to use accessing target space
        

// Because the DSISR and DAR are either not set or are not to be trusted on some 64-bit
// processors on an alignment interrupt, we must fetch the faulting instruction ourselves,
// then decode/hash the opcode and reconstruct the EA manually.

        mtmsr	r25					// turn on FP and (if it was on at fault) DR and RI
        isync						// wait for it to happen
		cmpw	r0,r0				// turn on beq so we can check for DSIs
        lwz		r20,0(r28)			// fetch faulting instruction, probably with DR on
        bne--	a64RedriveAsISI		// got a DSI trying to fetch it, pretend it was an ISI
        mtmsr	r26					// turn DR back off
        isync						// wait for it to happen


// Set a few flags while we wait for the faulting instruction to arrive from cache.

        rlwinm.	r0,r29,0,MSR_SE_BIT,MSR_SE_BIT				// Were we single stepping?
		stw		r20,savemisc2(r13)	// Save the instruction image in case we notify
        crnot	kTrace,cr0_eq
        rlwinm.	r0,r19,0,enaNotifyEMb,enaNotifyEMb			// Should we notify?
        crnot	kNotify,cr0_eq        


// Hash the intruction into a 5-bit value "AAAAB" used to index the branch table, and a
// 1-bit kUpdate flag, as follows:
//  ¥ for X-form instructions (with primary opcode 31):
//       the "AAAA" bits are bits 21-24 of the instruction
//       the "B" bit is the XOR of bits 29 and 30
//       the update bit is instruction bit 25
//	¥ for D and DS-form instructions (actually, any primary opcode except 31):
//       the "AAAA" bits are bits 1-4 of the instruction
//       the "B" bit is 0
//       the update bit is instruction bit 5
//
// Just for fun (and perhaps a little speed on deep-pipe machines), we compute the hash,
// update flag, and EA without branches and with ipc >= 2.
//
// When we "bctr" to the opcode-specific reoutine, the following are all set up:
//		MSR = EE and IR off, SF and FP on
//		r12 = full 64-bit EA (r17 is clamped EA)
//		r13 = save-area pointer (physical)
//		r14 = ptr to saver0 in save-area (ie, to base of GPRs)
//		r15 = 0x00000000FFFFFFFF if 32-bit mode fault, 0xFFFFFFFFFFFFFFFF if 64
//		r16 = RA * 8 (ie, reg# not reg value)
//		r17 = EA, clamped to 32 bits if 32-bit mode fault (see also r12)
//		r18 = (RA|0) (reg value)
//		r19 = -1 if X-form, 0 if D-form
//		r20 = faulting instruction
//		r21 = RT * 8 (ie, reg# not reg value)
//		r22 = addr(aaFPopTable)+(RT*32), ie ptr to floating pt table for target register
//		r25 = MSR at entrance, probably with DR and RI set (for access to target space)
//		r26 = MSR at entrance
//		r27 = free
//		r28 = SRR0 (ie, EA of faulting instruction)
//		r29 = SRR1 (ie, MSR at fault)
//		r30 = scratch, usually user data
//		r31 = per-proc pointer
//		cr2 = kTrace, kNotify, and kAlignment flags
//      cr3 = saved copy of feature flags used in lowmem vector code
//		cr6 = bits 24-27 of CR are bits 24-27 of opcode if X-form, or bits 4-5 and 00 if D-form
//			  bit 25 is the kUpdate flag, set for update form instructions
//		cr7 = bits 28-31 of CR are bits 28-31 of opcode if X-form, or 0 if D-form

a64GotInstruction:					// here from program interrupt with instruction in r20
        rlwinm	r21,r20,6+6,20,25	// move the primary opcode (bits 0-6) to bits 20-25
        la		r14,saver0(r13)		// r14 <- base address of GPR registers
        xori	r19,r21,0x07C0		// iff primary opcode is 31, set r19 to 0
        rlwinm	r16,r20,16+3,24,28	// r16 <- RA*8
        subi	r19,r19,1			// set bit 0 iff X-form (ie, if primary opcode is 31)
        rlwinm	r17,r20,21+3,24,28	// r17 <- RB*8 (if X-form)
        sradi	r19,r19,63			// r19 <- -1 if X-form, 0 if D-form
        extsh	r22,r20				// r22 <- displacement (if D-form)

        ldx		r23,r14,r17			// get (RB), if any
        and		r15,r20,r19			// instruction if X, 0 if D
        andc	r17,r21,r19			// primary opcode in bits 20-25 if D, 0 if X
        ldx		r18,r14,r16			// get (RA)
        subi	r24,r16,1			// set bit 0 iff RA==0
        or		r21,r15,r17			// r21 <- instruction if X, or bits 0-5 in bits 20-25 if D
        sradi	r24,r24,63			// r24 <- -1 if RA==0, 0 otherwise
        rlwinm	r17,r21,32-4,25,28	// shift opcode bits 21-24 to 25-28 (hash "AAAA" bits)
        lis		r10,ha16(a64BranchTable)	// start to build up branch table address
        rlwimi	r17,r21,0,29,29		// move opcode bit 29 into hash as start of "B" bit
        rlwinm	r30,r21,1,29,29		// position opcode bit 30 in position 29
        and		r12,r23,r19			// RB if X-form, 0 if D-form
        andc	r11,r22,r19			// 0 if X-form, sign extended displacement if D-form
        xor		r17,r17,r30			// bit 29 ("B") of hash is xor(bit29,bit30)
        addi	r10,r10,lo16(a64BranchTable)
        or		r12,r12,r11			// r12 <- (RB) or displacement, as appropriate
        lwzx	r30,r10,r17			// get address from branch table
        mtcrf	0x01,r21			// move opcode bits 28-31 to CR7
        sradi	r15,r29,32			// propogate SF bit from SRR1 (MSR_SF, which is bit 0)
        andc	r18,r18,r24			// r18 <- (RA|0)
        mtcrf	0x02,r21			// move opcode bits 24-27 to CR6 (kUpdate is bit 25)
        add		r12,r18,r12			// r12 <- 64-bit EA
        mtctr	r30					// set up branch address
        
        oris	r15,r15,0xFFFF		// start to fill low word of r15 with 1s
        rlwinm	r21,r20,11+3,24,28	// r21 <- RT * 8
        lis		r22,ha16(EXT(aaFPopTable))	// start to compute address of floating pt table
        ori		r15,r15,0xFFFF		// now bits 32-63 of r15 are 1s
        addi	r22,r22,lo16(EXT(aaFPopTable))
        and		r17,r12,r15			// clamp EA to 32 bits if fault occured in 32-bit mode
        rlwimi	r22,r21,2,22,26		// move RT into aaFPopTable address (which is 1KB aligned)
        
        bf--	kAlignment,a64HandleProgramInt	// return to Program Interrupt handler
        bctr						// if alignment interrupt, jump to opcode-specific routine
        
        
// Floating-pt load single (lfs[u], lfsx[u])

a64LfsLfsx:
        bl		a64Load4Bytes		// get data in r30
        mtctr	r22					// set up address of "lfs fRT,emfp0(r31)"
        stw		r30,emfp0(r31)		// put word here for aaFPopTable routine
        bctrl						// do the lfs
        b		a64UpdateCheck		// update RA if necessary and exit
        
        
// Floating-pt store single (stfs[u], stfsx[u])

a64StfsStfsx:
        ori		r22,r22,8			// set dir==1 (ie, single store) in aaFPopTable
        mtctr	r22					// set up address of "stfs fRT,emfp0(r31)"
        bctrl						// execute the store into emfp0
        lwz		r30,emfp0(r31)		// get the word
        bl		a64Store4Bytes		// store r30 into user space
        b		a64UpdateCheck		// update RA if necessary and exit
        

// Floating-pt store as integer word (stfiwx)

a64Stfiwx:
        ori		r22,r22,16+8		// set size=1, dir==1 (ie, double store) in aaFPopTable
        mtctr	r22					// set up FP register table address
        bctrl						// double precision store into emfp0
        lwz		r30,emfp0+4(r31)	// get the low-order word
        bl		a64Store4Bytes		// store r30 into user space
        b		a64Exit				// successfully emulated
        

// Floating-pt load double (lfd[u], lfdx[u])

a64LfdLfdx:
        ori		r22,r22,16			// set Double bit in aaFPopTable address
        bl		a64Load8Bytes		// get data in r30
        mtctr	r22					// set up address of "lfd fRT,emfp0(r31)"
        std		r30,emfp0(r31)		// put doubleword here for aaFPopTable routine
        bctrl						// execute the load
        b		a64UpdateCheck		// update RA if necessary and exit


// Floating-pt store double (stfd[u], stfdx[u])

a64StfdStfdx:
        ori		r22,r22,16+8		// set size=1, dir==1 (ie, double store) in aaFPopTable address
        mtctr	r22					// address of routine to stfd RT
        bctrl						// store into emfp0
        ld		r30,emfp0(r31)		// get the doubleword
        bl		a64Store8Bytes		// store r30 into user space
        b		a64UpdateCheck		// update RA if necessary and exit


// Load halfword w 0-fill (lhz[u], lhzx[u])

a64LhzLhzx:
        bl		a64Load2Bytes		// load into r30 from user space (w 0-fill)
        stdx	r30,r14,r21			// store into RT slot in register file
        b		a64UpdateCheck		// update RA if necessary and exit


// Load halfword w sign fill (lha[u], lhax[u])

a64LhaLhax:
        bl		a64Load2Bytes		// load into r30 from user space (w 0-fill)
        extsh	r30,r30				// sign-extend
        stdx	r30,r14,r21			// store into RT slot in register file
        b		a64UpdateCheck		// update RA if necessary and exit


// Load halfword byte reversed (lhbrx)

a64Lhbrx:
        bl		a64Load2Bytes		// load into r30 from user space (w 0-fill)
        rlwinm	r3,r30,8,16,23		// reverse bytes into r3
        rlwimi	r3,r30,24,24,31
        stdx	r3,r14,r21			// store into RT slot in register file
        b		a64Exit				// successfully emulated


// Store halfword (sth[u], sthx[u])

a64SthSthx:
        ldx		r30,r14,r21			// get RT
        bl		a64Store2Bytes		// store r30 into user space
        b		a64UpdateCheck		// update RA if necessary and exit


// Store halfword byte reversed (sthbrx)

a64Sthbrx:
        addi	r21,r21,6			// point to low two bytes of RT
        lhbrx	r30,r14,r21			// load and reverse
        bl		a64Store2Bytes		// store r30 into user space
        b		a64Exit				// successfully emulated


// Load word w 0-fill (lwz[u], lwzx[u]), also lwarx.

a64LwzLwzxLwarx:
        andc	r3,r19,r20			// light bit 30 of r3 iff lwarx
        andi.	r0,r3,2				// is it lwarx?
        bne--	a64PassAlong		// yes, never try to emulate a lwarx
        bl		a64Load4Bytes		// load 4 bytes from user space into r30 (0-filled)
        stdx	r30,r14,r21			// update register file
        b		a64UpdateCheck		// update RA if necessary and exit
        
        
// Load word w sign fill (lwa, lwax[u])

a64Lwa:
        crclr	kUpdate				// no update form of lwa (its a reserved encoding)
a64Lwax:
        bl		a64Load4Bytes		// load 4 bytes from user space into r30 (0-filled)
        extsw	r30,r30				// sign extend
        stdx	r30,r14,r21			// update register file
        b		a64UpdateCheck		// update RA if necessary and exit


// Load word byte reversed (lwbrx)

a64Lwbrx:
        bl		a64Load4Bytes		// load 4 bytes from user space into r30 (0-filled)
        rlwinm	r3,r30,24,0,31		// flip bytes 1234 to 4123
        rlwimi	r3,r30,8,8,15		// r3 is now 4323
        rlwimi	r3,r30,8,24,31		// r3 is now 4321
        stdx	r3,r14,r21			// update register file
        b		a64Exit				// successfully emulated

        
// Store word (stw[u], stwx[u])

a64StwStwx:
        ldx		r30,r14,r21			// get RT
        bl		a64Store4Bytes		// store r30 into user space
        b		a64UpdateCheck		// update RA if necessary and exit


// Store word byte reversed (stwbrx)

a64Stwbrx:
        addi	r21,r21,4			// point to low word of RT
        lwbrx	r30,r14,r21			// load and reverse
        bl		a64Store4Bytes		// store r30 into user space
        b		a64Exit				// successfully emulated


// Load doubleword (ld[u], ldx[u]), also lwa.

a64LdLwa:							// these are DS form: ld=0, ldu=1, and lwa=2
        mtcrf	0x01,r20			// move DS field to cr7
        rlwinm	r3,r20,0,30,31		// must adjust EA by subtracting DS field
        sub		r12,r12,r3			// subtract from full 64-bit EA
        and		r17,r12,r15			// then re-clamp to 32 bits if necessary
        bt		30,a64Lwa			// handle lwa
        crmove	kUpdate,31			// if opcode bit 31 is set, it is ldu so set update flag
a64Ldx:
        bl		a64Load8Bytes		// load 8 bytes from user space into r30
        stdx	r30,r14,r21			// update register file
        b		a64UpdateCheck		// update RA if necessary and exit


// Store doubleword (stdx[u], std[u], stwcx)

a64StdxStwcx:
        bf--	30,a64PassAlong		// stwcx, so pass along alignment exception
        b		a64Stdx				// was stdx
a64StdStfiwx:						// if DS form: 0=std, 1=stdu, 2-3=undefined
        bt		30,a64Stfiwx		// handle stfiwx
        rlwinm	r3,r20,0,30,31		// must adjust EA by subtracting DS field
        mtcrf	0x01,r20			// move DS field to cr7
        sub		r12,r12,r3			// subtract from full 64-bit EA
        and		r17,r12,r15			// then re-clamp to 32 bits if necessary
        crmove	kUpdate,31			// if DS==1, then it is update form
a64Stdx:
        ldx		r30,r14,r21			// get RT
        bl		a64Store8Bytes		// store RT into user space
        b		a64UpdateCheck		// update RA if necessary and exit


// Dcbz and Dcbz128 (bit 10 distinguishes the two forms)

a64DcbzDcbz128:
        andis.	r0,r20,0x0020		// bit 10 set?
        li		r3,0				// get a 0 to store
        li		r0,4				// assume 32-bit version, store 8 bytes 4x
        rldicr	r17,r17,0,63-5		// 32-byte align EA
		li		r4,_COMM_PAGE_BASE_ADDRESS
        beq		a64DcbzSetup		// it was the 32-byte version
        rldicr	r17,r17,0,63-7		// zero low 7 bits of EA
        li		r0,16				// store 8 bytes 16x
a64DcbzSetup:
		sub		r4,r28,r4			// get instruction offset from start of commpage
        and		r4,r4,r15			// mask off high-order bits if 32-bit mode
		cmpldi  r4,_COMM_PAGE_AREA_USED // did fault occur in commpage area?
        bge		a64NotCommpage		// not in commpage
        rlwinm.	r4,r29,0,MSR_PR_BIT,MSR_PR_BIT	// did fault occur in user mode?
        beq--	a64NotCommpage		// do not zero cr7 if kernel got alignment exception
        lwz		r4,savecr(r13)		// if we take a dcbz{128} in the commpage...
        rlwinm	r4,r4,0,0,27		// ...clear user's cr7...
        stw		r4,savecr(r13)		// ...as a flag for commpage code
a64NotCommpage:
        mtctr	r0
        cmpw	r0,r0				// turn cr0 beq on so we can check for DSIs
        mtmsr	r25					// turn on DR and RI so we can address user space
        isync						// wait for it to happen
a64DcbzLoop:
        std		r3,0(r17)			// store into user space
        bne--	a64RedriveAsDSI
        addi	r17,r17,8
        bdnz	a64DcbzLoop
        
        mtmsr	r26					// restore MSR
        isync						// wait for it to happen
        b		a64Exit


// Load and store multiple (lmw, stmw), distinguished by bit 25

a64LmwStmw:
        subfic	r22,r21,32*8		// how many regs to load or store?
        srwi	r22,r22,1			// get bytes to load/store
        bf		25,a64LoadMultiple	// handle lmw
        b		a64StoreMultiple	// it was stmw
        
        
// Load string word immediate (lswi)

a64Lswi:
        rlwinm	r22,r20,21,27,31	// get #bytes in r22
        and		r17,r18,r15			// recompute EA as (RA|0), and clamp
        subi	r3,r22,1			// r22==0?
        rlwimi	r22,r3,6,26,26		// map count of 0 to 32
        b		a64LoadMultiple
        
        
// Store string word immediate (stswi)

a64Stswi:
        rlwinm	r22,r20,21,27,31	// get #bytes in r22
        and		r17,r18,r15			// recompute EA as (RA|0), and clamp
        subi	r3,r22,1			// r22==0?
        rlwimi	r22,r3,6,26,26		// map count of 0 to 32
        b		a64StoreMultiple
        
        
// Load string word indexed (lswx), also lwbrx

a64LswxLwbrx:
        bf		30,a64Lwbrx			// was lwbrx
        ld		r22,savexer(r13)	// get the xer
        rlwinm	r22,r22,0,25,31		// isolate the byte count
        b		a64LoadMultiple		// join common code
        
        
// Store string word indexed (stswx), also stwbrx

a64StswxStwbrx:
        bf		30,a64Stwbrx		// was stwbrx
        ld		r22,savexer(r13)	// get the xer
        rlwinm	r22,r22,0,25,31		// isolate the byte count
        b		a64StoreMultiple	// join common code


// Load multiple words.  This handles lmw, lswi, and lswx.

a64LoadMultiple:					// r22 = byte count, may be 0
        subic.	r3,r22,1			// get (#bytes-1)
        blt		a64Exit				// done if 0
        add		r4,r17,r3			// get EA of last operand byte
        and		r4,r4,r15			// clamp
        cmpld	r4,r17				// address space wrap?
        blt--	a64PassAlong		// pass along exception if so
        srwi.	r4,r22,2			// get # full words to load
        rlwinm	r22,r22,0,30,31		// r22 <- leftover byte count
        cmpwi	cr1,r22,0			// leftover bytes?
        beq		a64Lm3				// no words
        mtctr	r4					// set up word count
        cmpw	r0,r0				// set beq for DSI test
a64Lm2:
        mtmsr	r25					// turn on DR and RI
        isync						// wait for it to happen
        lbz		r3,0(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r4,1(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r5,2(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r6,3(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        rlwinm	r30,r3,24,0,7		// pack bytes into r30
        rldimi	r30,r4,16,40
        rldimi	r30,r5,8,48
        rldimi	r30,r6,0,56
        mtmsr	r26					// turn DR back off so we can store into register file
        isync
        addi	r17,r17,4			// bump EA
        stdx	r30,r14,r21			// pack into register file
        addi	r21,r21,8			// bump register file offset
        rlwinm	r21,r21,0,24,28		// wrap around to 0
        bdnz	a64Lm2
a64Lm3:								// cr1/r22 = leftover bytes (0-3), cr0 beq set
        beq		cr1,a64Exit			// no leftover bytes
        mtctr	r22
        mtmsr	r25					// turn on DR so we can access user space
        isync
        lbz		r3,0(r17)			// get 1st leftover byte
        bne--	a64RedriveAsDSI		// got a DSI
        rlwinm	r30,r3,24,0,7		// position in byte 4 of r30 (and clear rest of r30)
        bdz		a64Lm4				// only 1 byte leftover
        lbz		r3,1(r17)			// get 2nd byte
        bne--	a64RedriveAsDSI		// got a DSI
        rldimi	r30,r3,16,40		// insert into byte 5 of r30
        bdz		a64Lm4				// only 2 bytes leftover
        lbz		r3,2(r17)			// get 3rd byte
        bne--	a64RedriveAsDSI		// got a DSI
        rldimi	r30,r3,8,48			// insert into byte 6
a64Lm4:
        mtmsr	r26					// turn DR back off so we can store into register file
        isync
        stdx	r30,r14,r21			// pack partially-filled word into register file
        b		a64Exit


// Store multiple words.  This handles stmw, stswi, and stswx.

a64StoreMultiple:					// r22 = byte count, may be 0
        subic.	r3,r22,1			// get (#bytes-1)
        blt		a64Exit				// done if 0
        add		r4,r17,r3			// get EA of last operand byte
        and		r4,r4,r15			// clamp
        cmpld	r4,r17				// address space wrap?
        blt--	a64PassAlong		// pass along exception if so
        srwi.	r4,r22,2			// get # full words to load
        rlwinm	r22,r22,0,30,31		// r22 <- leftover byte count
        cmpwi	cr1,r22,0			// leftover bytes?
        beq		a64Sm3				// no words
        mtctr	r4					// set up word count
        cmpw	r0,r0				// turn on beq so we can check for DSIs
a64Sm2:
        ldx		r30,r14,r21			// get next register
        addi	r21,r21,8			// bump register file offset
        rlwinm	r21,r21,0,24,28		// wrap around to 0
        srwi	r3,r30,24			// shift the four bytes into position
        srwi	r4,r30,16
        srwi	r5,r30,8
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        stb		r3,0(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r4,1(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r5,2(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r30,3(r17)
        bne--	a64RedriveAsDSI		// got a DSI
        mtmsr	r26					// turn DR back off
        isync
        addi	r17,r17,4			// bump EA
        bdnz	a64Sm2
a64Sm3:								// r22 = 0-3, cr1 set on r22, cr0 beq set
        beq		cr1,a64Exit			// no leftover bytes
        ldx		r30,r14,r21			// get last register
        mtctr	r22
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
a64Sm4:
        rlwinm	r30,r30,8,0,31		// position next byte
        stb		r30,0(r17)			// pack into user space
        addi	r17,r17,1			// bump user space ptr
        bne--	a64RedriveAsDSI		// got a DSI
        bdnz	a64Sm4
        mtmsr	r26					// turn DR back off
        isync
        b		a64Exit


// Subroutines to load bytes from user space.

a64Load2Bytes:						// load 2 bytes right-justified into r30
        addi	r7,r17,1			// get EA of last byte
        and		r7,r7,r15			// clamp
        cmpld	r7,r17				// address wrap?
        blt--	a64PassAlong		// yes
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        sub.	r30,r30,r30			// 0-fill dest and set beq
        b		a64Load2			// jump into routine
a64Load4Bytes:						// load 4 bytes right-justified into r30 (ie, low order word)
        addi	r7,r17,3			// get EA of last byte
        and		r7,r7,r15			// clamp
        cmpld	r7,r17				// address wrap?
        blt--	a64PassAlong		// yes
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        sub.	r30,r30,r30			// 0-fill dest and set beq
        b		a64Load4			// jump into routine
a64Load8Bytes:						// load 8 bytes into r30
        addi	r7,r17,7			// get EA of last byte
        and		r7,r7,r15			// clamp
        cmpld	r7,r17				// address wrap?
        blt--	a64PassAlong		// yes
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        sub.	r30,r30,r30			// 0-fill dest and set beq
        lbz		r3,-7(r7)			// get byte 0
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r4,-6(r7)			// and byte 1, etc
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r5,-5(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r6,-4(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        rldimi	r30,r3,56,0			// position bytes in upper word
        rldimi	r30,r4,48,8
        rldimi	r30,r5,40,16
        rldimi	r30,r6,32,24
a64Load4:
        lbz		r3,-3(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r4,-2(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        rldimi	r30,r3,24,32		// insert bytes 4 and 5 into r30
        rldimi	r30,r4,16,40
a64Load2:
        lbz		r3,-1(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        lbz		r4,0(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        mtmsr	r26					// turn DR back off
        isync
        rldimi	r30,r3,8,48			// insert bytes 6 and 7 into r30
        rldimi	r30,r4,0,56
        blr
        
        
// Subroutines to store bytes into user space.

a64Store2Bytes:						// store bytes 6 and 7 of r30
        addi	r7,r17,1			// get EA of last byte
        and		r7,r7,r15			// clamp
        cmpld	r7,r17				// address wrap?
        blt--	a64PassAlong		// yes
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        cmpw	r0,r0				// set beq so we can check for DSI
        b		a64Store2			// jump into routine
a64Store4Bytes:						// store bytes 4-7 of r30 (ie, low order word)
        addi	r7,r17,3			// get EA of last byte
        and		r7,r7,r15			// clamp
        cmpld	r7,r17				// address wrap?
        blt--	a64PassAlong		// yes
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        cmpw	r0,r0				// set beq so we can check for DSI
        b		a64Store4			// jump into routine
a64Store8Bytes:						// r30 = bytes
        addi	r7,r17,7			// get EA of last byte
        and		r7,r7,r15			// clamp
        cmpld	r7,r17				// address wrap?
        blt--	a64PassAlong		// yes
        mtmsr	r25					// turn on DR so we can access user space
        isync						// wait for it to happen
        cmpw	r0,r0				// set beq so we can check for DSI
        rotldi	r3,r30,8			// shift byte 0 into position
        rotldi	r4,r30,16			// and byte 1
        rotldi	r5,r30,24			// and byte 2
        rotldi	r6,r30,32			// and byte 3
        stb		r3,-7(r7)			// store byte 0
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r4,-6(r7)			// and byte 1 etc...
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r5,-5(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r6,-4(r7)
        bne--	a64RedriveAsDSI		// got a DSI
a64Store4:
        rotldi	r3,r30,40			// shift byte 4 into position
        rotldi	r4,r30,48			// and byte 5
        stb		r3,-3(r7)
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r4,-2(r7)
        bne--	a64RedriveAsDSI		// got a DSI
a64Store2:
        rotldi	r3,r30,56			// shift byte 6 into position
        stb		r3,-1(r7)			// store byte 6
        bne--	a64RedriveAsDSI		// got a DSI
        stb		r30,0(r7)			// store byte 7, which is already positioned
        bne--	a64RedriveAsDSI		// got a DSI
        mtmsr	r26					// turn off DR
        isync
        blr
        
                
// Exit routines.

a64ExitEm:
		li		r30,T_EMULATE			// Change exception code to emulate
		stw		r30,saveexception(r13)	// Save it
		b		a64Exit					// Join standard exit routine...

a64PassAlong:							// unhandled exception, just pass it along
        li		r0,1					// Set that the alignment/program exception was not emulated
        crset	kNotify					// return T_ALIGNMENT or T_PROGRAM
		stw		r0,savemisc3(r13)		// Set that emulation was not done
        crclr	kTrace					// not a trace interrupt
        b		a64Exit1
a64UpdateCheck:							// successfully emulated, may be update form
        bf		kUpdate,a64Exit			// update?
        stdx	r12,r14,r16				// yes, store 64-bit EA into RA
a64Exit:								// instruction successfully emulated
        addi	r28,r28,4				// bump SRR0 past the emulated instruction
        li		r30,T_IN_VAIN			// eat the interrupt since we emulated it
        and		r28,r28,r15				// clamp to address space size (32 vs 64)
        std		r28,savesrr0(r13)		// save, so we return to next instruction
a64Exit1:
        bt--	kTrace,a64Trace			// were we in single-step at fault?
        bt--	kNotify,a64Notify		// should we say T_ALIGNMENT anyway?
a64Exit2:
        mcrf	cr6,cr3					// restore feature flags
        mr		r11,r30					// pass back exception code (T_IN_VAIN etc) in r11
        b		EXT(EmulExit)			// return to exception processing


// Notification requested: pass exception upstairs even though it might have been emulated.

a64Notify:
        li		r30,T_ALIGNMENT			// somebody wants to know about it (but don't redrive)
        bt		kAlignment,a64Exit2		// was an alignment exception
        li		r30,T_PROGRAM			// was an emulated instruction
        b		a64Exit2


// Emulate a trace interrupt after handling alignment interrupt.

a64Trace:
        lwz		r9,SAVflags(r13)		// get the save-area flags
        li		r30,T_TRACE
        oris	r9,r9,hi16(SAVredrive)	// Set the redrive bit
        stw		r30,saveexception(r13)	// Set the exception code
        stw		r9,SAVflags(r13)		// Set the flags
        b		a64Exit2				// Exit and do trace interrupt...


// Got a DSI accessing user space.  Redrive.  One way this can happen is if another
// processor removes a mapping while we are emulating.

a64RedriveAsISI:						// this DSI happened fetching the opcode (r1==DSISR  r4==DAR)
        mtmsr	r26						// turn DR back off
        isync							// wait for it to happen
        li		r30,T_INSTRUCTION_ACCESS
        rlwimi	r29,r1,0,0,4			// insert the fault type from DSI's DSISR
        std		r29,savesrr1(r13)		// update SRR1 to look like an ISI
        b		a64Redrive

a64RedriveAsDSI:						// r0==DAR  r1==DSISR
        mtmsr	r26						// turn DR back off
        isync							// wait for it to happen
        stw		r1,savedsisr(r13)		// Set the DSISR of failed access
        std		r0,savedar(r13)			// Set the address of the failed access
        li		r30,T_DATA_ACCESS		// Set failing data access code
a64Redrive:
        lwz		r9,SAVflags(r13)		// Pick up the flags
        stw		r30,saveexception(r13)	// Set the replacement code
        oris	r9,r9,hi16(SAVredrive)	// Set the redrive bit
        stw		r9,SAVflags(r13)		// Set redrive request
        crclr	kTrace					// don't take a trace interrupt
        crclr	kNotify					// don't pass alignment exception
        b		a64Exit2				// done
        

// This is the branch table, indexed by the "AAAAB" opcode hash.

a64BranchTable:
        .long	a64LwzLwzxLwarx		// 00000  lwz[u], lwzx[u], lwarx
        .long	a64Ldx				// 00001  ldx[u]
        .long	a64PassAlong		// 00010  ldarx 	(never emulate these)
        .long	a64PassAlong		// 00011
        .long	a64StwStwx			// 00100  stw[u], stwx[u]
        .long	a64StdxStwcx		// 00101  stdx[u], stwcx
        .long	a64PassAlong		// 00110
        .long	a64PassAlong		// 00111  stdcx		(never emulate these)
        .long	a64LhzLhzx			// 01000  lhz[u], lhzx[u]
        .long	a64PassAlong		// 01001
        .long	a64LhaLhax			// 01010  lha[u], lhax[u]
        .long	a64Lwax				// 01011  lwax[u]
        .long	a64SthSthx			// 01100  sth[u], sthx[u]
        .long	a64PassAlong		// 01101
        .long	a64LmwStmw			// 01110  lmw, stmw
        .long	a64PassAlong		// 01111
        .long	a64LfsLfsx			// 10000  lfs[u], lfsx[u]
        .long	a64LswxLwbrx		// 10001  lswx, lwbrx
        .long	a64LfdLfdx			// 10010  lfd[u], lfdx[u]
        .long	a64Lswi				// 10011  lswi
        .long	a64StfsStfsx		// 10100  stfs[u], stfsx[u]
        .long	a64StswxStwbrx		// 10101  stswx, stwbrx
        .long	a64StfdStfdx		// 10110  stfd[u], stfdx[u]
        .long	a64Stswi			// 10111  stswi
        .long	a64PassAlong		// 11000
        .long	a64Lhbrx			// 11001  lhbrx
        .long	a64LdLwa			// 11010  ld[u], lwa
        .long	a64PassAlong		// 11011
        .long	a64PassAlong		// 11100
        .long	a64Sthbrx			// 11101  sthbrx
        .long	a64StdStfiwx		// 11110  std[u], stfiwx
        .long	a64DcbzDcbz128		// 11111  dcbz, dcbz128


