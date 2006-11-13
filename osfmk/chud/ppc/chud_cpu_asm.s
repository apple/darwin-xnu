/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 
#define ASSEMBLER
#include <chud/ppc/chud_spr.h>
#include <ppc/asm.h>
#include <mach/kern_return.h>

/*
 * kern_return_t mfspr64(uint64_t *val, int spr);
 * 
 * r3: address to store value in
 * r4: spr to read from
 *
 */
 
;           Force a line boundry here
            .align  5
            .globl  EXT(mfspr64)

EXT(mfspr64):
            ;; generic PPC 64-bit wide SPRs
            cmpwi	r4,chud_ppc_srr0
            beq		mfspr64_srr0
            cmpwi	r4,chud_ppc_srr1
            beq		mfspr64_srr1
            cmpwi	r4,chud_ppc_dar
            beq		mfspr64_dar
            cmpwi	r4,chud_ppc_sdr1
            beq		mfspr64_sdr1
            cmpwi	r4,chud_ppc_sprg0
            beq		mfspr64_sprg0       
            cmpwi	r4,chud_ppc_sprg1
            beq		mfspr64_sprg1  
            cmpwi	r4,chud_ppc_sprg2
            beq		mfspr64_sprg2  
            cmpwi	r4,chud_ppc_sprg3
            beq		mfspr64_sprg3
            cmpwi	r4,chud_ppc64_asr
            beq		mfspr64_asr
            cmpwi	r4,chud_ppc_dabr
            beq		mfspr64_dabr
            
            ;; GPUL specific 64-bit wide SPRs
            cmpwi	r4,chud_970_hid0
            beq		mfspr64_hid0
            cmpwi	r4,chud_970_hid1
            beq		mfspr64_hid1
            cmpwi	r4,chud_970_hid4
            beq		mfspr64_hid4
            cmpwi	r4,chud_970_hid5
            beq		mfspr64_hid5       
            cmpwi	r4,chud_970_mmcr0
            beq		mfspr64_mmcr0            
            cmpwi	r4,chud_970_mmcr1
            beq		mfspr64_mmcr1
            cmpwi	r4,chud_970_mmcra
            beq		mfspr64_mmcra
            cmpwi	r4,chud_970_siar
            beq		mfspr64_siar
            cmpwi	r4,chud_970_sdar
            beq		mfspr64_sdar
            cmpwi	r4,chud_970_imc
            beq		mfspr64_imc
            cmpwi	r4,chud_970_rmor
            beq		mfspr64_rmor
            cmpwi	r4,chud_970_hrmor
            beq		mfspr64_hrmor
            cmpwi	r4,chud_970_hior
            beq		mfspr64_hior
            cmpwi	r4,chud_970_lpidr
            beq		mfspr64_lpidr
            cmpwi	r4,chud_970_lpcr
            beq		mfspr64_lpcr
            cmpwi	r4,chud_970_dabrx
            beq		mfspr64_dabrx
            cmpwi	r4,chud_970_hsprg0
            beq		mfspr64_hsprg0
            cmpwi	r4,chud_970_hsprg1
            beq		mfspr64_hsprg1
            cmpwi	r4,chud_970_hsrr0
            beq		mfspr64_hsrr0
            cmpwi	r4,chud_970_hsrr1
            beq		mfspr64_hsrr1
            cmpwi	r4,chud_970_hdec
            beq		mfspr64_hdec
            cmpwi	r4,chud_970_trig0
            beq		mfspr64_trig0
            cmpwi	r4,chud_970_trig1
            beq		mfspr64_trig1
            cmpwi	r4,chud_970_trig2
            beq		mfspr64_trig2
            cmpwi	r4,chud_ppc64_accr
            beq		mfspr64_accr
            cmpwi	r4,chud_970_scomc
            beq		mfspr64_scomc
            cmpwi	r4,chud_970_scomd
            beq		mfspr64_scomd
                                                                                                                                                            
            b		mfspr64_failure
            
mfspr64_srr0:
            mfspr	r5,chud_ppc_srr0
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_srr1:
            mfspr	r5,chud_ppc_srr1
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_dar:
            mfspr	r5,chud_ppc_dar
            std		r5,0(r3)
            b		mfspr64_success          
mfspr64_sdr1:
            mfspr	r5,chud_ppc_sdr1
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_sprg0:
            mfspr	r5,chud_ppc_sprg0
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_sprg1:
            mfspr	r5,chud_ppc_sprg1
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_sprg2:
            mfspr	r5,chud_ppc_sprg2
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_sprg3:
            mfspr	r5,chud_ppc_sprg3
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_asr:
            mfspr	r5,chud_ppc64_asr
            std		r5,0(r3)
            b		mfspr64_success             
mfspr64_dabr:
            mfspr	r5,chud_ppc_dabr
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_hid0:
            mfspr	r5,chud_970_hid0
            std		r5,0(r3)
            b		mfspr64_success            
mfspr64_hid1:
            mfspr	r5,chud_970_hid1
            std		r5,0(r3)
            b		mfspr64_success     
mfspr64_hid4:
            mfspr	r5,chud_970_hid4
            std		r5,0(r3)
            b		mfspr64_success             
mfspr64_hid5:
            mfspr	r5,chud_970_hid5
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_mmcr0:
            mfspr	r5,chud_970_mmcr0
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_mmcr1:
            mfspr	r5,chud_970_mmcr1
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_mmcra:
            mfspr	r5,chud_970_mmcra
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_siar:
            mfspr	r5,chud_970_siar
            std		r5,0(r3)
            b		mfspr64_success            
mfspr64_sdar:
            mfspr	r5,chud_970_sdar
            std		r5,0(r3)
            b		mfspr64_success              
mfspr64_imc:
            mfspr	r5,chud_970_imc
            std		r5,0(r3)
            b		mfspr64_success                          
mfspr64_rmor:
            mfspr	r5,chud_970_rmor
            std		r5,0(r3)
            b		mfspr64_success              
mfspr64_hrmor:
            mfspr	r5,chud_970_hrmor
            std		r5,0(r3)
            b		mfspr64_success  
mfspr64_hior:
            mfspr	r5,chud_970_hior
            std		r5,0(r3)
            b		mfspr64_success  
mfspr64_lpidr:
            mfspr	r5,chud_970_lpidr
            std		r5,0(r3)
            b		mfspr64_success   
mfspr64_lpcr:
            mfspr	r5,chud_970_lpcr
            std		r5,0(r3)
            b		mfspr64_success  
mfspr64_dabrx:
            mfspr	r5,chud_970_dabrx
            std		r5,0(r3)
            b		mfspr64_success  
mfspr64_hsprg0:
            mfspr	r5,chud_970_hsprg0
            std		r5,0(r3)
            b		mfspr64_success   
mfspr64_hsprg1:
            mfspr	r5,chud_970_hsprg1
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_hsrr0:
            mfspr	r5,chud_970_hsrr0
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_hsrr1:
            mfspr	r5,chud_970_hsrr1
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_hdec:
            mfspr	r5,chud_970_hdec
            std		r5,0(r3)
            b		mfspr64_success             
mfspr64_trig0:
            mfspr	r5,chud_970_trig0
            std		r5,0(r3)
            b		mfspr64_success 
mfspr64_trig1:
            mfspr	r5,chud_970_trig1
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_trig2:
            mfspr	r5,chud_970_trig2
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_accr:
            mfspr	r5,chud_ppc64_accr
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_scomc:
            mfspr	r5,chud_970_scomc
            std		r5,0(r3)
            b		mfspr64_success
mfspr64_scomd:
            mfspr	r5,chud_970_scomd
            std		r5,0(r3)
            b		mfspr64_success
            
mfspr64_failure:
            li		r3,KERN_FAILURE
            blr
            
mfspr64_success:
            li		r3,KERN_SUCCESS
            blr


/*
 * kern_return_t mtspr64(int spr, uint64_t *val);
 * 
 * r3: spr to write to
 * r4: address to get value from
 *
 */
 
;           Force a line boundry here
            .align  5
            .globl  EXT(mtspr64)

EXT(mtspr64):
            ;; generic PPC 64-bit wide SPRs
            cmpwi	r3,chud_ppc_srr0
            beq		mtspr64_srr0
            cmpwi	r3,chud_ppc_srr1
            beq		mtspr64_srr1
            cmpwi	r3,chud_ppc_dar
            beq		mtspr64_dar
            cmpwi	r3,chud_ppc_sdr1
            beq		mtspr64_sdr1
            cmpwi	r3,chud_ppc_sprg0
            beq		mtspr64_sprg0       
            cmpwi	r3,chud_ppc_sprg1
            beq		mtspr64_sprg1  
            cmpwi	r3,chud_ppc_sprg2
            beq		mtspr64_sprg2  
            cmpwi	r3,chud_ppc_sprg3
            beq		mtspr64_sprg3
            cmpwi	r3,chud_ppc64_asr
            beq		mtspr64_asr
            cmpwi	r3,chud_ppc_dabr
            beq		mtspr64_dabr
            
            ;; GPUL specific 64-bit wide SPRs
            cmpwi	r3,chud_970_hid0
            beq		mtspr64_hid0
            cmpwi	r3,chud_970_hid1
            beq		mtspr64_hid1
            cmpwi	r3,chud_970_hid4
            beq		mtspr64_hid4
            cmpwi	r3,chud_970_hid5
            beq		mtspr64_hid5       
            cmpwi	r3,chud_970_mmcr0
            beq		mtspr64_mmcr0            
            cmpwi	r3,chud_970_mmcr1
            beq		mtspr64_mmcr1
            cmpwi	r3,chud_970_mmcra
            beq		mtspr64_mmcra
            cmpwi	r3,chud_970_siar
            beq		mtspr64_siar
            cmpwi	r3,chud_970_sdar
            beq		mtspr64_sdar
            cmpwi	r3,chud_970_imc
            beq		mtspr64_imc
            cmpwi	r3,chud_970_rmor
            beq		mtspr64_rmor
            cmpwi	r3,chud_970_hrmor
            beq		mtspr64_hrmor
            cmpwi	r3,chud_970_hior
            beq		mtspr64_hior
            cmpwi	r3,chud_970_lpidr
            beq		mtspr64_lpidr
            cmpwi	r3,chud_970_lpcr
            beq		mtspr64_lpcr
            cmpwi	r3,chud_970_dabrx
            beq		mtspr64_dabrx       
            cmpwi	r3,chud_970_hsprg0
            beq		mtspr64_hsprg0
            cmpwi	r3,chud_970_hsprg1
            beq		mtspr64_hsprg1
            cmpwi	r3,chud_970_hsrr0
            beq		mtspr64_hsrr0
            cmpwi	r3,chud_970_hsrr1
            beq		mtspr64_hsrr1
            cmpwi	r3,chud_970_hdec
            beq		mtspr64_hdec
            cmpwi	r3,chud_970_trig0
            beq		mtspr64_trig0
            cmpwi	r3,chud_970_trig1
            beq		mtspr64_trig1
            cmpwi	r3,chud_970_trig2
            beq		mtspr64_trig2
            cmpwi	r3,chud_ppc64_accr
            beq		mtspr64_accr
            cmpwi	r3,chud_970_scomc
            beq		mtspr64_scomc
            cmpwi	r3,chud_970_scomd
            beq		mtspr64_scomd
                                                                                                                                                            
            b		mtspr64_failure
            
mtspr64_srr0:
            ld		r5,0(r4)
            mtspr	chud_ppc_srr0,r5
            b		mtspr64_success
mtspr64_srr1:
            ld		r5,0(r4)
            mtspr	chud_ppc_srr1,r5
            b		mtspr64_success
mtspr64_dar:
            ld		r5,0(r4)
            mtspr	chud_ppc_dar,r5
            b		mtspr64_success          
mtspr64_sdr1:
            ld		r5,0(r4)
            mtspr	chud_ppc_sdr1,r5
            b		mtspr64_success 
mtspr64_sprg0:
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg0,r5
            b		mtspr64_success
mtspr64_sprg1:
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg1,r5
            b		mtspr64_success 
mtspr64_sprg2:
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg2,r5
            b		mtspr64_success 
mtspr64_sprg3:
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg3,r5
            b		mtspr64_success 
mtspr64_asr:
            ld		r5,0(r4)
            mtspr	chud_ppc64_asr,r5
            b		mtspr64_success             
mtspr64_dabr:
            ld		r5,0(r4)
            mtspr	chud_ppc_dabr,r5
            b		mtspr64_success 
mtspr64_hid0:
            ld		r5,0(r4)
            sync
            mtspr	chud_970_hid0,r5
            mfspr	r5,chud_970_hid0	/* syncronization requirements */
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            b		mtspr64_success            
mtspr64_hid1:
            ld		r5,0(r4)
            mtspr	chud_970_hid1,r5	/* tell you twice */
            mtspr	chud_970_hid1,r5
            isync
            b		mtspr64_success     
mtspr64_hid4:
            ld		r5,0(r4)
            sync				/* syncronization requirements */
            mtspr	chud_970_hid4,r5
            isync
            b		mtspr64_success             
mtspr64_hid5:
            ld		r5,0(r4)
            mtspr	chud_970_hid5,r5
            b		mtspr64_success
mtspr64_mmcr0:
            ld		r5,0(r4)
            mtspr	chud_970_mmcr0,r5
            b		mtspr64_success
mtspr64_mmcr1:
            ld		r5,0(r4)
            mtspr	chud_970_mmcr1,r5
            b		mtspr64_success
mtspr64_mmcra:
            ld		r5,0(r4)
            mtspr	chud_970_mmcra,r5
            b		mtspr64_success
mtspr64_siar:
            ld		r5,0(r4)
            mtspr	chud_970_siar,r5
            b		mtspr64_success            
mtspr64_sdar:
            ld		r5,0(r4)
            mtspr	chud_970_sdar,r5
            b		mtspr64_success              
mtspr64_imc:
            ld		r5,0(r4)
            mtspr	chud_970_imc,r5
            b		mtspr64_success                          
mtspr64_rmor:
            ld		r5,0(r4)
            mtspr	chud_970_rmor,r5
            b		mtspr64_success              
mtspr64_hrmor:
            ld		r5,0(r4)
            mtspr	chud_970_hrmor,r5
            b		mtspr64_success  
mtspr64_hior:
            ld		r5,0(r4)
            mtspr	chud_970_hior,r5
            b		mtspr64_success  
mtspr64_lpidr:
            ld		r5,0(r4)
            mtspr	chud_970_lpidr,r5
            b		mtspr64_success   
mtspr64_lpcr:
            ld		r5,0(r4)
            mtspr	chud_970_lpcr,r5
            b		mtspr64_success    
mtspr64_dabrx:
            ld		r5,0(r4)
            mtspr	chud_970_dabrx,r5
            b		mtspr64_success    
mtspr64_hsprg0:
            ld		r5,0(r4)
            mtspr	chud_970_hsprg0,r5
            b		mtspr64_success   
mtspr64_hsprg1:
            ld		r5,0(r4)
            mtspr	chud_970_hsprg1,r5
            b		mtspr64_success 
mtspr64_hsrr0:
            ld		r5,0(r4)
            mtspr	chud_970_hsrr0,r5
            b		mtspr64_success 
mtspr64_hsrr1:
            ld		r5,0(r4)
            mtspr	chud_970_hsrr1,r5
            b		mtspr64_success 
mtspr64_hdec:
            ld		r5,0(r4)
            mtspr	chud_970_hdec,r5
            b		mtspr64_success             
mtspr64_trig0:
            ld		r5,0(r4)
            mtspr	chud_970_trig0,r5
            b		mtspr64_success 
mtspr64_trig1:
            ld		r5,0(r4)
            mtspr	chud_970_trig1,r5
            b		mtspr64_success
mtspr64_trig2:
            ld		r5,0(r4)
            mtspr	chud_970_trig2,r5
            b		mtspr64_success
mtspr64_accr:
            ld		r5,0(r4)
            mtspr	chud_ppc64_accr,r5
            b		mtspr64_success
mtspr64_scomc:
            ld		r5,0(r4)
            mtspr	chud_970_scomc,r5
            b		mtspr64_success
mtspr64_scomd:
            ld		r5,0(r4)
            mtspr	chud_970_scomd,r5
            b		mtspr64_success
            
mtspr64_failure:
            li		r3,KERN_FAILURE
            blr
            
mtspr64_success:
            li		r3,KERN_SUCCESS
            blr


/*
 * kern_return_t mfmsr64(uint64_t *val);
 * 
 * r3: address to store value in
 *
 */
 
;           Force a line boundry here
            .align  5
            .globl  EXT(mfmsr64)

EXT(mfmsr64):            
            mfmsr	r5
            std		r5,0(r3)
mfmsr64_success:
            li		r3,KERN_SUCCESS
            blr

mfmsr64_failure:
            li		r3,KERN_FAILURE
            blr


/*
 * kern_return_t mtmsr64(uint64_t *val);
 * 
 * r3: address to load value from
 *
 */
 
;           Force a line boundry here
            .align  5
            .globl  EXT(mtmsr64)

EXT(mtmsr64):            
            ld		r5,0(r3)
            mtmsrd	r5
            b		mtmsr64_success
            
mtmsr64_success:
            li		r3,KERN_SUCCESS
            blr

mtmsr64_failure:
            li		r3,KERN_FAILURE
            blr

.L_end:
