/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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
 
#define ASSEMBLER
#include <ppc/chud/chud_spr.h>
#include <ppc/asm.h>
#include <mach/kern_return.h>

			.text
            .align  5
            .globl  EXT(chudxnu_mfsrr0_64)
EXT(chudxnu_mfsrr0_64):
            mfspr	r5,chud_ppc_srr0
            std		r5,0(r3)
            blr
            
            .align  5
            .globl  EXT(chudxnu_mfsrr1_64)
EXT(chudxnu_mfsrr1_64):
            mfspr	r5,chud_ppc_srr1
            std		r5,0(r3)
            blr

            .align  5
            .globl  EXT(chudxnu_mfdar_64)
EXT(chudxnu_mfdar_64):
            mfspr	r5,chud_ppc_dar
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfsdr1_64)
EXT(chudxnu_mfsdr1_64):
            mfspr	r5,chud_ppc_sdr1
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfsprg0_64)
EXT(chudxnu_mfsprg0_64):
            mfspr	r5,chud_ppc_sprg0
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfsprg1_64)
EXT(chudxnu_mfsprg1_64):
            mfspr	r5,chud_ppc_sprg1
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfsprg2_64)
EXT(chudxnu_mfsprg2_64):
            mfspr	r5,chud_ppc_sprg2
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfsprg3_64)
EXT(chudxnu_mfsprg3_64):
            mfspr	r5,chud_ppc_sprg3
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfasr_64)
EXT(chudxnu_mfasr_64):
            mfspr	r5,chud_ppc64_asr
            std		r5,0(r3)
            blr             
                
            .align  5
            .globl  EXT(chudxnu_mfdabr_64)
EXT(chudxnu_mfdabr_64):
            mfspr	r5,chud_ppc_dabr
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfhid0_64)
EXT(chudxnu_mfhid0_64):
            mfspr	r5,chud_970_hid0
            std		r5,0(r3)
            blr            
                
            .align  5
            .globl  EXT(chudxnu_mfhid1_64)
EXT(chudxnu_mfhid1_64):
            mfspr	r5,chud_970_hid1
            std		r5,0(r3)
            blr     
                
            .align  5
            .globl  EXT(chudxnu_mfhid4_64)
EXT(chudxnu_mfhid4_64):
            mfspr	r5,chud_970_hid4
            std		r5,0(r3)
            blr             
                
            .align  5
            .globl  EXT(chudxnu_mfhid5_64)
EXT(chudxnu_mfhid5_64):
            mfspr	r5,chud_970_hid5
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfmmcr0_64)
EXT(chudxnu_mfmmcr0_64):
            mfspr	r5,chud_970_mmcr0
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfmmcr1_64)
EXT(chudxnu_mfmmcr1_64):
            mfspr	r5,chud_970_mmcr1
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfmmcra_64)
EXT(chudxnu_mfmmcra_64):
            mfspr	r5,chud_970_mmcra
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfsiar_64)
EXT(chudxnu_mfsiar_64):
            mfspr	r5,chud_970_siar
            std		r5,0(r3)
            blr            
                
            .align  5
            .globl  EXT(chudxnu_mfsdar_64)
EXT(chudxnu_mfsdar_64):
            mfspr	r5,chud_970_sdar
            std		r5,0(r3)
            blr              
                
            .align  5
            .globl  EXT(chudxnu_mfimc_64)
EXT(chudxnu_mfimc_64):
            mfspr	r5,chud_970_imc
            std		r5,0(r3)
            blr                          
                
            .align  5
            .globl  EXT(chudxnu_mfrmor_64)
EXT(chudxnu_mfrmor_64):
            mfspr	r5,chud_970_rmor
            std		r5,0(r3)
            blr              
                
            .align  5
            .globl  EXT(chudxnu_mfhrmor_64)
EXT(chudxnu_mfhrmor_64):
            mfspr	r5,chud_970_hrmor
            std		r5,0(r3)
            blr  
                
            .align  5
            .globl  EXT(chudxnu_mfhior_64)
EXT(chudxnu_mfhior_64):
            mfspr	r5,chud_970_hior
            std		r5,0(r3)
            blr  
                
            .align  5
            .globl  EXT(chudxnu_mflpidr_64)
EXT(chudxnu_mflpidr_64):
            mfspr	r5,chud_970_lpidr
            std		r5,0(r3)
            blr   
                
            .align  5
            .globl  EXT(chudxnu_mflpcr_64)
EXT(chudxnu_mflpcr_64):
            mfspr	r5,chud_970_lpcr
            std		r5,0(r3)
            blr   
                
            .align  5
            .globl  EXT(chudxnu_mfdabrx_64)
EXT(chudxnu_mfdabrx_64):
            mfspr	r5,chud_970_dabrx
            std		r5,0(r3)
            blr   
                
            .align  5
            .globl  EXT(chudxnu_mfhsprg0_64)
EXT(chudxnu_mfhsprg0_64):
            mfspr	r5,chud_970_hsprg0
            std		r5,0(r3)
            blr   
                
            .align  5
            .globl  EXT(chudxnu_mfhsprg1_64)
EXT(chudxnu_mfhsprg1_64):
            mfspr	r5,chud_970_hsprg1
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfhsrr0_64)
EXT(chudxnu_mfhsrr0_64):
            mfspr	r5,chud_970_hsrr0
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfhsrr1_64)
EXT(chudxnu_mfhsrr1_64):
            mfspr	r5,chud_970_hsrr1
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mfhdec_64)
EXT(chudxnu_mfhdec_64):
            mfspr	r5,chud_970_hdec
            std		r5,0(r3)
            blr             
                
            .align  5
            .globl  EXT(chudxnu_mftrig0_64)
EXT(chudxnu_mftrig0_64):
            mfspr	r5,chud_970_trig0
            std		r5,0(r3)
            blr 
                
            .align  5
            .globl  EXT(chudxnu_mftrig1_64)
EXT(chudxnu_mftrig1_64):
            mfspr	r5,chud_970_trig1
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mftrig2_64)
EXT(chudxnu_mftrig2_64):
            mfspr	r5,chud_970_trig2
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfaccr_64)
EXT(chudxnu_mfaccr_64):
            mfspr	r5,chud_ppc64_accr
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfscomc_64)
EXT(chudxnu_mfscomc_64):
            mfspr	r5,chud_970_scomc
            std		r5,0(r3)
            blr
                
            .align  5
            .globl  EXT(chudxnu_mfscomd_64)
EXT(chudxnu_mfscomd_64):
            mfspr	r5,chud_970_scomd
            std		r5,0(r3)
            blr
            
            .align  5
            .globl  EXT(chudxnu_mtsrr0_64)
EXT(chudxnu_mtsrr0_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_srr0,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtsrr1_64)
EXT(chudxnu_mtsrr1_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_srr1,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtdar_64)
EXT(chudxnu_mtdar_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_dar,r5
            blr          

            .align  5
            .globl  EXT(chudxnu_mtsdr1_64)
EXT(chudxnu_mtsdr1_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_sdr1,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mtsprg0_64)
EXT(chudxnu_mtsprg0_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg0,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtsprg1_64)
EXT(chudxnu_mtsprg1_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg1,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mtsprg2_64)
EXT(chudxnu_mtsprg2_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg2,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mtsprg3_64)
EXT(chudxnu_mtsprg3_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_sprg3,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mtasr_64)
EXT(chudxnu_mtasr_64):
            ld		r5,0(r4)
            mtspr	chud_ppc64_asr,r5
            blr             

            .align  5
            .globl  EXT(chudxnu_mtdabr_64)
EXT(chudxnu_mtdabr_64):
            ld		r5,0(r4)
            mtspr	chud_ppc_dabr,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mthid0_64)
EXT(chudxnu_mthid0_64):
            ld		r5,0(r4)
            sync
            mtspr	chud_970_hid0,r5
            mfspr	r5,chud_970_hid0	/* syncronization requirements */
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            mfspr	r5,chud_970_hid0
            blr            

            .align  5
            .globl  EXT(chudxnu_mthid1_64)
EXT(chudxnu_mthid1_64):
            ld		r5,0(r4)
            mtspr	chud_970_hid1,r5	/* tell you twice */
            mtspr	chud_970_hid1,r5
            isync
            blr     

            .align  5
            .globl  EXT(chudxnu_mthid4_64)
EXT(chudxnu_mthid4_64):
            ld		r5,0(r4)
            sync				/* syncronization requirements */
            mtspr	chud_970_hid4,r5
            isync
            blr             

            .align  5
            .globl  EXT(chudxnu_mthid5_64)
EXT(chudxnu_mthid5_64):
            ld		r5,0(r4)
            mtspr	chud_970_hid5,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtmmcr0_64)
EXT(chudxnu_mtmmcr0_64):
            ld		r5,0(r4)
            mtspr	chud_970_mmcr0,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtmmcr1_64)
EXT(chudxnu_mtmmcr1_64):
            ld		r5,0(r4)
            mtspr	chud_970_mmcr1,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtmmcra_64)
EXT(chudxnu_mtmmcra_64):
            ld		r5,0(r4)
            mtspr	chud_970_mmcra,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtsiar_64)
EXT(chudxnu_mtsiar_64):
            ld		r5,0(r4)
            mtspr	chud_970_siar,r5
            blr            

            .align  5
            .globl  EXT(chudxnu_mtsdar_64)
EXT(chudxnu_mtsdar_64):
            ld		r5,0(r4)
            mtspr	chud_970_sdar,r5
            blr              

            .align  5
            .globl  EXT(chudxnu_mtimc_64)
EXT(chudxnu_mtimc_64):
            ld		r5,0(r4)
            mtspr	chud_970_imc,r5
            blr                          

            .align  5
            .globl  EXT(chudxnu_mtrmor_64)
EXT(chudxnu_mtrmor_64):
            ld		r5,0(r4)
            mtspr	chud_970_rmor,r5
            blr              

            .align  5
            .globl  EXT(chudxnu_mthrmor_64)
EXT(chudxnu_mthrmor_64):
            ld		r5,0(r4)
            mtspr	chud_970_hrmor,r5
            blr  

            .align  5
            .globl  EXT(chudxnu_mthior_64)
EXT(chudxnu_mthior_64):
            ld		r5,0(r4)
            mtspr	chud_970_hior,r5
            blr  

            .align  5
            .globl  EXT(chudxnu_mtlpidr_64)
EXT(chudxnu_mtlpidr_64):
            ld		r5,0(r4)
            mtspr	chud_970_lpidr,r5
            blr   

            .align  5
            .globl  EXT(chudxnu_mtlpcr_64)
EXT(chudxnu_mtlpcr_64):
            ld		r5,0(r4)
            mtspr	chud_970_lpcr,r5
            blr    

            .align  5
            .globl  EXT(chudxnu_mtdabrx_64)
EXT(chudxnu_mtdabrx_64):
            ld		r5,0(r4)
            mtspr	chud_970_lpcr,r5
            blr  

            .align  5
            .globl  EXT(chudxnu_mthsprg0_64)
EXT(chudxnu_mthsprg0_64):
            ld		r5,0(r4)
            mtspr	chud_970_hsprg0,r5
            blr   

            .align  5
            .globl  EXT(chudxnu_mthsprg1_64)
EXT(chudxnu_mthsprg1_64):
            ld		r5,0(r4)
            mtspr	chud_970_hsprg1,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mthsrr0_64)
EXT(chudxnu_mthsrr0_64):
            ld		r5,0(r4)
            mtspr	chud_970_hsrr0,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mthsrr1_64)
EXT(chudxnu_mthsrr1_64):
            ld		r5,0(r4)
            mtspr	chud_970_hsrr1,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mthdec_64)
EXT(chudxnu_mthdec_64):
            ld		r5,0(r4)
            mtspr	chud_970_hdec,r5
            blr             

            .align  5
            .globl  EXT(chudxnu_mttrig0_64)
EXT(chudxnu_mttrig0_64):
            ld		r5,0(r4)
            mtspr	chud_970_trig0,r5
            blr 

            .align  5
            .globl  EXT(chudxnu_mttrig1_64)
EXT(chudxnu_mttrig1_64):
            ld		r5,0(r4)
            mtspr	chud_970_trig1,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mttrig2_64)
EXT(chudxnu_mttrig2_64):
            ld		r5,0(r4)
            mtspr	chud_970_trig2,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtaccr_64)
EXT(chudxnu_mtaccr_64):
            ld		r5,0(r4)
            mtspr	chud_ppc64_accr,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtscomc_64)
EXT(chudxnu_mtscomc_64):
            ld		r5,0(r4)
            mtspr	chud_970_scomc,r5
            blr

            .align  5
            .globl  EXT(chudxnu_mtscomd_64)
EXT(chudxnu_mtscomd_64):
            ld		r5,0(r4)
            mtspr	chud_970_scomd,r5
            
            .align  5
            .globl  EXT(chudxnu_mfmsr_64)
EXT(chudxnu_mfmsr_64):            
            mfmsr	r5
            std		r5,0(r3)
            blr

            .align  5
            .globl  EXT(chudxnu_mtmsr_64)
EXT(chudxnu_mtmsr_64):            
            ld		r5,0(r3)
            mtmsrd	r5
            blr

.L_end:
