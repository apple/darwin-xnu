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

#ifndef _CHUD_CPU_ASM_H_
#define _CHUD_CPU_ASM_H_

void chudxnu_mfsrr0_64(uint64_t *val);
void chudxnu_mfsrr1_64(uint64_t *val);
void chudxnu_mfdar_64(uint64_t *val);
void chudxnu_mfsdr1_64(uint64_t *val);
void chudxnu_mfsprg0_64(uint64_t *val);
void chudxnu_mfsprg1_64(uint64_t *val);
void chudxnu_mfsprg2_64(uint64_t *val);
void chudxnu_mfsprg3_64(uint64_t *val);
void chudxnu_mfasr_64(uint64_t *val);
void chudxnu_mfdabr_64(uint64_t *val);
void chudxnu_mfhid0_64(uint64_t *val);
void chudxnu_mfhid1_64(uint64_t *val);
void chudxnu_mfhid4_64(uint64_t *val);
void chudxnu_mfhid5_64(uint64_t *val);
void chudxnu_mfmmcr0_64(uint64_t *val);
void chudxnu_mfmmcr1_64(uint64_t *val);
void chudxnu_mfmmcra_64(uint64_t *val);
void chudxnu_mfsiar_64(uint64_t *val);
void chudxnu_mfsdar_64(uint64_t *val);
void chudxnu_mfimc_64(uint64_t *val);
void chudxnu_mfrmor_64(uint64_t *val);
void chudxnu_mfhrmor_64(uint64_t *val);
void chudxnu_mfhior_64(uint64_t *val);
void chudxnu_mflpidr_64(uint64_t *val);
void chudxnu_mflpcr_64(uint64_t *val);
void chudxnu_mfdabrx_64(uint64_t *val);
void chudxnu_mfhsprg0_64(uint64_t *val);
void chudxnu_mfhsprg1_64(uint64_t *val);
void chudxnu_mfhsrr0_64(uint64_t *val);
void chudxnu_mfhsrr1_64(uint64_t *val);
void chudxnu_mfhdec_64(uint64_t *val);
void chudxnu_mftrig0_64(uint64_t *val);
void chudxnu_mftrig1_64(uint64_t *val);
void chudxnu_mftrig2_64(uint64_t *val);
void chudxnu_mfaccr_64(uint64_t *val);
void chudxnu_mfscomc_64(uint64_t *val);
void chudxnu_mfscomd_64(uint64_t *val);
void chudxnu_mfmsr_64(uint64_t *val);            

void chudxnu_mtsrr0_64(uint64_t *val);
void chudxnu_mtsrr1_64(uint64_t *val);
void chudxnu_mtdar_64(uint64_t *val);
void chudxnu_mtsdr1_64(uint64_t *val);
void chudxnu_mtsprg0_64(uint64_t *val);
void chudxnu_mtsprg1_64(uint64_t *val);
void chudxnu_mtsprg2_64(uint64_t *val);
void chudxnu_mtsprg3_64(uint64_t *val);
void chudxnu_mtasr_64(uint64_t *val);
void chudxnu_mtdabr_64(uint64_t *val);
void chudxnu_mthid0_64(uint64_t *val);
void chudxnu_mthid1_64(uint64_t *val);
void chudxnu_mthid4_64(uint64_t *val);
void chudxnu_mthid5_64(uint64_t *val);
void chudxnu_mtmmcr0_64(uint64_t *val);
void chudxnu_mtmmcr1_64(uint64_t *val);
void chudxnu_mtmmcra_64(uint64_t *val);
void chudxnu_mtsiar_64(uint64_t *val);
void chudxnu_mtsdar_64(uint64_t *val);
void chudxnu_mtimc_64(uint64_t *val);
void chudxnu_mtrmor_64(uint64_t *val);
void chudxnu_mthrmor_64(uint64_t *val);
void chudxnu_mthior_64(uint64_t *val);
void chudxnu_mtlpidr_64(uint64_t *val);
void chudxnu_mtlpcr_64(uint64_t *val);
void chudxnu_mtdabrx_64(uint64_t *val);
void chudxnu_mthsprg0_64(uint64_t *val);
void chudxnu_mthsprg1_64(uint64_t *val);
void chudxnu_mthsrr0_64(uint64_t *val);
void chudxnu_mthsrr1_64(uint64_t *val);
void chudxnu_mthdec_64(uint64_t *val);
void chudxnu_mttrig0_64(uint64_t *val);
void chudxnu_mttrig1_64(uint64_t *val);
void chudxnu_mttrig2_64(uint64_t *val);
void chudxnu_mtaccr_64(uint64_t *val);
void chudxnu_mtscomc_64(uint64_t *val);
void chudxnu_mtscomd_64(uint64_t *val);
void chudxnu_mtmsr_64(uint64_t *val);

#endif // _CHUD_CPU_ASM_H_
