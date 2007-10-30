/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
 
#ifndef _I386_VMX_CPU_H_
#define _I386_VMX_CPU_H_

#include <mach/machine/vm_types.h>
#include <mach/boolean.h>
#include <i386/vmx/vmx_asm.h>

/*
 * Physical CPU's VMX specifications
 *
 */
typedef struct vmx_specs {
	boolean_t	initialized;	/* the specs have already been read */
	boolean_t	vmx_present;	/* VMX feature available and enabled */
	uint32_t	vmcs_id;	/* VMCS revision identifier */
	uint8_t		vmcs_mem_type;	/* VMCS memory type, (see enum above) */
	uint16_t	vmcs_size;	/* VMCS region size in bytes */
	boolean_t	act_halt;	/* HLT activity state supported */
	boolean_t	act_shutdown;	/* shutdown activity state supported */
	boolean_t	act_SIPI;	/* wait-for-SIPI activity supported */
	boolean_t	act_CSTATE;	/* C-state activity state supported */
	uint8_t		cr3_targs;	/* CR3 target values supported */
	uint32_t	max_msrs;	/* max MSRs to load/store on VMX transition */
	uint32_t	mseg_id;	/* MSEG revision identifier for SMI */
	/*
	 * Allowed settings for these controls are specified by
	 * a pair of bitfields: 0-settings contain 0 bits
	 * corresponding to controls thay may be 0; 1-settings
	 * contain 1 bits corresponding to controls that may be 1.
	 */
	uint32_t	pin_exctls_0;	/* allowed 0s pin-based controls */
	uint32_t	pin_exctls_1;	/* allowed 1s pin-based controls */
	
	uint32_t	proc_exctls_0;	/* allowed 0s proc-based controls */
	uint32_t	proc_exctls_1;	/* allowed 1s proc-based controls */
	
	uint32_t	sec_exctls_0;	/* allowed 0s 2ndary proc-based ctrls */
	uint32_t	sec_exctls_1;	/* allowed 1s 2ndary proc-based ctrls */
	
	uint32_t	exit_ctls_0;	/* allowed 0s VM-exit controls */
	uint32_t	exit_ctls_1;	/* allowed 1s VM-exit controls */
	
	uint32_t	enter_ctls_0;	/* allowed 0s VM-entry controls */
	uint32_t	enter_ctls_1;	/* allowed 1s VM-entry controls */

	/*
	 * Fixed control register bits are specified by a pair of
	 * bitfields: 0-settings contain 0 bits corresponding to
	 * CR bits that may be 0; 1-settings contain 1 bits
	 * corresponding to CR bits that may be 1.
	 */
	uint32_t	cr0_fixed_0;	/* allowed 0-settings for CR0 */
	uint32_t	cr0_fixed_1;	/* allowed 1-settings for CR0 */
	
	uint32_t	cr4_fixed_0;	/* allowed 0-settings for CR4 */
	uint32_t	cr4_fixed_1;	/* allowed 1-settings for CR4 */
} vmx_specs_t;

typedef struct vmx_cpu {
	vmx_specs_t	specs;		/* this phys CPU's VMX specifications */
	void		*vmxon_region;	/* the logical address of the VMXON region page */
} vmx_cpu_t;

void vmx_get_specs(void);
void vmx_resume(void);
void vmx_suspend(void);

#endif	/* _I386_VMX_CPU_H_ */
