/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#include <mach_kdp.h>
#include <mach/vm_param.h>
#include <arm/lowglobals.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

extern vm_offset_t vm_kernel_stext;
extern void	*version;
extern void	*kmod;
extern void	*kdp_trans_off;
extern void	*osversion;
extern void	*flag_kdp_trigger_reboot;
extern void	*manual_pkt;
extern struct vm_object pmap_object_store;	/* store pt pages */

lowglo lowGlo __attribute__ ((aligned(PAGE_MAX_SIZE))) = {
	.lgVerCode = { 'O','c','t','o','p','u','s',' ' },
	// Increment the major version for changes that break the current Astris
	// usage of lowGlo values
	// Increment the minor version for changes that provide additonal info/function
	// but does not break current usage
	.lgLayoutMajorVersion = 3,
	.lgLayoutMinorVersion = 0,
	.lgLayoutMagic = LOWGLO_LAYOUT_MAGIC,
	.lgVersion = (uint32_t)&version,
	.lgKmodptr = (uint32_t)&kmod,
	.lgPageShift = PAGE_SHIFT,
#if MACH_KDP
	.lgTransOff = (uint32_t)&kdp_trans_off,
#endif
	.lgOSVersion = (uint32_t)&osversion,
#if MACH_KDP && CONFIG_KDP_INTERACTIVE_DEBUGGING
	.lgRebootFlag	= (uint32_t)&flag_kdp_trigger_reboot,
	.lgManualPktAddr = (uint32_t)&manual_pkt,
#endif
	.lgPmapMemQ = (uint32_t)&(pmap_object_store.memq),
	.lgPmapMemPageOffset = offsetof(struct vm_page_with_ppnum, vmp_phys_page),
	.lgPmapMemChainOffset = offsetof(struct vm_page, vmp_listq),
	.lgPmapMemPagesize = (uint32_t)sizeof(struct vm_page),

	.lgPmapMemStartAddr = -1,
	.lgPmapMemEndAddr = -1,
	.lgPmapMemFirstppnum = -1
};

void patch_low_glo(void)
{
	lowGlo.lgStext = (uint32_t)vm_kernel_stext;
}

void patch_low_glo_static_region(uint32_t address, uint32_t size)
{
	lowGlo.lgStaticAddr = address;
	lowGlo.lgStaticSize = size;
}


void patch_low_glo_vm_page_info(void * start_addr, void * end_addr, uint32_t first_ppnum)
{
	lowGlo.lgPmapMemStartAddr = (uint32_t)start_addr;
	lowGlo.lgPmapMemEndAddr = (uint32_t)end_addr;
	lowGlo.lgPmapMemFirstppnum = first_ppnum;
}
