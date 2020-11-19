/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
/**
 * ARM64 specific definitions for hibernation platform abstraction layer.
 */

#ifndef _ARM64_PAL_HIBERNATE_H
#define _ARM64_PAL_HIBERNATE_H

#include <IOKit/IOHibernatePrivate.h>

__BEGIN_DECLS

/*!
 * @enum        pal_hib_map_type_t
 * @discussion  Parameter to pal_hib_map used to signify which memory region to map.
 */
typedef enum {
	DEST_COPY_AREA = 1,
	COPY_PAGE_AREA,
	BITMAP_AREA,
	IMAGE_AREA,
	IMAGE2_AREA,
	SCRATCH_AREA,
	WKDM_AREA,
} pal_hib_map_type_t;

/*!
 * @struct      pal_hib_ctx
 * @discussion  ARM64-specific PAL context; see pal_hib_ctx_t for details.
 */
struct pal_hib_ctx {
#if HIBERNATE_HMAC_IMAGE
	struct ccdigest_info di;
	hibernate_scratch_t pagesRestored;
#endif /* HIBERNATE_HMAC_IMAGE */
};

/*!
 * @typedef      pal_hib_globals_t
 * @discussion  ARM64-specific state preserved pre-hibernation and needed during hibernation resume.
 *
 * @field       dockChannelRegBase   Physical address of the dockchannel registers
 * @field       dockChannelWstatMask Mask to apply to dockchannel WSTAT register to compute available FIFO entries
 * @field       hibUartRegBase       Physical address of the UART registers
 * @field       hmacRegBase          Physical address of the hmac block registers
 */
typedef struct {
	uint64_t dockChannelRegBase;
	uint64_t dockChannelWstatMask;
	uint64_t hibUartRegBase;
	uint64_t hmacRegBase;
} pal_hib_globals_t;
extern pal_hib_globals_t gHibernateGlobals;

/*!
 * @function    pal_hib_get_stack_pages
 * @discussion  Returns the stack base address and number of pages to use during hibernation resume.
 *
 * @param       first_page      Out parameter: the base address of the hibernation resume stack
 * @param       page_count      Out parameter: the number of pages in the hibernation stack
 */
void pal_hib_get_stack_pages(vm_offset_t *first_page, vm_offset_t *page_count);

/*!
 * @function    pal_hib_resume_tramp
 * @discussion  Platform-specific system setup before calling hibernate_kernel_entrypoint.
 *
 * @param       headerPpnum     The page number of the IOHibernateImageHeader
 */
void pal_hib_resume_tramp(uint32_t headerPpnum);

/*!
 * @typedef      pal_hib_tramp_result_t
 * @discussion  This type is used to store the result of pal_hib_resume_tramp.
 *
 * @field       ttbr0               Physical address of the first level translation table (low mem)
 * @field       ttbr1               Physical address of the first level translation table (high mem)
 * @field       memSlide            Offset from physical address to virtual address during hibernation resume
 * @field       kernelSlide         Offset from physical address to virtual address in the kernel map
 */
typedef struct{
	uint64_t ttbr0;
	uint64_t ttbr1;
	uint64_t memSlide;
	uint64_t kernelSlide;
} pal_hib_tramp_result_t;

#if HIBERNATE_TRAP_HANDLER
/*!
 * @function    hibernate_trap
 * @discussion  Platform-specific function for handling a trap during hibernation resume.
 *
 * @param       context         The context captured during the trap
 * @param       trap_addr       The address of the low level trap handler that was invoked
 */
void hibernate_trap(arm_context_t *context, uint64_t trap_addr) __attribute__((noreturn));
#endif /* HIBERNATE_TRAP_HANDLER */

__END_DECLS

#endif /* _ARM64_PAL_HIBERNATE_H */
