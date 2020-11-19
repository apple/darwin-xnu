/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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
 * Platform abstraction layer to support hibernation.
 */

#ifndef _MACHINE_PAL_HIBERNATE_H
#define _MACHINE_PAL_HIBERNATE_H

#include <sys/cdefs.h>

#if defined (__i386__) || defined(__x86_64__)
#include "i386/pal_hibernate.h"
#elif defined (__arm__)
//#include "arm/pal_hibernate.h"
#elif defined(__arm64__)
#include "arm64/pal_hibernate.h"
#else
#error architecture not supported
#endif

__BEGIN_DECLS

/*!
 * @typedef     pal_hib_restore_stage_t
 * @discussion  hibernate_kernel_entrypoint restores data in multiple stages; this enum defines those stages.
 */
typedef enum {
	pal_hib_restore_stage_dram_pages    = 0,
	pal_hib_restore_stage_preview_pages = 1,
	pal_hib_restore_stage_handoff_data  = 2,
} pal_hib_restore_stage_t;

/*!
 * @typedef     pal_hib_ctx_t
 * @discussion  This type is used to pass context between pal_hib_resume_init, pal_hib_restored_page, and
 *              pal_hib_patchup during hibernation resume. The context is declared on the stack in
 *              hibernate_kernel_entrypoint, so it should be relatively small. During pal_hib_resume_init(),
 *              additional memory can be allocated with hibernate_page_list_grab if necessary.
 */
typedef struct pal_hib_ctx pal_hib_ctx_t;

/*!
 * @function    __hib_assert
 * @discussion  Called when a fatal assertion has been detected during hibernation. Logs the
 *              expression string and loops indefinitely.
 *
 * @param       file            The source file in which the failed assertion occurred
 * @param       line            The line number at which the failed assertion occurred
 * @param       expression      A string describing the failed assertion
 */
void __hib_assert(const char *file, int line, const char *expression) __attribute__((noreturn));
#define HIB_ASSERT(ex) \
	(__builtin_expect(!!((ex)), 1L) ? (void)0 : __hib_assert(__FILE__, __LINE__, # ex))

/*!
 * @function    pal_hib_map
 * @discussion  Given a map type and a physical address, return the corresponding virtual address.
 *
 * @param       virt            Which memory region to access
 * @param       phys            The physical address to access
 *
 * @result      The virtual address corresponding to this physical address.
 */
uintptr_t pal_hib_map(pal_hib_map_type_t virt, uint64_t phys);

/*!
 * @function    pal_hib_restore_pal_state
 * @discussion  Callout to the platform abstraction layer to restore platform-specific data.
 *
 * @param       src             Pointer to platform-specific data
 */
void pal_hib_restore_pal_state(uint32_t *src);

/*!
 * @function    pal_hib_init
 * @discussion  Platform-specific hibernation initialization.
 */
void pal_hib_init(void);

/*!
 * @function    pal_hib_write_hook
 * @discussion  Platform-specific callout before the hibernation image is written.
 */
void pal_hib_write_hook(void);

/*!
 * @function    pal_hib_resume_init
 * @discussion  Initialize the platform-specific hibernation resume context. Additional memory can
 *              be allocated with hibernate_page_list_grab if necessary
 *
 * @param       palHibCtx       Pointer to platform-specific hibernation resume context
 * @param       map             map argument that can be passed to hibernate_page_list_grab
 * @param       nextFree        nextFree argument that can be passed to hibernate_page_list_grab
 */
void pal_hib_resume_init(pal_hib_ctx_t *palHibCtx, hibernate_page_list_t *map, uint32_t *nextFree);

/*!
 * @function    pal_hib_restored_page
 * @discussion  Inform the platform abstraction layer of a page that will be restored.
 *
 * @param       palHibCtx       Pointer to platform-specific hibernation resume context
 * @param       stage           The stage of hibernation resume during which this page will be resumed
 * @param       ppnum           The page number of the page that will be resumed.
 */
void pal_hib_restored_page(pal_hib_ctx_t *palHibCtx, pal_hib_restore_stage_t stage, ppnum_t ppnum);

/*!
 * @function    pal_hib_patchup
 * @discussion  Allow the platform abstraction layer to perform post-restore fixups.
 *
 * @param       palHibCtx       Pointer to platform-specific hibernation resume context
 */
void pal_hib_patchup(pal_hib_ctx_t *palHibCtx);

/*!
 * @function    pal_hib_teardown_pmap_structs
 * @discussion  Platform-specific function to return a range of memory that doesn't need to be saved during hibernation.
 *
 * @param       unneeded_start   Out parameter: the beginning of the unneeded range
 * @param       unneeded_end     Out parameter: the end of the unneeded range
 */
void pal_hib_teardown_pmap_structs(addr64_t *unneeded_start, addr64_t *unneeded_end);

/*!
 * @function    pal_hib_rebuild_pmap_structs
 * @discussion  Platform-specific function to fix up the teardown done by pal_hib_teardown_pmap_structs.
 */
void pal_hib_rebuild_pmap_structs(void);

/*!
 * @function    pal_hib_decompress_page
 * @discussion  Decompress a page of memory using WKdm
 *
 * @param       src             The compressed data
 * @param       dst             A page-sized buffer to decompress into; must be page aligned
 * @param       scratch         A page-sized scratch buffer to use during decompression
 * @param       compressedSize  The number of bytes to decompress
 */
void pal_hib_decompress_page(void *src, void *dst, void *scratch, unsigned int compressedSize);

__END_DECLS

#endif /* _MACHINE_PAL_HIBERNATE_H */
