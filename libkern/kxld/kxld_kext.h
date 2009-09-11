/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#ifndef _KXLD_KEXT_H_
#define _KXLD_KEXT_H_

#include <mach/machine.h>
#include <sys/types.h>
#if KERNEL
    #include <libkern/kxld_types.h>
#else 
    #include "kxld_types.h"
#endif

struct kxld_array;
struct kxld_kext;
struct kxld_dict;
struct kxld_sect;
struct kxld_seg;
struct kxld_symtab;
struct kxld_vtable;
typedef struct kxld_kext KXLDKext;

/*******************************************************************************
* Constructors and Destructors
*******************************************************************************/

size_t kxld_kext_sizeof(void)
    __attribute__((const, nonnull, visibility("hidden")));

kern_return_t kxld_kext_init(KXLDKext *kext, u_char *file, u_long size,
    const char *name, KXLDFlags flags, boolean_t is_kernel, KXLDArray *seg_order, 
    cpu_type_t cputype, cpu_subtype_t cpusubtype)
    __attribute__((nonnull(1,2,4), visibility("hidden")));

void kxld_kext_clear(KXLDKext *kext)
    __attribute__((nonnull, visibility("hidden")));

void kxld_kext_deinit(KXLDKext *kext)
    __attribute__((nonnull, visibility("hidden")));

/*******************************************************************************
* Accessors
*******************************************************************************/

boolean_t kxld_kext_is_true_kext(const KXLDKext *kext) 
    __attribute__((pure, nonnull, visibility("hidden")));

boolean_t kxld_kext_is_32_bit(const KXLDKext *kext)
    __attribute__((pure, nonnull, visibility("hidden")));

void kxld_kext_get_cputype(const KXLDKext *kext, cpu_type_t *cputype,
    cpu_subtype_t *cpusubtype)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_kext_validate_cputype(const KXLDKext *kext, cpu_type_t cputype,
    cpu_subtype_t cpusubtype)
    __attribute__((pure, nonnull, visibility("hidden")));

void kxld_kext_get_vmsize(const KXLDKext *kext, u_long *header_size, 
    u_long *vmsize)
    __attribute__((nonnull, visibility("hidden")));

const struct kxld_symtab * kxld_kext_get_symtab(const KXLDKext *kext)
    __attribute__((pure, nonnull, visibility("hidden")));

u_int kxld_kext_get_num_symbols(const KXLDKext *kext)
    __attribute__((pure, nonnull, visibility("hidden")));

void kxld_kext_get_vtables(KXLDKext *kext, const struct kxld_array **vtables)
    __attribute__((nonnull, visibility("hidden")));

u_int kxld_kext_get_num_vtables(const KXLDKext *kext)
    __attribute__((pure, nonnull, visibility("hidden")));

struct kxld_seg * kxld_kext_get_seg_by_name(const KXLDKext *kext, 
    const char *segname)
    __attribute__((pure, nonnull, visibility("hidden")));

struct kxld_sect * kxld_kext_get_sect_by_name(const KXLDKext *kext, 
    const char *segname, const char *sectname)
    __attribute__((pure, nonnull, visibility("hidden")));

int kxld_kext_get_sectnum_for_sect(const KXLDKext *kext, 
    const struct kxld_sect *sect)
    __attribute__((pure, nonnull, visibility("hidden")));

const struct kxld_array * kxld_kext_get_section_order(const KXLDKext *kext)
    __attribute__((pure, nonnull, visibility("hidden")));

/* This will be the same size as kxld_kext_get_vmsize */
kern_return_t kxld_kext_export_linked_object(const KXLDKext *kext,
    u_char *linked_object, kxld_addr_t *kmod_info_kern)
    __attribute__((nonnull, visibility("hidden")));

#if !KERNEL
kern_return_t kxld_kext_export_symbol_file(const KXLDKext *kext, 
    u_char **symbol_file, u_long *filesize)
    __attribute__((nonnull, visibility("hidden")));
#endif

boolean_t kxld_kext_target_needs_swap(const KXLDKext *kext)
    __attribute__((pure, nonnull, visibility("hidden")));

/*******************************************************************************
* Modifiers
*******************************************************************************/

kern_return_t kxld_kext_resolve(KXLDKext *kext, struct kxld_dict *patched_vtables,
    struct kxld_dict *defined_symbols)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_kext_relocate(KXLDKext *kext, kxld_addr_t link_address,
    struct kxld_dict *patched_vtables, struct kxld_dict *defined_symbols,
    struct kxld_dict *obsolete_symbols)
    __attribute__((nonnull(1,3,4), visibility("hidden")));

#endif /* _KXLD_KEXT_H_ */
