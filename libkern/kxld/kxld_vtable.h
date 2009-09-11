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
#ifndef _KXLD_VTABLE_H_
#define _KXLD_VTABLE_H_

#include <sys/types.h>
#if KERNEL
    #include <libkern/kxld_types.h>
#else
    #include "kxld_types.h"
#endif

#include "kxld_array.h"

struct kxld_array;
struct kxld_reloc;
struct kxld_relocator;
struct kxld_sect;
struct kxld_sym;
struct kxld_symtab;
struct kxld_vtable_hdr;
struct section;

typedef struct kxld_vtable KXLDVTable;
typedef union kxld_vtable_entry KXLDVTableEntry;

struct kxld_vtable {
    u_char *vtable;
    const char *name;
    KXLDArray entries;
    boolean_t is_patched;
};

struct kxld_vtable_patched_entry {
    char *name;
    kxld_addr_t addr;
};

struct kxld_vtable_unpatched_entry {
    struct kxld_sym *sym;
    struct kxld_reloc *reloc;
};

union kxld_vtable_entry {
    struct kxld_vtable_patched_entry patched;
    struct kxld_vtable_unpatched_entry unpatched;
};

/*******************************************************************************
* Constructors and destructors
*******************************************************************************/

kern_return_t kxld_vtable_init_from_kernel_macho(KXLDVTable *vtable,
    const struct kxld_sym *sym, const struct kxld_sect *sect, 
    const struct kxld_symtab *symtab, const struct kxld_relocator *relocator)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_vtable_init_from_final_macho(KXLDVTable *vtable,
    const struct kxld_sym *sym, const struct kxld_sect *sect, 
    const struct kxld_symtab *symtab, const struct kxld_relocator *relocator,
    const struct kxld_array *relocs)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_vtable_init_from_object_macho(KXLDVTable *vtable,
    const struct kxld_sym *sym, const struct kxld_sect *sect, 
    const struct kxld_symtab *symtab, const struct kxld_relocator *relocator)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_vtable_init_from_link_state_32(KXLDVTable *vtable, u_char *state,
    struct kxld_vtable_hdr *hdr)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_vtable_init_from_link_state_64(KXLDVTable *vtable, u_char *state,
    struct kxld_vtable_hdr *hdr)
    __attribute__((nonnull, visibility("hidden")));

kern_return_t kxld_vtable_copy(KXLDVTable *vtable, const KXLDVTable *src)
    __attribute__((nonnull, visibility("hidden")));

void kxld_vtable_clear(KXLDVTable *vtable)
    __attribute__((visibility("hidden")));

void kxld_vtable_deinit(KXLDVTable *vtable)
    __attribute__((visibility("hidden")));

/*******************************************************************************
* Modifiers
*******************************************************************************/

/* With strict patching, the vtable patcher with only patch pad slots */
kern_return_t kxld_vtable_patch(KXLDVTable *vtable, const KXLDVTable *super_vtable,
    struct kxld_symtab *symtab, boolean_t strict_patching)
    __attribute__((nonnull, visibility("hidden")));

#endif /* _KXLD_VTABLE_H_ */

