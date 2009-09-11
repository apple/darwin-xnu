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
#ifndef _KXLD_STATE_H_
#define _KXLD_STATE_H_

#include <sys/types.h>
#if KERNEL
    #include <libkern/kxld_types.h>
#else 
    #include "kxld_types.h"
#endif

#include "kxld_array.h"
#include "kxld_util.h"

struct kxld_dict;
struct kxld_kext;
struct kxld_link_state_hdr;
typedef struct kxld_state KXLDState;
typedef struct kxld_link_state_hdr KXLDLinkStateHdr;
typedef struct kxld_vtable_hdr KXLDVTableHdr;
typedef struct kxld_sym_entry_32 KXLDSymEntry32;
typedef struct kxld_sym_entry_64 KXLDSymEntry64;

struct kxld_state {
    u_char *file;
    KXLDArray vtables;
    boolean_t swap;
};

/* 
 * The format of the link state object is as follows:
 
   *      Field            ***       Type           *
   **************************************************
   * Link state header     *** KXLDLinkStateHdr     *
   **************************************************
   * Section order entries *** KXLDSectionName      *
   **************************************************
   * Vtable headers        *** KXLDVTableHdr        *
   **************************************************
   * VTables               *** KXLDSymEntry[32|64]  *
   **************************************************
   * Exported symbols      *** KXLDSymEntry[32|64]  *
   **************************************************
   * String table          *** char[]               *
   **************************************************
   
 */

struct kxld_link_state_hdr {
    uint32_t magic;
    uint32_t version;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    uint32_t nsects;
    uint32_t sectoff;
    uint32_t nvtables;
    uint32_t voff;
    uint32_t nsyms;
    uint32_t symoff;
};

struct kxld_vtable_hdr {
    uint32_t nameoff;
    uint32_t vtableoff;
    uint32_t nentries;
};

struct kxld_sym_entry_32 {
    uint32_t addr;
    uint32_t nameoff;
    uint32_t flags;
};

struct kxld_sym_entry_64 {
    uint64_t addr;
    uint32_t nameoff;
    uint32_t flags;
} __attribute__((aligned(16)));

#define KXLD_SYM_OBSOLETE 0x1

/*******************************************************************************
* Constructors and destructors
*******************************************************************************/

kern_return_t kxld_state_init_from_file(KXLDState *state, u_char *file,
    KXLDArray *section_order)
    __attribute__((nonnull(1,2), visibility("hidden")));

void kxld_state_clear(KXLDState *state)
    __attribute__((nonnull, visibility("hidden")));

void kxld_state_deinit(KXLDState *state)
    __attribute__((nonnull, visibility("hidden")));

/*******************************************************************************
* Accessors
*******************************************************************************/

u_int kxld_state_get_num_symbols(KXLDState *state)
    __attribute__((pure, nonnull, visibility("hidden")));

kern_return_t kxld_state_get_symbols(KXLDState *state, 
    struct kxld_dict *defined_symbols,
    struct kxld_dict *obsolete_symbols)
    __attribute__((nonnull, visibility("hidden")));

u_int kxld_state_get_num_vtables(KXLDState *state)
    __attribute__((pure, nonnull, visibility("hidden")));

kern_return_t kxld_state_get_vtables(KXLDState *state,
    struct kxld_dict *patched_vtables)
    __attribute__((nonnull, visibility("hidden")));

void kxld_state_get_cputype(const KXLDState *state,
    cpu_type_t *cputype, cpu_subtype_t *cpusubtype)
    __attribute__((nonnull, visibility("hidden")));

/*******************************************************************************
* Exporters
*******************************************************************************/

kern_return_t kxld_state_export_kext_to_file(struct kxld_kext *kext, u_char **file,
    u_long *filesize, struct kxld_dict *tmpdict, KXLDArray *tmps)
    __attribute__((nonnull, visibility("hidden")));

#endif /* _KXLD_STATE_H_ */

