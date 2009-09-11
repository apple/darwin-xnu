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
#include <string.h>

#if !KERNEL
    #include <libkern/OSByteOrder.h>
#endif

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_array.h"
#include "kxld_dict.h"
#include "kxld_kext.h"
#include "kxld_state.h"
#include "kxld_sym.h"
#include "kxld_symtab.h"
#include "kxld_util.h"
#include "kxld_vtable.h"

#define LINK_STATE_MAGIC 0xF00DD00D
#define CIGAM_ETATS_KNIL 0x0DD00DF0

#define LINK_STATE_MAGIC_64 0xCAFEF00D
#define CIGAM_ETATS_KNIL_64 0x0DF0FECA

#define LINK_STATE_VERSION 1

static kern_return_t init_string_index(KXLDDict *strings, KXLDArray *tmps, 
    KXLDSymtabIterator *iter, const KXLDArray *vtables, u_int nsymentries, 
    u_long *strsize);
static kern_return_t add_string_to_index(KXLDDict *strings, const char *str, 
    KXLDArray *tmps, u_int *tmpi, u_long *stroff);
static kern_return_t create_link_state(u_char **_file, u_long *_filesize, 
    const KXLDKext *kext,  KXLDSymtabIterator *iter, const KXLDArray *vtables, 
    KXLDDict *strings, u_int nsyms, u_int nsymentries, u_long strsize);
static boolean_t state_is_32_bit(KXLDLinkStateHdr *state);

#if KXLD_USER_OR_ILP32
static kern_return_t get_symbols_32(KXLDState *state, KXLDDict *defined_symbols,
    KXLDDict *obsolete_symbols);
static kern_return_t copy_symbols_32(u_char *file, u_long *data_offset, 
    KXLDSymtabIterator *iter, const KXLDDict *strings);
static kern_return_t copy_vtables_32(u_char *file, u_long *header_offset, 
    u_long *data_offset, const KXLDArray *vtables, const KXLDDict *strings);
#endif /* KXLD_USER_OR_ILP32*/
#if KXLD_USER_OR_LP64
static kern_return_t get_symbols_64(KXLDState *state, KXLDDict *defined_symbols,
    KXLDDict *obsolete_symbols);
static kern_return_t copy_symbols_64(u_char *file, u_long *data_offset, 
    KXLDSymtabIterator *iter, const KXLDDict *strings);
static kern_return_t copy_vtables_64(u_char *file, u_long *header_offset, 
    u_long *data_offset, const KXLDArray *vtables, const KXLDDict *strings);
#endif /* KXLD_USER_OR_ILP64 */

#if !KERNEL
static boolean_t swap_link_state(u_char *state);
static void swap_link_state_32(u_char *state);
static void swap_link_state_64(u_char *state);
static boolean_t unswap_link_state(u_char *state);
static void unswap_link_state_32(u_char *state);
static void unswap_link_state_64(u_char *state);
static void swap_state_hdr(KXLDLinkStateHdr *state_hdr);
static void swap_vtable_hdr(KXLDVTableHdr *vtable_hdr);
static void swap_sym_entry_32(KXLDSymEntry32 *entry);
static void swap_sym_entry_64(KXLDSymEntry64 *entry);
#endif

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_state_init_from_file(KXLDState *state, u_char *file, 
    KXLDArray *section_order __unused)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDLinkStateHdr *hdr = (KXLDLinkStateHdr *) file;
#if KXLD_USER_OR_OBJECT
    KXLDSectionName *dstname = NULL;
    KXLDSectionName *srcname = NULL;
#endif
    KXLDVTableHdr *vhdr = NULL;
    KXLDVTable *vtable = NULL;
    u_int i = 0;

    check(state);
    check(file);

#if !KERNEL
    /* Swap the link state file to host byte order for as long this kxld_state
     * object owns the file.
     */
    state->swap = swap_link_state(file);
#endif
    require_action(hdr->magic == LINK_STATE_MAGIC || 
        hdr->magic == LINK_STATE_MAGIC_64,
        finish, rval=KERN_FAILURE);

    state->file = file;

#if KXLD_USER_OR_OBJECT
    if (section_order && !section_order->nitems && hdr->nsects) {
        rval = kxld_array_init(section_order, sizeof(*dstname), hdr->nsects);
        require_noerr(rval, finish);

        srcname = (KXLDSectionName *) (file + hdr->sectoff);
        for (i = 0; i < hdr->nsects; ++i, ++srcname) {
            dstname = kxld_array_get_item(section_order, i);
            memcpy(dstname, srcname, sizeof(*srcname));
        }
    }
#endif

    rval = kxld_array_init(&state->vtables, sizeof(*vtable), hdr->nvtables);
    require_noerr(rval, finish);
    
    vhdr = (KXLDVTableHdr *) (file + hdr->voff);
    for (i = 0; i < hdr->nvtables; ++i, ++vhdr) {
        vtable = kxld_array_get_item(&state->vtables, i);
        KXLD_3264_FUNC(kxld_is_32_bit(hdr->cputype), rval,
            kxld_vtable_init_from_link_state_32,
            kxld_vtable_init_from_link_state_64,
            vtable, file, vhdr);
        require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_state_clear(KXLDState *state)
{
    KXLDVTable *vtable = NULL;
    u_int i = 0;

    check(state);

#if !KERNEL
    /* We use kxld_state objects to wrap the link state files.  Whenever the
     * file is wrapped by a kxld_state object, the file is kept in host byte
     * order.  Once we are done, we must return it to target byte order.
     */
    if (state->swap) (void)unswap_link_state(state->file);
#endif

    state->file = NULL;
    state->swap = FALSE;
    for (i = 0; i < state->vtables.nitems; ++i) {
        vtable = kxld_array_get_item(&state->vtables, i);
        kxld_vtable_clear(vtable);
    }
    kxld_array_reset(&state->vtables);
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_state_deinit(KXLDState *state)
{
    KXLDVTable *vtable = NULL;
    u_int i = 0;

    check(state);

#if !KERNEL
    if (state->file && state->swap) (void)unswap_link_state(state->file);
#endif
   
    for (i = 0; i < state->vtables.maxitems; ++i) {
        vtable = kxld_array_get_slot(&state->vtables, i);
        kxld_vtable_deinit(vtable);
    }
    kxld_array_deinit(&state->vtables);
    bzero(state, sizeof(*state));
}

/*******************************************************************************
*******************************************************************************/
u_int 
kxld_state_get_num_symbols(KXLDState *state)
{
    KXLDLinkStateHdr *hdr = (KXLDLinkStateHdr *) state->file;

    return hdr->nsyms;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_state_get_symbols(KXLDState *state, KXLDDict *defined_symbols,
    KXLDDict *obsolete_symbols)
{
    KXLDLinkStateHdr * hdr = (KXLDLinkStateHdr *) state->file;
    kern_return_t rval = KERN_FAILURE;

    check(state);
    check(defined_symbols);
    check(obsolete_symbols);

    require_action(hdr->magic == LINK_STATE_MAGIC || 
        hdr->magic == LINK_STATE_MAGIC_64,
        finish, rval=KERN_FAILURE);

    KXLD_3264_FUNC(state_is_32_bit(hdr), rval,
        get_symbols_32, get_symbols_64,
        state, defined_symbols, obsolete_symbols);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
get_symbols_32(KXLDState *state, KXLDDict *defined_symbols,
    KXLDDict *obsolete_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDLinkStateHdr *hdr = (KXLDLinkStateHdr *) state->file;
    KXLDSymEntry32 *entry = NULL;
    const char *name = NULL;
    u_int i = 0;

    entry = (KXLDSymEntry32 *) (state->file + hdr->symoff);
    for (i = 0; i < hdr->nsyms; ++i, ++entry) {
        name = (const char *) (state->file + entry->nameoff);
        rval = kxld_dict_insert(defined_symbols, name, &entry->addr);
        require_noerr(rval, finish);

        if (entry->flags & KXLD_SYM_OBSOLETE) {
            rval = kxld_dict_insert(obsolete_symbols, name, &entry->addr);
            require_noerr(rval, finish);
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
static kern_return_t
get_symbols_64(KXLDState *state, KXLDDict *defined_symbols,
    KXLDDict *obsolete_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDLinkStateHdr *hdr = (KXLDLinkStateHdr *) state->file;
    KXLDSymEntry64 *entry = NULL;
    const char *name = NULL;
    u_int i = 0;

    entry = (KXLDSymEntry64 *) (state->file + hdr->symoff);
    for (i = 0; i < hdr->nsyms; ++i, ++entry) {
        name = (const char *) (state->file + entry->nameoff);
        rval = kxld_dict_insert(defined_symbols, name, &entry->addr);
        require_noerr(rval, finish);

        if (entry->flags & KXLD_SYM_OBSOLETE) {
            rval = kxld_dict_insert(obsolete_symbols, name, &entry->addr);
            require_noerr(rval, finish);
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
u_int 
kxld_state_get_num_vtables(KXLDState *state)
{
    return state->vtables.nitems;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_state_get_vtables(KXLDState *state, KXLDDict *patched_vtables)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDVTable *vtable = NULL;
    u_int i = 0;

    check(state);
    check(patched_vtables);

    for (i = 0; i < state->vtables.nitems; ++i) {
        vtable = kxld_array_get_item(&state->vtables, i);
        rval = kxld_dict_insert(patched_vtables, vtable->name, vtable);
        require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_state_get_cputype(const KXLDState *state, cpu_type_t *cputype, 
    cpu_subtype_t *cpusubtype)
{
    KXLDLinkStateHdr *hdr = (KXLDLinkStateHdr *) state->file;
    
    check(state);
    check(cputype);
    check(cpusubtype);

    *cputype = hdr->cputype;
    *cpusubtype = hdr->cpusubtype;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_state_export_kext_to_file(KXLDKext *kext, u_char **file, u_long *filesize, 
    KXLDDict *strings, KXLDArray *tmps)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    const KXLDSymtab *symtab = NULL;
    const KXLDArray *vtables = NULL;
    const KXLDVTable *vtable = NULL;
    u_int nsyms = 0;
    u_int nsymentries = 0;
    u_int i = 0;
    u_long strsize = 0;

    check(kext);
    check(file);
    check(tmps);

    bzero(&iter, sizeof(iter));

    /* Get the vtables and symbol tables from the kext */

    kxld_kext_get_vtables(kext, &vtables);
    symtab = kxld_kext_get_symtab(kext);
    require_action(symtab, finish, rval=KERN_FAILURE);

    /* Count the number of symentries we'll need in the linkstate */

    kxld_symtab_iterator_init(&iter, symtab, kxld_sym_is_exported, FALSE);

    nsyms = kxld_symtab_iterator_get_num_remaining(&iter);
    nsymentries = nsyms;
    for (i = 0; i < vtables->nitems; ++i) {
        vtable = kxld_array_get_item(vtables, i);
        nsymentries += vtable->entries.nitems;
    }

    /* Initialize the string index */

    rval = init_string_index(strings, tmps, &iter, vtables, nsymentries, 
        &strsize);
    require_noerr(rval, finish);

    /* Create the linkstate file */

    rval = create_link_state(file, filesize, kext, &iter, vtables, 
        strings, nsyms, nsymentries, strsize);
    require_noerr(rval, finish);

    /* Swap if necessary */

#if !KERNEL
    if (kxld_kext_target_needs_swap(kext)) unswap_link_state(*file);
#endif /* !KERNEL */
    
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_string_index(KXLDDict *strings, KXLDArray *tmps, KXLDSymtabIterator *iter,
    const KXLDArray *vtables, u_int nsymentries, u_long *_strsize)
{
    kern_return_t rval = KERN_SUCCESS;
    const KXLDSym *sym = NULL;
    const KXLDVTable *vtable = NULL;
    const KXLDVTableEntry *ventry = NULL;
    u_long strsize = 0;
    u_int tmpi = 0;
    u_int i = 0;
    u_int j = 0;

    check(strings);
    check(tmps);
    check(iter);
    check(vtables);
    check(_strsize);

    *_strsize = 0;

    /* Initialize the string dictionary and string offset array */
    
    rval = kxld_dict_init(strings, kxld_dict_string_hash, kxld_dict_string_cmp,
        nsymentries);
    require_noerr(rval, finish);

    rval = kxld_array_init(tmps, sizeof(u_long), nsymentries);
    require_noerr(rval, finish);

    /* Add all of the strings from the symbol table to the dictionary */

    kxld_symtab_iterator_reset(iter);
    while ((sym = kxld_symtab_iterator_get_next(iter))) {
        rval = add_string_to_index(strings, sym->name, tmps, &tmpi, &strsize);
        require_noerr(rval, finish);
    }

    /* Add all of the strings from the vtables entries to the dictionary */

    for (i = 0; i < vtables->nitems; ++i) {
        vtable = kxld_array_get_item(vtables, i);
        rval = add_string_to_index(strings, vtable->name, tmps, &tmpi, &strsize);
        require_noerr(rval, finish);

        for (j = 0; j < vtable->entries.nitems; ++j) {
            ventry = kxld_array_get_item(&vtable->entries, j);
            if (ventry->patched.name) {
                rval = add_string_to_index(strings, ventry->patched.name, tmps, 
                    &tmpi, &strsize);
                require_noerr(rval, finish);
            }
        }
    }

    *_strsize = strsize;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
add_string_to_index(KXLDDict *strings, const char *str, KXLDArray *tmps,
    u_int *tmpi, u_long *stroff)
{
    kern_return_t rval = KERN_FAILURE;
    u_long *tmpp = NULL;

    if (!kxld_dict_find(strings, str)) {
        tmpp = kxld_array_get_item(tmps, (*tmpi)++);
        *tmpp = *stroff;
        
        rval = kxld_dict_insert(strings, str, tmpp);
        require_noerr(rval, finish);
    
        *stroff += strlen(str) + 1;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t
state_is_32_bit(KXLDLinkStateHdr *state)
{
    return kxld_is_32_bit(state->cputype);
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
create_link_state(u_char **_file, u_long *_filesize, const KXLDKext *kext,
    KXLDSymtabIterator *iter, const KXLDArray *vtables, KXLDDict *strings, 
    u_int nsyms, u_int nsymentries, u_long strsize)
{
    kern_return_t rval = KERN_SUCCESS;
    u_char *file = NULL;
    KXLDLinkStateHdr *hdr = NULL;
    KXLDDictIterator striter;
#if KXLD_USER_OR_OBJECT
    KXLDSectionName *dstsectname = NULL;
    KXLDSectionName *srcsectname = NULL;
    const KXLDArray *section_order = NULL;
    u_int i = 0;
#endif
    const char *name = NULL;
    char *dstname = NULL;
    u_long *stridx = 0;
    u_long hsize = 0;
    u_long dsize = 0;
    u_long filesize = 0;
    u_long hoff = 0;
    u_long doff = 0;
    u_long stroff = 0;

    check(_file);
    check(iter);
    check(vtables);
    check(strings);

    *_file = NULL;
    *_filesize = 0;

#if KXLD_USER_OR_OBJECT
    section_order = kxld_kext_get_section_order(kext);
#endif

    /* Calculate header and data size */

    hsize = sizeof(KXLDLinkStateHdr);
    hsize += vtables->nitems * sizeof(KXLDVTableHdr);
#if KXLD_USER_OR_OBJECT
    if (section_order) {
        hsize += section_order->nitems * sizeof(KXLDSectionName);
    }
#endif

    if (kxld_kext_is_32_bit(kext)) {
        dsize = nsymentries * sizeof(KXLDSymEntry32);
    } else {
        dsize = nsymentries * sizeof(KXLDSymEntry64);
    }

    filesize = hsize + dsize + strsize;

    hoff = 0;
    doff = hsize;
    stroff = hsize + dsize;

    /* Allocate the link state */

    file = kxld_alloc_pageable(filesize);
    require_action(file, finish, rval=KERN_RESOURCE_SHORTAGE);

    /* Initialize link state header */

    hdr = (KXLDLinkStateHdr *) file;
    hoff += sizeof(*hdr); 

    if (state_is_32_bit(hdr)) {
        hdr->magic = LINK_STATE_MAGIC;
    } else {
        hdr->magic = LINK_STATE_MAGIC_64;
    }
    hdr->version = LINK_STATE_VERSION;
    kxld_kext_get_cputype(kext, &hdr->cputype, &hdr->cpusubtype);
    hdr->nsects = 0;
    hdr->nvtables = vtables->nitems;
    hdr->nsyms = nsyms;

#if KXLD_USER_OR_OBJECT
    if (section_order) {
        hdr->nsects = section_order->nitems;
        hdr->sectoff = (uint32_t) hoff;

        dstsectname = (KXLDSectionName *) (file + hoff);
        hoff += section_order->nitems * sizeof(*dstsectname);

        for (i = 0; i < section_order->nitems; ++i, ++dstsectname) {
            srcsectname = kxld_array_get_item(section_order, i);
            memcpy(dstsectname, srcsectname, sizeof(*srcsectname));
        }
    }
#endif

    hdr->voff = (uint32_t) hoff;
    hdr->symoff = (uint32_t) doff;

    /* Copy strings */
    
    kxld_dict_iterator_init(&striter, strings);
    kxld_dict_iterator_get_next(&striter, (const void **) &name, (void **) &stridx);
    while (name) {
        *stridx += stroff;
        dstname = (char *) (file + *stridx);
        strlcpy(dstname, name, filesize - *stridx);
        kxld_dict_iterator_get_next(&striter, (const void **) &name, (void **) &stridx);
    }

    /* Copy symbols */

    KXLD_3264_FUNC(state_is_32_bit(hdr), rval,
        copy_symbols_32, copy_symbols_64,
        file, &doff, iter, strings);
    require_noerr(rval, finish);

    /* Copy vtables */

    KXLD_3264_FUNC(state_is_32_bit(hdr), rval,
        copy_vtables_32, copy_vtables_64,
        file, &hoff, &doff, vtables, strings);
    require_noerr(rval, finish);

    *_file = file;
    *_filesize = filesize;
    file = NULL;
    rval = KERN_SUCCESS;

finish:

    if (file) {
        kxld_page_free(file, filesize);
        file = NULL;
    }

    return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
copy_symbols_32(u_char *file, u_long *data_offset, KXLDSymtabIterator *iter, 
    const KXLDDict *strings)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymEntry32 *symentry = NULL;
    const KXLDSym *sym = NULL;
    u_long *stridx = 0;

    kxld_symtab_iterator_reset(iter);
    while ((sym = kxld_symtab_iterator_get_next(iter))) {
        symentry = (KXLDSymEntry32 *) (file + *data_offset);
        stridx = kxld_dict_find(strings, sym->name);
        require_action(stridx, finish, rval=KERN_FAILURE);

        /* Initialize the symentry */

        symentry->nameoff = (uint32_t) *stridx;
        if (sym->predicates.is_thumb) {
            symentry->addr = (uint32_t) sym->link_addr | 1;
        } else {            
            symentry->addr = (uint32_t) sym->link_addr;
        }
        symentry->flags = 0;

        /* Set any flags */

        symentry->flags |= (kxld_sym_is_obsolete(sym)) ? KXLD_SYM_OBSOLETE : 0;

        *data_offset += sizeof(*symentry);
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
static kern_return_t
copy_symbols_64(u_char *file, u_long *data_offset, KXLDSymtabIterator *iter, 
    const KXLDDict *strings)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymEntry64 *symentry = NULL;
    const KXLDSym *sym = NULL;
    u_long *stridx = 0;

    kxld_symtab_iterator_reset(iter);
    while ((sym = kxld_symtab_iterator_get_next(iter))) {
        symentry = (KXLDSymEntry64 *) (file + *data_offset);
        stridx = kxld_dict_find(strings, sym->name);
        require_action(stridx, finish, rval=KERN_FAILURE);

        /* Initialize the symentry */

        symentry->nameoff = (uint32_t) *stridx;
        symentry->addr = (uint64_t) sym->link_addr;
        symentry->flags = 0;

        /* Set any flags */

        symentry->flags |= (kxld_sym_is_obsolete(sym)) ? KXLD_SYM_OBSOLETE : 0;

        *data_offset += sizeof(*symentry);
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
copy_vtables_32(u_char *file, u_long *header_offset, u_long *data_offset,
    const KXLDArray *vtables, const KXLDDict *strings)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDVTable *vtable = NULL;
    KXLDVTableHdr *vhdr = NULL;
    KXLDVTableEntry *ventry = NULL;
    KXLDSymEntry32 *symentry = NULL;
    u_long *stridx = 0;
    u_int i = 0;
    u_int j = 0;

    for (i = 0; i < vtables->nitems; ++i) {
        vtable = kxld_array_get_item(vtables, i);
        stridx = kxld_dict_find(strings, vtable->name);
        require_action(stridx, finish, rval=KERN_FAILURE);

        vhdr = (KXLDVTableHdr *) (file + *header_offset);
        vhdr->nameoff = (uint32_t) *stridx;
        vhdr->nentries = vtable->entries.nitems;
        vhdr->vtableoff = (uint32_t) (*data_offset);

        *header_offset += sizeof(*vhdr);

        for(j = 0; j < vtable->entries.nitems; ++j) {

            ventry = kxld_array_get_item(&vtable->entries, j);
            symentry = (KXLDSymEntry32 *) (file + *data_offset);
            
            if (ventry->patched.name) {
                stridx = kxld_dict_find(strings, ventry->patched.name);
                require_action(stridx, finish, rval=KERN_FAILURE);

                symentry->nameoff = (uint32_t) *stridx;
                symentry->addr = (uint32_t) ventry->patched.addr;
            } else {
                symentry->nameoff = 0;
                symentry->addr = 0;
            }

            *data_offset += sizeof(*symentry);
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
static kern_return_t
copy_vtables_64(u_char *file, u_long *header_offset, u_long *data_offset,
    const KXLDArray *vtables, const KXLDDict *strings)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDVTable *vtable = NULL;
    KXLDVTableHdr *vhdr = NULL;
    KXLDVTableEntry *ventry = NULL;
    KXLDSymEntry64 *symentry = NULL;
    u_long *stridx = 0;
    u_int i = 0;
    u_int j = 0;

    for (i = 0; i < vtables->nitems; ++i) {
        vtable = kxld_array_get_item(vtables, i);
        stridx = kxld_dict_find(strings, vtable->name);
        require_action(stridx, finish, rval=KERN_FAILURE);

        vhdr = (KXLDVTableHdr *) (file + *header_offset);
        vhdr->nameoff = (uint32_t) *stridx;
        vhdr->nentries = vtable->entries.nitems;
        vhdr->vtableoff = (uint32_t) (*data_offset);

        *header_offset += sizeof(*vhdr);

        for(j = 0; j < vtable->entries.nitems; ++j) {

            ventry = kxld_array_get_item(&vtable->entries, j);
            symentry = (KXLDSymEntry64 *) (file + *data_offset);
            
            if (ventry->patched.name) {
                stridx = kxld_dict_find(strings, ventry->patched.name);
                require_action(stridx, finish, rval=KERN_FAILURE);

                symentry->nameoff = (uint32_t) *stridx;
                symentry->addr = (uint64_t) ventry->patched.addr;
            } else {
                symentry->nameoff = 0;
                symentry->addr = 0;
            }

            *data_offset += sizeof(*symentry);
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

#if !KERNEL
/*******************************************************************************
*******************************************************************************/
static boolean_t
swap_link_state(u_char *state)
{
    KXLDLinkStateHdr *state_hdr = (KXLDLinkStateHdr *) state;

    if (state_hdr->magic == CIGAM_ETATS_KNIL) {
        swap_link_state_32(state);
        return TRUE;
    } else if (state_hdr->magic == CIGAM_ETATS_KNIL_64) {
        swap_link_state_64(state);
        return TRUE;
    }

    return FALSE;
}

/*******************************************************************************
*******************************************************************************/
static void
swap_link_state_32(u_char *state)
{
    KXLDLinkStateHdr *state_hdr = NULL;
    KXLDVTableHdr *vtable_hdr = NULL;
    KXLDSymEntry32 *entry = NULL;
    u_int i = 0;
    u_int j = 0;
    
    state_hdr = (KXLDLinkStateHdr *) state;

    if (state_hdr->magic != CIGAM_ETATS_KNIL) return;

    /* Swap the header */
    swap_state_hdr(state_hdr);

    /* Swap the symbols */
    entry = (KXLDSymEntry32 *) (state + state_hdr->symoff);
    for (i = 0; i < state_hdr->nsyms; ++i, ++entry) {
        swap_sym_entry_32(entry);
    }

    /* Swap the vtable headers and entries */
    vtable_hdr = (KXLDVTableHdr *) (state + state_hdr->voff);
    for (i = 0; i < state_hdr->nvtables; ++i, ++vtable_hdr) {
        swap_vtable_hdr(vtable_hdr);

        entry = (KXLDSymEntry32 *) (state + vtable_hdr->vtableoff);
        for (j = 0; j < vtable_hdr->nentries; ++j, ++entry) {
            swap_sym_entry_32(entry);
        }
    }
}

/*******************************************************************************
*******************************************************************************/
static void
swap_link_state_64(u_char *state)
{
    KXLDLinkStateHdr *state_hdr = NULL;
    KXLDVTableHdr *vtable_hdr = NULL;
    KXLDSymEntry64 *entry = NULL;
    u_int i = 0;
    u_int j = 0;
    
    state_hdr = (KXLDLinkStateHdr *) state;

    if (state_hdr->magic != CIGAM_ETATS_KNIL_64) return;

    /* Swap the header */
    swap_state_hdr(state_hdr);

    /* Swap the symbols */
    entry = (KXLDSymEntry64 *) (state + state_hdr->symoff);
    for (i = 0; i < state_hdr->nsyms; ++i, ++entry) {
        swap_sym_entry_64(entry);
    }

    /* Swap the vtable headers and entries */
    vtable_hdr = (KXLDVTableHdr *) (state + state_hdr->voff);
    for (i = 0; i < state_hdr->nvtables; ++i, ++vtable_hdr) {
        swap_vtable_hdr(vtable_hdr);

        entry = (KXLDSymEntry64 *) (state + vtable_hdr->vtableoff);
        for (j = 0; j < vtable_hdr->nentries; ++j, ++entry) {
            swap_sym_entry_64(entry);
        }
    }
}

/*******************************************************************************
*******************************************************************************/
static boolean_t
unswap_link_state(u_char *state)
{
    KXLDLinkStateHdr *state_hdr = (KXLDLinkStateHdr *) state;

    if (state_hdr->magic == LINK_STATE_MAGIC) {
        unswap_link_state_32(state);
        return TRUE;
    } else if (state_hdr->magic == LINK_STATE_MAGIC_64) {
        unswap_link_state_64(state);
        return TRUE;
    }

    return FALSE;
}

/*******************************************************************************
*******************************************************************************/
static void
unswap_link_state_32(u_char *state)
{
    KXLDLinkStateHdr *state_hdr = NULL;
    KXLDVTableHdr *vtable_hdr = NULL;
    KXLDSymEntry32 *entry = NULL;
    u_int i = 0;
    u_int j = 0;
    
    state_hdr = (KXLDLinkStateHdr *) state;

    if (state_hdr->magic != LINK_STATE_MAGIC) return;

    /* Unswap the vtables and their headers */
    vtable_hdr = (KXLDVTableHdr *) (state + state_hdr->voff);
    for (i = 0; i < state_hdr->nvtables; ++i, ++vtable_hdr) {
        entry = (KXLDSymEntry32 *) (state + vtable_hdr->vtableoff);
        for (j = 0; j < vtable_hdr->nentries; ++j, ++entry) {
            swap_sym_entry_32(entry);
        }

        swap_vtable_hdr(vtable_hdr);
    }

    /* Unswap the symbols themselves */
    entry = (KXLDSymEntry32 *) (state + state_hdr->symoff);
    for (i = 0; i < state_hdr->nsyms; ++i, ++entry) {
        swap_sym_entry_32(entry);
    }

    /* Unswap the header */
    swap_state_hdr(state_hdr);
}

/*******************************************************************************
*******************************************************************************/
static void
unswap_link_state_64(u_char *state)
{
    KXLDLinkStateHdr *state_hdr = NULL;
    KXLDVTableHdr *vtable_hdr = NULL;
    KXLDSymEntry64 *entry = NULL;
    u_int i = 0;
    u_int j = 0;
    
    state_hdr = (KXLDLinkStateHdr *) state;

    if (state_hdr->magic != LINK_STATE_MAGIC_64) return;

    /* Unswap the vtables and their headers */
    vtable_hdr = (KXLDVTableHdr *) (state + state_hdr->voff);
    for (i = 0; i < state_hdr->nvtables; ++i, ++vtable_hdr) {
        entry = (KXLDSymEntry64 *) (state + vtable_hdr->vtableoff);
        for (j = 0; j < vtable_hdr->nentries; ++j, ++entry) {
            swap_sym_entry_64(entry);
        }

        swap_vtable_hdr(vtable_hdr);
    }

    /* Unswap the symbols themselves */
    entry = (KXLDSymEntry64 *) (state + state_hdr->symoff);
    for (i = 0; i < state_hdr->nsyms; ++i, ++entry) {
        swap_sym_entry_64(entry);
    }

    /* Unswap the header */
    swap_state_hdr(state_hdr);
}

/*******************************************************************************
*******************************************************************************/
static void
swap_state_hdr(KXLDLinkStateHdr *state_hdr)
{
    state_hdr->magic = OSSwapInt32(state_hdr->magic);
    state_hdr->version = OSSwapInt32(state_hdr->version);
    state_hdr->cputype = OSSwapInt32(state_hdr->cputype);
    state_hdr->cpusubtype = OSSwapInt32(state_hdr->cpusubtype);
    state_hdr->nsects = OSSwapInt32(state_hdr->nsects);
    state_hdr->sectoff = OSSwapInt32(state_hdr->sectoff);
    state_hdr->nvtables = OSSwapInt32(state_hdr->nvtables);
    state_hdr->voff = OSSwapInt32(state_hdr->voff);
    state_hdr->nsyms = OSSwapInt32(state_hdr->nsyms);
    state_hdr->symoff = OSSwapInt32(state_hdr->symoff);
}

/*******************************************************************************
*******************************************************************************/
static void
swap_vtable_hdr(KXLDVTableHdr *vtable_hdr)
{
    vtable_hdr->nameoff = OSSwapInt32(vtable_hdr->nameoff);
    vtable_hdr->vtableoff = OSSwapInt32(vtable_hdr->vtableoff);
    vtable_hdr->nentries = OSSwapInt32(vtable_hdr->nentries);
}

/*******************************************************************************
*******************************************************************************/
static void
swap_sym_entry_32(KXLDSymEntry32 *entry)
{
    entry->nameoff = OSSwapInt32(entry->nameoff);
    entry->addr = OSSwapInt32(entry->addr);
}

/*******************************************************************************
*******************************************************************************/
static void
swap_sym_entry_64(KXLDSymEntry64 *entry)
{
    entry->nameoff = OSSwapInt32(entry->nameoff);
    entry->addr = OSSwapInt64(entry->addr);
}
#endif /* !KERNEL */

