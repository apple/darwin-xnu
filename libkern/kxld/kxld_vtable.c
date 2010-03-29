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
#include <mach-o/loader.h>
#include <sys/types.h>

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_demangle.h"
#include "kxld_reloc.h"
#include "kxld_sect.h"
#include "kxld_state.h"
#include "kxld_sym.h"
#include "kxld_symtab.h"
#include "kxld_util.h"
#include "kxld_vtable.h"

#define VTABLE_ENTRY_SIZE_32 4
#define VTABLE_HEADER_LEN_32 2
#define VTABLE_HEADER_SIZE_32 (VTABLE_HEADER_LEN_32 * VTABLE_ENTRY_SIZE_32)

#define VTABLE_ENTRY_SIZE_64 8
#define VTABLE_HEADER_LEN_64 2
#define VTABLE_HEADER_SIZE_64 (VTABLE_HEADER_LEN_64 * VTABLE_ENTRY_SIZE_64)

static kern_return_t init_by_relocs(KXLDVTable *vtable, const KXLDSym *sym,
    const KXLDSect *sect, const KXLDSymtab *symtab, 
    const KXLDRelocator *relocator);

static kern_return_t init_by_entries_and_relocs(KXLDVTable *vtable, 
    const KXLDSym *sym, const KXLDSymtab *symtab, 
    const KXLDRelocator *relocator, const KXLDArray *relocs);

static kxld_addr_t get_entry_value(u_char *entry, const KXLDRelocator *relocator)
    __attribute__((pure));
#if !KERNEL
static kxld_addr_t swap_entry_value(kxld_addr_t entry_value, 
    const KXLDRelocator *relocator) __attribute__((const));
#endif /* !KERNEL */
static kern_return_t init_by_entries(KXLDVTable *vtable, const KXLDSymtab *symtab,
    const KXLDRelocator *relocator);

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_vtable_init_from_kernel_macho(KXLDVTable *vtable, const KXLDSym *sym, 
    const KXLDSect *sect, const KXLDSymtab *symtab, 
    const KXLDRelocator *relocator)
{
    kern_return_t rval = KERN_FAILURE;
    char *demangled_name = NULL;
    size_t demangled_length = 0;

    check(vtable);
    check(sym);
    check(sect);
    check(symtab);

    vtable->name = sym->name;
    vtable->vtable = sect->data + kxld_sym_get_section_offset(sym, sect);
    vtable->is_patched = FALSE;

    require_action(kxld_sect_get_num_relocs(sect) == 0, finish,
        rval=KERN_FAILURE;
        kxld_log(kKxldLogPatching, kKxldLogErr, 
            kKxldLogMalformedVTable,
            kxld_demangle(vtable->name, &demangled_name, &demangled_length)));

    rval = init_by_entries(vtable, symtab, relocator);
    require_noerr(rval, finish);

    vtable->is_patched = TRUE;

    rval = KERN_SUCCESS;

finish:
    if (rval) kxld_vtable_deinit(vtable);
    if (demangled_name) kxld_free(demangled_name, demangled_length);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_vtable_init_from_object_macho(KXLDVTable *vtable, const KXLDSym *sym, 
    const KXLDSect *sect, const KXLDSymtab *symtab, 
    const KXLDRelocator *relocator)
{
    kern_return_t rval = KERN_FAILURE;
    char *demangled_name = NULL;
    size_t demangled_length = 0;

    check(vtable);
    check(sym);
    check(sect);
    check(symtab);

    vtable->name = sym->name;
    vtable->vtable = sect->data + kxld_sym_get_section_offset(sym, sect);
    vtable->is_patched = FALSE;

    require_action(kxld_sect_get_num_relocs(sect) > 0, finish,
        rval=KERN_FAILURE;
        kxld_log(kKxldLogPatching, kKxldLogErr, 
            kKxldLogMalformedVTable, 
            kxld_demangle(vtable->name, &demangled_name, &demangled_length)));

    rval = init_by_relocs(vtable, sym, sect, symtab, relocator);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    if (rval) kxld_vtable_deinit(vtable);
    if (demangled_name) kxld_free(demangled_name, demangled_length);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_vtable_init_from_final_macho(KXLDVTable *vtable, const KXLDSym *sym, 
    const KXLDSect *sect, const KXLDSymtab *symtab, 
    const KXLDRelocator *relocator, const KXLDArray *relocs)
{
    kern_return_t rval = KERN_FAILURE;
    char *demangled_name = NULL;
    size_t demangled_length = 0;

    check(vtable);
    check(sym);
    check(sect);
    check(symtab);

    vtable->name = sym->name;
    vtable->vtable = sect->data + kxld_sym_get_section_offset(sym, sect);
    vtable->is_patched = FALSE;

    require_action(kxld_sect_get_num_relocs(sect) == 0, finish,
        rval=KERN_FAILURE;
        kxld_log(kKxldLogPatching, kKxldLogErr, 
            kKxldLogMalformedVTable, 
            kxld_demangle(vtable->name, &demangled_name, &demangled_length)));

    rval = init_by_entries_and_relocs(vtable, sym, symtab,
        relocator, relocs);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    if (rval) kxld_vtable_deinit(vtable);
    if (demangled_name) kxld_free(demangled_name, demangled_length);

    return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_vtable_init_from_link_state_32(KXLDVTable *vtable, u_char *file, 
    KXLDVTableHdr *hdr)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymEntry32 *sym = NULL;
    KXLDVTableEntry *entry = NULL;
    u_int i = 0;

    check(vtable);
    check(file);
    check(hdr);

    vtable->name = (char *) (file + hdr->nameoff);
    vtable->is_patched = TRUE;

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), 
        hdr->nentries);
    require_noerr(rval, finish);
    
    sym = (KXLDSymEntry32 *) (file + hdr->vtableoff);
    for (i = 0; i < vtable->entries.nitems; ++i, ++sym) {
        entry = kxld_array_get_item(&vtable->entries, i);
        entry->patched.name = (char *) (file + sym->nameoff);
        entry->patched.addr = sym->addr;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_vtable_init_from_link_state_64(KXLDVTable *vtable, u_char *file, 
    KXLDVTableHdr *hdr)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymEntry64 *sym = NULL;
    KXLDVTableEntry *entry = NULL;
    u_int i = 0;

    check(vtable);
    check(file);
    check(hdr);

    vtable->name = (char *) (file + hdr->nameoff);
    vtable->is_patched = TRUE;

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), 
        hdr->nentries);
    require_noerr(rval, finish);
    
    sym = (KXLDSymEntry64 *) (file + hdr->vtableoff);
    for (i = 0; i < vtable->entries.nitems; ++i, ++sym) {
        entry = kxld_array_get_item(&vtable->entries, i);
        entry->patched.name = (char *) (file + sym->nameoff);
        entry->patched.addr = sym->addr;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_vtable_copy(KXLDVTable *vtable, const KXLDVTable *src)
{
    kern_return_t rval = KERN_FAILURE;

    check(vtable);
    check(src);
    
    vtable->vtable = src->vtable;
    vtable->name = src->name;
    vtable->is_patched = src->is_patched;

    rval = kxld_array_copy(&vtable->entries, &src->entries);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
* Initializes a vtable object by matching up relocation entries to the vtable's
* entries and finding the corresponding symbols.
*******************************************************************************/
static kern_return_t
init_by_relocs(KXLDVTable *vtable, const KXLDSym *sym, const KXLDSect *sect, 
    const KXLDSymtab *symtab, const KXLDRelocator *relocator)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    KXLDVTableEntry *entry = NULL;
    KXLDSym *tmpsym = NULL;
    kxld_addr_t vtable_base_offset = 0;
    kxld_addr_t entry_offset = 0;
    u_int i = 0;
    u_int nentries = 0;
    u_int vtable_entry_size = 0;
    u_int base_reloc_index = 0;
    u_int reloc_index = 0;

    check(vtable);
    check(sym);
    check(sect);
    check(symtab);
    check(relocator);

    /* Find the first entry past the vtable padding */

    vtable_base_offset = kxld_sym_get_section_offset(sym, sect);
    if (relocator->is_32_bit) {
        vtable_entry_size = VTABLE_ENTRY_SIZE_32;
        vtable_base_offset += VTABLE_HEADER_SIZE_32;
    } else {
        vtable_entry_size = VTABLE_ENTRY_SIZE_64;
        vtable_base_offset += VTABLE_HEADER_SIZE_64;
    }

    /* Find the relocation entry at the start of the vtable */

    rval = kxld_reloc_get_reloc_index_by_offset(&sect->relocs, 
        vtable_base_offset, &base_reloc_index);
    require_noerr(rval, finish);

    /* Count the number of consecutive relocation entries to find the number of
     * vtable entries.  For some reason, the __TEXT,__const relocations are
     * sorted in descending order, so we have to walk backwards.  Also, make
     * sure we don't run off the end of the section's relocs.
     */

    reloc_index = base_reloc_index;
    entry_offset = vtable_base_offset;
    reloc = kxld_array_get_item(&sect->relocs, reloc_index);
    while (reloc->address == entry_offset) {
        ++nentries;
        if (!reloc_index) break;

        --reloc_index;

        reloc = kxld_array_get_item(&sect->relocs, reloc_index);
        entry_offset += vtable_entry_size;
    }

    /* Allocate the symbol index */

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), nentries);
    require_noerr(rval, finish);

    /* Find the symbols for each vtable entry */

    for (i = 0; i < vtable->entries.nitems; ++i) {
        reloc = kxld_array_get_item(&sect->relocs, base_reloc_index - i);
        entry = kxld_array_get_item(&vtable->entries, i);

        /* If we can't find a symbol, it means it is a locally-defined,
         * non-external symbol that has been stripped.  We don't patch over
         * locally-defined symbols, so we leave the symbol as NULL and just
         * skip it.  We won't be able to patch subclasses with this symbol,
         * but there isn't much we can do about that.
         */
        tmpsym = kxld_reloc_get_symbol(relocator, reloc, sect->data, symtab);

        entry->unpatched.sym = tmpsym;
        entry->unpatched.reloc = reloc;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kxld_addr_t
get_entry_value(u_char *entry, const KXLDRelocator *relocator)
{
    kxld_addr_t entry_value;

    if (relocator->is_32_bit) {
        entry_value = *(uint32_t *)entry;
    } else {
        entry_value = *(uint64_t *)entry;
    }

    return entry_value;
}

#if !KERNEL
/*******************************************************************************
*******************************************************************************/
static kxld_addr_t
swap_entry_value(kxld_addr_t entry_value, const KXLDRelocator *relocator)
{
    if (relocator->is_32_bit) {
        entry_value = OSSwapInt32((uint32_t) entry_value);
    } else {
        entry_value = OSSwapInt64((uint64_t) entry_value);
    }

    return entry_value;
}
#endif /* KERNEL */

/*******************************************************************************
* Initializes a vtable object by reading the symbol values out of the vtable
* entries and performing reverse symbol lookups on those values.
*******************************************************************************/
static kern_return_t
init_by_entries(KXLDVTable *vtable, const KXLDSymtab *symtab, 
    const KXLDRelocator *relocator)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDVTableEntry *tmpentry = NULL;
    KXLDSym *sym = NULL;
    u_char *base_entry = NULL;
    u_char *entry = NULL;
    kxld_addr_t entry_value = 0;
    u_int vtable_entry_size = 0;
    u_int vtable_header_size = 0;
    u_int nentries = 0;
    u_int i = 0;

    if (relocator->is_32_bit) {
        vtable_entry_size = VTABLE_ENTRY_SIZE_32;
        vtable_header_size = VTABLE_HEADER_SIZE_32;
    } else {
        vtable_entry_size = VTABLE_ENTRY_SIZE_64;
        vtable_header_size = VTABLE_HEADER_SIZE_64;
    }

    base_entry = vtable->vtable + vtable_header_size;

    /* Count the number of entries (the vtable is null-terminated) */

    entry = base_entry;
    entry_value = get_entry_value(entry, relocator);
    while (entry_value) {
        ++nentries;
        entry += vtable_entry_size;
        entry_value = get_entry_value(entry, relocator);
    }
    
    /* Allocate the symbol index */

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), nentries);
    require_noerr(rval, finish);

    /* Look up the symbols for each entry */

    entry = base_entry;
    rval = KERN_SUCCESS;
    for (i = 0; i < vtable->entries.nitems; ++i) {
        entry = base_entry + (i * vtable_entry_size);
        entry_value = get_entry_value(entry, relocator);

#if !KERNEL
        if (relocator->swap) {
            entry_value = swap_entry_value(entry_value, relocator);
        }
#endif /* !KERNEL */
        
        /* If we can't find the symbol, it means that the virtual function was
         * defined inline.  There's not much I can do about this; it just means
         * I can't patch this function.
         */
        tmpentry = kxld_array_get_item(&vtable->entries, i);
        sym = kxld_symtab_get_cxx_symbol_by_value(symtab, entry_value);

        if (sym) {
            tmpentry->patched.name = sym->name;
            tmpentry->patched.addr = sym->link_addr;
        } else {
            tmpentry->patched.name = NULL;
            tmpentry->patched.addr = 0;
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
* Initializes vtables by performing a reverse lookup on symbol values when
* they exist in the vtable entry, and by looking through a matching relocation
* entry when the vtable entry is NULL.
*
* Final linked images require this hybrid vtable initialization approach
* because they are already internally resolved.  This means that the vtables
* contain valid entries to local symbols, but still have relocation entries for
* external symbols.
*******************************************************************************/
static kern_return_t
init_by_entries_and_relocs(KXLDVTable *vtable, const KXLDSym *sym, 
    const KXLDSymtab *symtab, const KXLDRelocator *relocator, 
    const KXLDArray *relocs)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    KXLDVTableEntry *tmpentry = NULL;
    KXLDSym *tmpsym = NULL;
    u_int vtable_entry_size = 0;
    u_int vtable_header_size = 0;
    u_char *base_entry = NULL;
    u_char *entry = NULL;
    kxld_addr_t entry_value = 0;
    kxld_addr_t base_entry_offset = 0;
    kxld_addr_t entry_offset = 0;
    u_int nentries = 0;
    u_int i = 0;
    char *demangled_name1 = NULL;
    size_t demangled_length1 = 0;

    check(vtable);
    check(sym);
    check(symtab);
    check(relocs);

    /* Find the first entry and its offset past the vtable padding */

    if (relocator->is_32_bit) {
        vtable_entry_size = VTABLE_ENTRY_SIZE_32;
        vtable_header_size = VTABLE_HEADER_SIZE_32;
    } else {
        vtable_entry_size = VTABLE_ENTRY_SIZE_64;
        vtable_header_size = VTABLE_HEADER_SIZE_64;
    }

    base_entry = vtable->vtable + vtable_header_size;

    base_entry_offset = sym->base_addr;
    base_entry_offset += vtable_header_size;

    /* In a final linked image, a vtable slot is valid if it is nonzero
     * (meaning the userspace linker has already resolved it, or if it has
     * a relocation entry.  We'll know the end of the vtable when we find a
     * slot that meets neither of these conditions.
     */
    entry = base_entry;
    entry_value = get_entry_value(entry, relocator);
    entry_offset = base_entry_offset;
    while (1) {
        entry_value = get_entry_value(entry, relocator);
        if (!entry_value) {
            reloc = kxld_reloc_get_reloc_by_offset(relocs, entry_offset);
            if (!reloc) break;
        }

        ++nentries;
        entry += vtable_entry_size;
        entry_offset += vtable_entry_size;
    }

    /* Allocate the symbol index */

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), nentries);
    require_noerr(rval, finish);

    /* Find the symbols for each vtable entry */

    entry = base_entry;
    entry_value = get_entry_value(entry, relocator);
    entry_offset = base_entry_offset;
    for (i = 0; i < vtable->entries.nitems; ++i) {
        entry_value = get_entry_value(entry, relocator);

        /* If we can't find a symbol, it means it is a locally-defined,
         * non-external symbol that has been stripped.  We don't patch over
         * locally-defined symbols, so we leave the symbol as NULL and just
         * skip it.  We won't be able to patch subclasses with this symbol,
         * but there isn't much we can do about that.
         */
        if (entry_value) {
#if !KERNEL
            if (relocator->swap) {
                entry_value = swap_entry_value(entry_value, relocator);
            }
#endif /* !KERNEL */

            reloc = NULL;
            tmpsym = kxld_symtab_get_cxx_symbol_by_value(symtab, entry_value);
        } else {
            reloc = kxld_reloc_get_reloc_by_offset(relocs, entry_offset);
            require_action(reloc, finish,
                rval=KERN_FAILURE;
                kxld_log(kKxldLogPatching, kKxldLogErr, 
                    kKxldLogMalformedVTable, 
                    kxld_demangle(vtable->name, &demangled_name1, 
                        &demangled_length1)));
        
            tmpsym = kxld_reloc_get_symbol(relocator, reloc, 
                /* data */ NULL, symtab);
        }
 
        tmpentry = kxld_array_get_item(&vtable->entries, i);
        tmpentry->unpatched.reloc = reloc;
        tmpentry->unpatched.sym = tmpsym;

        entry += vtable_entry_size;
        entry_offset += vtable_entry_size;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_vtable_clear(KXLDVTable *vtable)
{
    check(vtable);

    vtable->vtable = NULL;
    vtable->name = NULL;
    vtable->is_patched = FALSE;
    kxld_array_clear(&vtable->entries);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_vtable_deinit(KXLDVTable *vtable)
{
    check(vtable);

    kxld_array_deinit(&vtable->entries);
    bzero(vtable, sizeof(*vtable));
}

/*******************************************************************************
* Patching vtables allows us to preserve binary compatibility across releases.
*******************************************************************************/
kern_return_t
kxld_vtable_patch(KXLDVTable *vtable, const KXLDVTable *super_vtable,
    KXLDSymtab *symtab, boolean_t strict_patching __unused)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDVTableEntry *child_entry = NULL;
    KXLDVTableEntry *parent_entry = NULL;
    KXLDSym *sym = NULL;
    u_int symindex = 0;
    u_int i = 0;
    char *demangled_name1 = NULL;
    char *demangled_name2 = NULL;
    char *demangled_name3 = NULL;
    size_t demangled_length1 = 0;
    size_t demangled_length2 = 0;
    size_t demangled_length3 = 0;

    check(vtable);
    check(super_vtable);

    require_action(!vtable->is_patched, finish, rval=KERN_SUCCESS);
    require_action(vtable->entries.nitems >= super_vtable->entries.nitems, finish,
        rval=KERN_FAILURE;
        kxld_log(kKxldLogPatching, kKxldLogErr, kKxldLogMalformedVTable, 
            kxld_demangle(vtable->name, &demangled_name1, &demangled_length1)));

    for (i = 0; i < super_vtable->entries.nitems; ++i) {
        child_entry = kxld_array_get_item(&vtable->entries, i);
        parent_entry = kxld_array_get_item(&super_vtable->entries, i);

        /* The child entry can be NULL when a locally-defined, non-external
         * symbol is stripped.  We wouldn't patch this entry anyway, so we
         * just skip it.
         */

        if (!child_entry->unpatched.sym) continue;

        /* It's possible for the patched parent entry not to have a symbol
         * (e.g. when the definition is inlined).  We can't patch this entry no
         * matter what, so we'll just skip it and die later if it's a problem
         * (which is not likely).
         */

        if (!parent_entry->patched.name) continue;

        /* 1) If the symbol is defined locally, do not patch */

        if (kxld_sym_is_defined_locally(child_entry->unpatched.sym)) continue;

        /* 2) If the child is a pure virtual function, do not patch.
         * In general, we want to proceed with patching when the symbol is 
         * externally defined because pad slots fall into this category.
         * The pure virtual function symbol is special case, as the pure
         * virtual property itself overrides the parent's implementation.
         */

        if (kxld_sym_is_pure_virtual(child_entry->unpatched.sym)) continue;

        /* 3) If the symbols are the same, do not patch */

        if (streq(child_entry->unpatched.sym->name, 
                  parent_entry->patched.name)) 
        {
            continue;
        }

        /* 4) If the parent vtable entry is a pad slot, and the child does not
         * match it, then the child was built against a newer version of the
         * libraries, so it is binary-incompatible.
         */

        require_action(!kxld_sym_name_is_padslot(parent_entry->patched.name),
            finish, rval=KERN_FAILURE;
            kxld_log(kKxldLogPatching, kKxldLogErr, 
                kKxldLogParentOutOfDate, 
                kxld_demangle(super_vtable->name, &demangled_name1, 
                    &demangled_length1), 
                kxld_demangle(vtable->name, &demangled_name2, 
                    &demangled_length2)));

#if KXLD_USER_OR_STRICT_PATCHING
        /* 5) If we are doing strict patching, we prevent kexts from declaring
         * virtual functions and not implementing them.  We can tell if a
         * virtual function is declared but not implemented because we resolve
         * symbols before patching; an unimplemented function will still be
         * undefined at this point.  We then look at whether the symbol has
         * the same class prefix as the vtable.  If it does, the symbol was
         * declared as part of the class and not inherited, which means we
         * should not patch it.
         */

        if (strict_patching && !kxld_sym_is_defined(child_entry->unpatched.sym))
        {
            char class_name[KXLD_MAX_NAME_LEN];
            char function_prefix[KXLD_MAX_NAME_LEN];
            u_long function_prefix_len = 0;

            rval = kxld_sym_get_class_name_from_vtable_name(vtable->name,
                class_name, sizeof(class_name));
            require_noerr(rval, finish);

            function_prefix_len = 
                kxld_sym_get_function_prefix_from_class_name(class_name,
                    function_prefix, sizeof(function_prefix));
            require(function_prefix_len, finish);

            if (!strncmp(child_entry->unpatched.sym->name, 
                    function_prefix, function_prefix_len)) 
            {
                continue;
            }
        }
#endif /* KXLD_USER_OR_STRICT_PATCHING */
    
        /* 6) The child symbol is unresolved and different from its parent, so
         * we need to patch it up.  We do this by modifying the relocation
         * entry of the vtable entry to point to the symbol of the parent
         * vtable entry.  If that symbol does not exist (i.e. we got the data
         * from a link state object's vtable representation), then we create a
         * new symbol in the symbol table and point the relocation entry to
         * that.
         */

        sym = kxld_symtab_get_symbol_by_name(symtab, parent_entry->patched.name);
        if (!sym) {
            rval = kxld_symtab_add_symbol(symtab, parent_entry->patched.name,
                parent_entry->patched.addr, &sym);
            require_noerr(rval, finish);
        }
        require_action(sym, finish, rval=KERN_FAILURE);

        rval = kxld_symtab_get_sym_index(symtab, sym, &symindex);
        require_noerr(rval, finish);

        rval = kxld_reloc_update_symindex(child_entry->unpatched.reloc, symindex);
        require_noerr(rval, finish);

        kxld_log(kKxldLogPatching, kKxldLogDetail,
            "In vtable '%s', patching '%s' with '%s'.", 
            kxld_demangle(vtable->name, &demangled_name1, &demangled_length1),
            kxld_demangle(child_entry->unpatched.sym->name, 
                &demangled_name2, &demangled_length2), 
            kxld_demangle(sym->name, &demangled_name3, &demangled_length3));

        kxld_sym_patch(child_entry->unpatched.sym);
        child_entry->unpatched.sym = sym;
    }

    /* Change the vtable representation from the unpatched layout to the
     * patched layout.
     */
    for (i = 0; i < vtable->entries.nitems; ++i) {
        char *name;
        kxld_addr_t addr;

        child_entry = kxld_array_get_item(&vtable->entries, i);
        if (child_entry->unpatched.sym) {
            name = child_entry->unpatched.sym->name;
            addr = child_entry->unpatched.sym->link_addr;
        } else {
            name = NULL;
            addr = 0;
        }

        child_entry->patched.name = name;
        child_entry->patched.addr = addr;
    }

    vtable->is_patched = TRUE;
    rval = KERN_SUCCESS;

finish:
    if (demangled_name1) kxld_free(demangled_name1, demangled_length1);
    if (demangled_name2) kxld_free(demangled_name2, demangled_length2);
    if (demangled_name3) kxld_free(demangled_name3, demangled_length3);
    
    return rval;
}

