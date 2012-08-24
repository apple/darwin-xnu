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

#if KERNEL
    #ifdef MACH_ASSERT
        #undef MACH_ASSERT
    #endif
    #define MACH_ASSERT 1
    #include <kern/assert.h>
#else
    #include <assert.h>
#endif

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_demangle.h"
#include "kxld_dict.h"
#include "kxld_object.h"
#include "kxld_reloc.h"
#include "kxld_sect.h"
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

static void  get_vtable_base_sizes(boolean_t is_32_bit, u_int *vtable_entry_size,
    u_int *vtable_header_size);

static kern_return_t init_by_relocs(KXLDVTable *vtable, const KXLDSym *vtable_sym,
    const KXLDSect *sect, const KXLDRelocator *relocator);

static kern_return_t init_by_entries_and_relocs(KXLDVTable *vtable, 
    const KXLDSym *vtable_sym, const KXLDRelocator *relocator, 
    const KXLDArray *relocs, const KXLDDict *defined_cxx_symbols);

static kern_return_t init_by_entries(KXLDVTable *vtable,
    const KXLDRelocator *relocator, const KXLDDict *defined_cxx_symbols);

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_vtable_init(KXLDVTable *vtable, const KXLDSym *vtable_sym, 
    const KXLDObject *object, const KXLDDict *defined_cxx_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    const KXLDArray *extrelocs = NULL;
    const KXLDRelocator *relocator = NULL;
    const KXLDSect *vtable_sect = NULL;
    char *demangled_name = NULL;
    size_t demangled_length = 0;

    check(vtable);
    check(vtable_sym);
    check(object);

    relocator = kxld_object_get_relocator(object);

    vtable_sect = kxld_object_get_section_by_index(object, 
        vtable_sym->sectnum);
    require_action(vtable_sect, finish, rval=KERN_FAILURE);

    vtable->name = vtable_sym->name;
    vtable->vtable = vtable_sect->data + 
        kxld_sym_get_section_offset(vtable_sym, vtable_sect);

    if (kxld_object_is_linked(object)) {
        rval = init_by_entries(vtable, relocator, defined_cxx_symbols);
        require_noerr(rval, finish);

        vtable->is_patched = TRUE;
    } else {
        if (kxld_object_is_final_image(object)) {
            extrelocs = kxld_object_get_extrelocs(object);
            require_action(extrelocs, finish,
                rval=KERN_FAILURE;
                kxld_log(kKxldLogPatching, kKxldLogErr, 
                    kKxldLogMalformedVTable, 
                    kxld_demangle(vtable->name, 
                        &demangled_name, &demangled_length)));

            rval = init_by_entries_and_relocs(vtable, vtable_sym, 
                relocator, extrelocs, defined_cxx_symbols);
            require_noerr(rval, finish);
        } else {
            require_action(kxld_sect_get_num_relocs(vtable_sect) > 0, finish,
                rval=KERN_FAILURE;
                kxld_log(kKxldLogPatching, kKxldLogErr, 
                    kKxldLogMalformedVTable, 
                    kxld_demangle(vtable->name, 
                        &demangled_name, &demangled_length)));

            rval = init_by_relocs(vtable, vtable_sym, vtable_sect, relocator);
            require_noerr(rval, finish);
        }
        
        vtable->is_patched = FALSE;
    }

    rval = KERN_SUCCESS;
finish:
    if (demangled_name) kxld_free(demangled_name, demangled_length);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static void 
get_vtable_base_sizes(boolean_t is_32_bit, u_int *vtable_entry_size,
    u_int *vtable_header_size)
{
    check(vtable_entry_size);
    check(vtable_header_size);

    if (is_32_bit) {
        *vtable_entry_size = VTABLE_ENTRY_SIZE_32;
        *vtable_header_size = VTABLE_HEADER_SIZE_32;
    } else {
        *vtable_entry_size = VTABLE_ENTRY_SIZE_64;
        *vtable_header_size = VTABLE_HEADER_SIZE_64;
    }
}

/*******************************************************************************
* Initializes a vtable object by matching up relocation entries to the vtable's
* entries and finding the corresponding symbols.
*******************************************************************************/
static kern_return_t
init_by_relocs(KXLDVTable *vtable, const KXLDSym *vtable_sym, 
    const KXLDSect *sect, const KXLDRelocator *relocator)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    KXLDVTableEntry *entry = NULL;
    KXLDSym *sym = NULL;
    kxld_addr_t vtable_base_offset = 0;
    kxld_addr_t entry_offset = 0;
    u_int i = 0;
    u_int nentries = 0;
    u_int vtable_entry_size = 0;
    u_int vtable_header_size = 0;
    u_int base_reloc_index = 0;
    u_int reloc_index = 0;

    check(vtable);
    check(vtable_sym);
    check(sect);
    check(relocator);

    /* Find the first entry past the vtable padding */

    (void) get_vtable_base_sizes(relocator->is_32_bit, 
        &vtable_entry_size, &vtable_header_size);

    vtable_base_offset = kxld_sym_get_section_offset(vtable_sym, sect) + 
        vtable_header_size;
   
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
        sym = kxld_reloc_get_symbol(relocator, reloc, sect->data);

        entry->unpatched.sym = sym;
        entry->unpatched.reloc = reloc;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
* Initializes a vtable object by reading the symbol values out of the vtable
* entries and performing reverse symbol lookups on those values.
*******************************************************************************/
static kern_return_t
init_by_entries(KXLDVTable *vtable, const KXLDRelocator *relocator,
    const KXLDDict *defined_cxx_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDVTableEntry *tmpentry = NULL;
    KXLDSym *sym = NULL;
    kxld_addr_t entry_value = 0;
    u_long entry_offset;
    u_int vtable_entry_size = 0;
    u_int vtable_header_size = 0;
    u_int nentries = 0;
    u_int i = 0;

    check(vtable);
    check(relocator);

    (void) get_vtable_base_sizes(relocator->is_32_bit, 
        &vtable_entry_size, &vtable_header_size);

    /* Count the number of entries (the vtable is null-terminated) */

    entry_offset = vtable_header_size;
    while (1) {
        entry_value = kxld_relocator_get_pointer_at_addr(relocator,
            vtable->vtable, entry_offset);
        if (!entry_value) break;

        entry_offset += vtable_entry_size;
        ++nentries;
    }

    /* Allocate the symbol index */

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), nentries);
    require_noerr(rval, finish);

    /* Look up the symbols for each entry */

    for (i = 0, entry_offset = vtable_header_size; 
         i < vtable->entries.nitems; 
         ++i, entry_offset += vtable_entry_size) 
    {
        entry_value = kxld_relocator_get_pointer_at_addr(relocator,
            vtable->vtable, entry_offset);

        /* If we can't find the symbol, it means that the virtual function was
         * defined inline.  There's not much I can do about this; it just means
         * I can't patch this function.
         */
        tmpentry = kxld_array_get_item(&vtable->entries, i);
        sym = kxld_dict_find(defined_cxx_symbols, &entry_value);

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
init_by_entries_and_relocs(KXLDVTable *vtable, const KXLDSym *vtable_sym, 
    const KXLDRelocator *relocator, const KXLDArray *relocs,
    const KXLDDict *defined_cxx_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    KXLDVTableEntry *tmpentry = NULL;
    KXLDSym *sym = NULL;
    u_int vtable_entry_size = 0;
    u_int vtable_header_size = 0;
    kxld_addr_t entry_value = 0;
    u_long entry_offset = 0;
    u_int nentries = 0;
    u_int i = 0;
    char *demangled_name1 = NULL;
    size_t demangled_length1 = 0;

    check(vtable);
    check(vtable_sym);
    check(relocator);
    check(relocs);

    /* Find the first entry and its offset past the vtable padding */

    (void) get_vtable_base_sizes(relocator->is_32_bit, 
        &vtable_entry_size, &vtable_header_size);

    /* In a final linked image, a vtable slot is valid if it is nonzero
     * (meaning the userspace linker has already resolved it) or if it has
     * a relocation entry.  We'll know the end of the vtable when we find a
     * slot that meets neither of these conditions.
     */
    entry_offset = vtable_header_size;
    while (1) {
        entry_value = kxld_relocator_get_pointer_at_addr(relocator,
            vtable->vtable, entry_offset);
        if (!entry_value) {
            reloc = kxld_reloc_get_reloc_by_offset(relocs, 
                vtable_sym->base_addr + entry_offset);
            if (!reloc) break;
        }

        ++nentries;
        entry_offset += vtable_entry_size;
    }

    /* Allocate the symbol index */

    rval = kxld_array_init(&vtable->entries, sizeof(KXLDVTableEntry), nentries);
    require_noerr(rval, finish);

    /* Find the symbols for each vtable entry */

    for (i = 0, entry_offset = vtable_header_size; 
         i < vtable->entries.nitems; 
         ++i, entry_offset += vtable_entry_size) 
    {
        entry_value = kxld_relocator_get_pointer_at_addr(relocator,
            vtable->vtable, entry_offset);

        /* If we can't find a symbol, it means it is a locally-defined,
         * non-external symbol that has been stripped.  We don't patch over
         * locally-defined symbols, so we leave the symbol as NULL and just
         * skip it.  We won't be able to patch subclasses with this symbol,
         * but there isn't much we can do about that.
         */
        if (entry_value) {
            reloc = NULL;
            sym = kxld_dict_find(defined_cxx_symbols, &entry_value);
        } else {
            reloc = kxld_reloc_get_reloc_by_offset(relocs,
                vtable_sym->base_addr + entry_offset);
            require_action(reloc, finish,
                rval=KERN_FAILURE;
                kxld_log(kKxldLogPatching, kKxldLogErr, 
                    kKxldLogMalformedVTable, 
                    kxld_demangle(vtable->name, &demangled_name1, 
                        &demangled_length1)));
        
            sym = kxld_reloc_get_symbol(relocator, reloc, /* data */ NULL);
        }

        tmpentry = kxld_array_get_item(&vtable->entries, i);
        tmpentry->unpatched.reloc = reloc;
        tmpentry->unpatched.sym = sym;
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
*******************************************************************************/
KXLDVTableEntry * 
kxld_vtable_get_entry_for_offset(const KXLDVTable *vtable, u_long offset, 
    boolean_t is_32_bit)
{
    KXLDVTableEntry *rval = NULL;
    u_int vtable_entry_size = 0;
    u_int vtable_header_size = 0;
    u_int vtable_entry_idx = 0;

    (void) get_vtable_base_sizes(is_32_bit, 
        &vtable_entry_size, &vtable_header_size);

    if (offset % vtable_entry_size) {
        goto finish;
    }

    vtable_entry_idx = (u_int) ((offset - vtable_header_size) / vtable_entry_size);
    rval = kxld_array_get_item(&vtable->entries, vtable_entry_idx);
finish:
    return rval;
}

/*******************************************************************************
* Patching vtables allows us to preserve binary compatibility across releases.
*******************************************************************************/
kern_return_t
kxld_vtable_patch(KXLDVTable *vtable, const KXLDVTable *super_vtable,
    KXLDObject *object)
{
    kern_return_t rval = KERN_FAILURE;
    const KXLDSymtab *symtab = NULL;
    const KXLDSym *sym = NULL;
    KXLDVTableEntry *child_entry = NULL;
    KXLDVTableEntry *parent_entry = NULL;
    u_int symindex = 0;
    u_int i = 0;
    char *demangled_name1 = NULL;
    char *demangled_name2 = NULL;
    char *demangled_name3 = NULL;
    size_t demangled_length1 = 0;
    size_t demangled_length2 = 0;
    size_t demangled_length3 = 0;
    boolean_t failure = FALSE;

    check(vtable);
    check(super_vtable);

    symtab = kxld_object_get_symtab(object);

    require_action(!vtable->is_patched, finish, rval=KERN_SUCCESS);
    require_action(super_vtable->is_patched, finish, rval=KERN_FAILURE);
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

        if (kxld_object_target_supports_strict_patching(object) && 
            !kxld_sym_is_defined(child_entry->unpatched.sym))
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
                failure = TRUE;
                kxld_log(kKxldLogPatching, kKxldLogErr,
                    "The %s is unpatchable because its class declares the "
                    "method '%s' without providing an implementation.",
                    kxld_demangle(vtable->name,
                        &demangled_name1, &demangled_length1),
                    kxld_demangle(child_entry->unpatched.sym->name,
                        &demangled_name2, &demangled_length2));
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

        sym = kxld_symtab_get_locally_defined_symbol_by_name(symtab, 
            parent_entry->patched.name);
        if (!sym) {
            rval = kxld_object_add_symbol(object, parent_entry->patched.name,
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

        rval = kxld_object_patch_symbol(object, child_entry->unpatched.sym);
        require_noerr(rval, finish);

        child_entry->unpatched.sym = sym;

        /*
         * The C++ ABI requires that functions be aligned on a 2-byte boundary:
         * http://www.codesourcery.com/public/cxx-abi/abi.html#member-pointers
         * If the LSB of any virtual function's link address is 1, then the
         * compiler has violated that part of the ABI, and we're going to panic
         * in _ptmf2ptf() (in OSMetaClass.h). Better to panic here with some
         * context.
         */
        assert(kxld_sym_is_pure_virtual(sym) || !(sym->link_addr & 1)); 
    }

    require_action(!failure, finish, rval=KERN_FAILURE);

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

