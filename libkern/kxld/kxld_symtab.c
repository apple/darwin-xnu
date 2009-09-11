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
#include <mach-o/nlist.h>
#include <sys/queue.h>
#include <sys/types.h>

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_array.h"
#include "kxld_dict.h"
#include "kxld_sect.h"
#include "kxld_sym.h"
#include "kxld_symtab.h"
#include "kxld_util.h"

struct kxld_symtab {
    KXLDArray syms;
    KXLDDict cxx_index;
    KXLDDict name_index;
    char *strings;
    u_int strsize;
};

/*******************************************************************************
* Prototypes
*******************************************************************************/

static kern_return_t init_macho(KXLDSymtab *symtab, u_char *macho, 
    struct symtab_command *src, kxld_addr_t linkedit_offset, boolean_t is_32_bit)
    __attribute__((nonnull));

#if KXLD_USER_OR_ILP32
static kern_return_t init_syms_32(KXLDSymtab *symtab, u_char *macho, u_long offset, 
    u_int nsyms);
#endif
#if KXLD_USER_OR_LP64
static kern_return_t init_syms_64(KXLDSymtab *symtab, u_char *macho, u_long offset, 
    u_int nsyms);
#endif

static kern_return_t make_cxx_index(KXLDSymtab *symtab)
    __attribute__((nonnull));
static boolean_t sym_is_defined_cxx(const KXLDSym *sym);
static kern_return_t make_name_index(KXLDSymtab *symtab)
    __attribute__((nonnull));
static boolean_t sym_is_name_indexed(const KXLDSym *sym);


/*******************************************************************************
*******************************************************************************/
size_t
kxld_symtab_sizeof()
{
    return sizeof(KXLDSymtab);
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_symtab_init_from_macho_32(KXLDSymtab *symtab, u_char *macho, 
    struct symtab_command *src, kxld_addr_t linkedit_offset)
{
    return init_macho(symtab, macho, src, linkedit_offset, TRUE);
}
#endif /* KXLD_USER_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_symtab_init_from_macho_64(KXLDSymtab *symtab, u_char *macho, 
    struct symtab_command *src, kxld_addr_t linkedit_offset)
{
    return init_macho(symtab, macho, src, linkedit_offset, FALSE);
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_macho(KXLDSymtab *symtab, u_char *macho, struct symtab_command *src,
    kxld_addr_t linkedit_offset, boolean_t is_32_bit __unused)
{
    kern_return_t rval = KERN_FAILURE;

    check(symtab);
    check(macho);
    check(src);

    /* Initialize the symbol array */

    rval = kxld_array_init(&symtab->syms, sizeof(KXLDSym), src->nsyms);
    require_noerr(rval, finish);

    /* Initialize the string table */

    symtab->strings = (char *) (macho + src->stroff + linkedit_offset);
    symtab->strsize = src->strsize;

    /* Initialize the symbols */

    KXLD_3264_FUNC(is_32_bit, rval,
        init_syms_32, init_syms_64,
        symtab, macho, (u_long) (src->symoff + linkedit_offset), src->nsyms);
    require_noerr(rval, finish);
       
    /* Create the C++ index */

    rval = make_cxx_index(symtab);
    require_noerr(rval, finish);

    /* Create the name index */

    rval = make_name_index(symtab);
    require_noerr(rval, finish);

    /* Save the output */

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_syms_32(KXLDSymtab *symtab, u_char *macho, u_long offset, u_int nsyms)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSym *sym = NULL;
    u_int i = 0;
    struct nlist *src_syms = (struct nlist *) (macho + offset);

    for (i = 0; i < nsyms; ++i) {
        sym = kxld_array_get_item(&symtab->syms, i);
        require_action(sym, finish, rval=KERN_FAILURE);

        rval = kxld_sym_init_from_macho32(sym, symtab->strings, &src_syms[i]);
        require_noerr(rval, finish);
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
init_syms_64(KXLDSymtab *symtab, u_char *macho, u_long offset, u_int nsyms)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSym *sym = NULL;
    u_int i = 0;
    struct nlist_64 *src_syms = (struct nlist_64 *) (macho + offset);

    for (i = 0; i < nsyms; ++i) {
        sym = kxld_array_get_item(&symtab->syms, i);
        require_action(sym, finish, rval=KERN_FAILURE);

        rval = kxld_sym_init_from_macho64(sym, symtab->strings, &src_syms[i]);
        require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
void
kxld_symtab_iterator_init(KXLDSymtabIterator *iter, const KXLDSymtab *symtab,
    KXLDSymPredicateTest test, boolean_t negate)
{
    check(iter);
    check(symtab);
    check(test);

    iter->symtab = symtab;
    iter->idx = 0;
    iter->test = test;
    iter->negate = negate;
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_symtab_clear(KXLDSymtab *symtab)
{
    check(symtab);

    kxld_array_clear(&symtab->syms);
    kxld_dict_clear(&symtab->cxx_index);
    kxld_dict_clear(&symtab->name_index);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_symtab_deinit(KXLDSymtab *symtab)
{
    check(symtab);

    kxld_array_deinit(&symtab->syms);
    kxld_dict_deinit(&symtab->cxx_index);
    kxld_dict_deinit(&symtab->name_index);
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_symtab_get_num_symbols(const KXLDSymtab *symtab)
{
    check(symtab);

    return symtab->syms.nitems;
}

/*******************************************************************************
*******************************************************************************/
KXLDSym *
kxld_symtab_get_symbol_by_index(const KXLDSymtab *symtab, u_int idx)
{
    check(symtab);

    return kxld_array_get_item(&symtab->syms, idx);
}

/*******************************************************************************
*******************************************************************************/
KXLDSym *
kxld_symtab_get_symbol_by_name(const KXLDSymtab *symtab, const char *name)
{
    check(symtab);
    check(name);

    return kxld_dict_find(&symtab->name_index, name);
}

/*******************************************************************************
*******************************************************************************/
KXLDSym *
kxld_symtab_get_cxx_symbol_by_value(const KXLDSymtab *symtab, kxld_addr_t value)
{
    check(symtab);

    /*
     * value may hold a THUMB address (with bit 0 set to 1) but the index will
     * have the real address (bit 0 set to 0).  So if bit 0 is set here,
     * we clear it (should impact no architectures but ARM).
     */
    kxld_addr_t v = value & ~1;

    return kxld_dict_find(&symtab->cxx_index, &v);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_symtab_get_sym_index(const KXLDSymtab *symtab, const KXLDSym *sym,
    u_int *symindex)
{
    kern_return_t rval = KERN_FAILURE;

    rval = kxld_array_get_index(&symtab->syms, sym, symindex);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_symtab_get_macho_header_size(void)
{
    return sizeof(struct symtab_command);
}

/*******************************************************************************
*******************************************************************************/
u_long 
kxld_symtab_get_macho_data_size(const KXLDSymtab *symtab, 
    boolean_t is_link_state, boolean_t is_32_bit)
{
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    u_long size = 1; /* strtab start padding */
    u_int nsyms = 0;
    
    check(symtab); 

    if (is_link_state) {
        kxld_symtab_iterator_init(&iter, symtab, kxld_sym_is_exported, FALSE);
    } else {
        kxld_symtab_iterator_init(&iter, symtab, 
            kxld_sym_is_defined_locally, FALSE);
    }

    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        size += strlen(sym->name) + 1;
        ++nsyms;
    }

    if (is_32_bit) {
        size += nsyms * sizeof(struct nlist);
    } else {
        size += nsyms * sizeof(struct nlist_64);
    }

    return size;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_symtab_export_macho(const KXLDSymtab *symtab, u_char *buf, 
    u_long *header_offset, u_long header_size,
    u_long *data_offset, u_long data_size,
    boolean_t is_link_state, boolean_t is_32_bit)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    struct symtab_command *symtabhdr = NULL;
    u_char *nl = NULL;
    u_long nlistsize = 0;
    char *strtab = NULL;
    u_long stroff = 1; /* strtab start padding */

    check(symtab);
    check(buf);
    check(header_offset);
    check(data_offset);

    require_action(sizeof(*symtabhdr) <= header_size - *header_offset, 
        finish, rval=KERN_FAILURE);
    symtabhdr = (struct symtab_command *) (buf + *header_offset);
    *header_offset += sizeof(*symtabhdr);
    
    /* Initialize the symbol table header */

    symtabhdr->cmd = LC_SYMTAB;
    symtabhdr->cmdsize = (uint32_t) sizeof(*symtabhdr);
    symtabhdr->symoff = (uint32_t) *data_offset;
    symtabhdr->strsize = 1; /* strtab start padding */
    
    /* Find the size of the symbol and string tables */

    if (is_link_state) {
        kxld_symtab_iterator_init(&iter, symtab, kxld_sym_is_exported, FALSE);
    } else {
        kxld_symtab_iterator_init(&iter, symtab, 
            kxld_sym_is_defined_locally, FALSE);
    }

    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        symtabhdr->nsyms++;
        symtabhdr->strsize += (uint32_t) (strlen(sym->name) + 1);
    }

    if (is_32_bit) {
        nlistsize = sizeof(struct nlist);
    } else {
        nlistsize = sizeof(struct nlist_64);
    }

    symtabhdr->stroff = (uint32_t) (symtabhdr->symoff + 
        (symtabhdr->nsyms * nlistsize));
    require_action(symtabhdr->stroff + symtabhdr->strsize <= data_size, finish,
        rval=KERN_FAILURE);

    /* Get pointers to the symbol and string tables */

    nl = buf + symtabhdr->symoff;
    strtab = (char *) (buf + symtabhdr->stroff);

    /* Copy over the symbols */

    kxld_symtab_iterator_reset(&iter);
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {

        KXLD_3264_FUNC(is_32_bit, rval,
            kxld_sym_export_macho_32, kxld_sym_export_macho_64,
            sym, nl, strtab, &stroff, symtabhdr->strsize, is_link_state);
        require_noerr(rval, finish);

        nl += nlistsize;
        stroff += rval;
    }

    /* Update the data offset */
    *data_offset += (symtabhdr->nsyms * nlistsize) + stroff;

    rval = KERN_SUCCESS;
    
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_symtab_iterator_get_num_remaining(const KXLDSymtabIterator *iter)
{
    u_int idx = 0;
    u_int count = 0;

    check(iter);

    idx = iter->idx;

    for (idx = iter->idx; idx < iter->symtab->syms.nitems; ++idx) {
        count += iter->test(kxld_array_get_item(&iter->symtab->syms, idx));
    }

    return count;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
make_cxx_index(KXLDSymtab *symtab)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    u_int nsyms = 0;

    check(symtab);

    /* Count the number of C++ symbols */
    kxld_symtab_iterator_init(&iter, symtab, sym_is_defined_cxx, FALSE);
    nsyms = kxld_symtab_iterator_get_num_remaining(&iter);

    /* Create the dictionary */
    rval = kxld_dict_init(&symtab->cxx_index, kxld_dict_kxldaddr_hash, 
        kxld_dict_kxldaddr_cmp, nsyms);
    require_noerr(rval, finish);

    /* Insert the non-stab symbols */
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        rval = kxld_dict_insert(&symtab->cxx_index, &sym->base_addr, sym);
        require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t
sym_is_defined_cxx(const KXLDSym *sym)
{
    return (kxld_sym_is_defined_locally(sym) && kxld_sym_is_cxx(sym));
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
make_name_index(KXLDSymtab *symtab)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    u_int nsyms = 0;

    check(symtab);

    /* Count the number of symbols we need to index by name */
    kxld_symtab_iterator_init(&iter, symtab, sym_is_name_indexed, FALSE);
    nsyms = kxld_symtab_iterator_get_num_remaining(&iter);

    /* Create the dictionary */
    rval = kxld_dict_init(&symtab->name_index, kxld_dict_string_hash, 
        kxld_dict_string_cmp, nsyms);
    require_noerr(rval, finish);

    /* Insert the non-stab symbols */
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        rval = kxld_dict_insert(&symtab->name_index, sym->name, sym);
        require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t
sym_is_name_indexed(const KXLDSym *sym)
{
    return (kxld_sym_is_vtable(sym)                     ||
        streq_safe(sym->name, KXLD_KMOD_INFO_SYMBOL, 
            const_strlen(KXLD_KMOD_INFO_SYMBOL))        ||
        streq_safe(sym->name, KXLD_WEAK_TEST_SYMBOL,
            const_strlen(KXLD_WEAK_TEST_SYMBOL)));
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_symtab_relocate(KXLDSymtab *symtab, const KXLDArray *sectarray)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    const KXLDSect *sect = NULL;
    
    check(symtab);
    check(sectarray);

    kxld_symtab_iterator_init(&iter, symtab, kxld_sym_is_section, FALSE);

    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        sect = kxld_array_get_item(sectarray, sym->sectnum);
        require_action(sect, finish, rval=KERN_FAILURE);
        kxld_sym_relocate(sym, sect);
    }

    rval = KERN_SUCCESS;

finish:

    return rval;
}

/*******************************************************************************
* This extends the symbol table and initializes the new symbol.  We insert the
* symbol into the name index, but we don't bother with the c++ value index
* because it is based on the base_addr of the symbol, and the base_addr of
* all synthesized symbols will be 0.
*******************************************************************************/
kern_return_t
kxld_symtab_add_symbol(KXLDSymtab *symtab, char *name, kxld_addr_t link_addr,
    KXLDSym **symout)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSym *sym = NULL;
    u_int symindex = symtab->syms.nitems;

    rval = kxld_array_resize(&symtab->syms, symindex + 1);
    require_noerr(rval, finish);

    sym = kxld_array_get_item(&symtab->syms, symindex);
    kxld_sym_init_absolute(sym, name, link_addr);

    rval = kxld_dict_insert(&symtab->name_index, sym->name, sym);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;
    *symout = sym;
    
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
KXLDSym *
kxld_symtab_iterator_get_next(KXLDSymtabIterator *iter)
{
    KXLDSym *sym = NULL;
    KXLDSym *tmp = NULL;
    boolean_t cmp = FALSE;

    check(iter);

    for (; iter->idx < iter->symtab->syms.nitems; ++iter->idx) {
        tmp = kxld_array_get_item(&iter->symtab->syms, iter->idx);
        cmp = iter->test(tmp);
        if (iter->negate) cmp = !cmp;

        if (cmp) {
            sym = tmp;
            ++iter->idx;
            break;
        }
    }

    return sym;   
}


/*******************************************************************************
*******************************************************************************/
void
kxld_symtab_iterator_reset(KXLDSymtabIterator *iter)
{
    check(iter);
    iter->idx = 0;
}

