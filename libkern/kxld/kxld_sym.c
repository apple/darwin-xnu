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
#include <stdint.h>
#include <sys/types.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_sect.h"
#include "kxld_sym.h"
#include "kxld_util.h"

#define CXX_PREFIX                      "__Z"
#define VTABLE_PREFIX                   CXX_PREFIX "TV"
#define OSOBJ_PREFIX                    CXX_PREFIX "N"
#define RESERVED_TOKEN                  "_RESERVED"
#define METACLASS_TOKEN                 "10gMetaClassE"
#define SUPER_METACLASS_POINTER_TOKEN   "10superClassE"
#define METACLASS_VTABLE_PREFIX         VTABLE_PREFIX "N"
#define METACLASS_VTABLE_SUFFIX         "9MetaClassE"
#define CXX_PURE_VIRTUAL                "___cxa_pure_virtual"
#define FINAL_CLASS_TOKEN               "14__OSFinalClassEv"

/*******************************************************************************
* Prototypes
*******************************************************************************/

static kern_return_t init_predicates(KXLDSym *sym, u_char n_type, u_short n_desc)
    __attribute__((nonnull));
static void init_sym_sectnum(KXLDSym *sym, u_int n_sect)
    __attribute__((nonnull));
static kern_return_t extract_inner_string(const char *str, const char *prefix, 
    const char *suffix, char *buf, u_long len);

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_init_from_macho32(KXLDSym *sym, char *strtab, const struct nlist *src) 
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);
    check(strtab);
    check(src);

    bzero(sym, sizeof(*sym));
    sym->name = strtab + src->n_un.n_strx;
    sym->type = src->n_type;
    sym->desc = src->n_desc;
    sym->base_addr = src->n_value;
    sym->link_addr = sym->base_addr;
    
    rval = init_predicates(sym, src->n_type, src->n_desc);
    require_noerr(rval, finish);

    (void) init_sym_sectnum(sym, src->n_sect);

    if (kxld_sym_is_indirect(sym)) {
        sym->alias = strtab + src->n_value;
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
kxld_sym_init_from_macho64(KXLDSym *sym, char *strtab, const struct nlist_64 *src) 
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);
    check(strtab);
    check(src);

    bzero(sym, sizeof(*sym));
    sym->name = strtab + src->n_un.n_strx;
    sym->type = src->n_type;
    sym->desc = src->n_desc;
    sym->base_addr = src->n_value;
    sym->link_addr = sym->base_addr;

    rval = init_predicates(sym, src->n_type, src->n_desc);
    require_noerr(rval, finish);

    (void) init_sym_sectnum(sym, src->n_sect);

    if (kxld_sym_is_indirect(sym)) {
        sym->alias = strtab + src->n_value;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
void 
kxld_sym_init_absolute(KXLDSym *sym, char *name, kxld_addr_t link_addr)
{
    check(sym);
    check(name);

    bzero(sym, sizeof(*sym));

    sym->name = name;
    sym->link_addr = link_addr;
    sym->type = N_ABS | N_EXT;
    sym->sectnum = NO_SECT;

    init_predicates(sym, N_ABS | N_EXT, 0);
    sym->is_resolved = TRUE;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_predicates(KXLDSym *sym, u_char n_type, u_short n_desc)
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);

    /* The type field is interpreted differently for normal symbols and stabs */
    if (n_type & N_STAB) {
        sym->is_stab = 1;

        switch (n_type) {
        /* Labeled as NO_SECT in stab.h */
        case N_GSYM:
        case N_FNAME:
        case N_RSYM:
        case N_SSYM:
        case N_LSYM:
        case N_BINCL:
        case N_PARAMS:
        case N_VERSION:
        case N_OLEVEL:
        case N_PSYM:
        case N_EINCL:
        case N_EXCL:
        case N_BCOMM:
        case N_LENG:
        case N_OPT:
        case N_OSO:
            sym->is_absolute = 1;
            break;
        /* Labeled as n_sect in stab.h */
        case N_FUN:
        case N_STSYM:
        case N_LCSYM:
        case N_BNSYM:
        case N_SLINE:
        case N_ENSYM:
        case N_SO:
        case N_SOL:
        case N_ENTRY:
        case N_ECOMM:
        case N_ECOML:
        /* These are labeled as NO_SECT in stab.h, but they are actually
         * section-based on OS X.  We must mark them as such so they get
         * relocated.
         */
        case N_RBRAC:
        case N_LBRAC:
            sym->is_section = 1;
            break;
        default:
            rval = KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                "Invalid N_STAB symbol type: %u.", n_type);
            goto finish;
        }
            
        /* Don't care about the C++ predicates for stabs */

    } else {
        u_char type = n_type & N_TYPE;

        /* The first set of type fields are mutually exclusive, so they can be
         * set with a switch statement.
         */
        switch (type) {
        case N_ABS:
            sym->is_absolute = 1;
            break;
        case N_SECT:
            sym->is_section = 1;
            break;
        case N_UNDF:
            if (sym->base_addr) {
                sym->is_common = 1;
            } else {
                sym->is_undefined = 1;
            }
            break;
        case N_INDR:
            sym->is_indirect = 1;
            break;
        default:
            rval = KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                "Invalid symbol type: %u.", type);
            goto finish;
        }

        /* Set the type-independent fields */
        if ((n_type & N_EXT) && !(n_type & N_PEXT)) {
            sym->is_external = 1;
        }

        if (n_desc & N_DESC_DISCARDED) {
            sym->is_obsolete = 1;
        }

        if (n_desc & N_WEAK_REF) {
           sym->is_weak = 1;
        }

        if (n_desc & N_ARM_THUMB_DEF) {
           sym->is_thumb = 1;
           sym->base_addr |= 1;
           sym->link_addr |= 1;
        }

        /* Set the C++-specific fields */
        if ((streq_safe(CXX_PREFIX, sym->name, const_strlen(CXX_PREFIX)))) {
            sym->is_cxx = 1;

            if (streq_safe(sym->name, METACLASS_VTABLE_PREFIX, 
                const_strlen(METACLASS_VTABLE_PREFIX)))
            {
                sym->is_meta_vtable = 1;
            } else if (streq_safe(sym->name, VTABLE_PREFIX, 
                const_strlen(VTABLE_PREFIX))) 
            {
                sym->is_class_vtable = 1;
            } else if (kxld_strstr(sym->name, RESERVED_TOKEN)) {
                sym->is_padslot = 1;
            } else if (kxld_strstr(sym->name, METACLASS_TOKEN)) {
                sym->is_metaclass = 1;
            } else if (kxld_strstr(sym->name, SUPER_METACLASS_POINTER_TOKEN)) {
                sym->is_super_metaclass_pointer = 1;
            }
        } else if (kxld_sym_name_is_pure_virtual(sym->name)) {
            sym->is_cxx = 1;
            sym->is_pure_virtual = 1;
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static void
init_sym_sectnum(KXLDSym *sym, u_int n_sect)
{
    /* The n_sect field is set to 0 when the symbol is not section-based, and
     * the number of the section in which the symbol exists otherwise.
     * Sometimes, symbols can be labeled as section-based, so we make sure that
     * they have a valid section number, and set them as absolute if they don't.
     */

    if (kxld_sym_is_section(sym)) {
        if (n_sect) {
            /* Convert the section number to an index into the section index */
            sym->sectnum = n_sect - 1;
        } else {
            sym->is_absolute = 1;
            sym->is_section = 0;
        }
    }

}

/*******************************************************************************
*******************************************************************************/
void
kxld_sym_deinit(KXLDSym *sym __unused)
{
    check(sym);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_sym_destroy(KXLDSym *sym)
{
    check(sym);
    kxld_sym_deinit(sym);
    kxld_free(sym, sizeof(*sym));
}


/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_absolute(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_absolute);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_section(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_section);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_defined(const KXLDSym *sym)
{
    check(sym);

    return ((kxld_sym_is_absolute(sym) || kxld_sym_is_section(sym)) && 
        !kxld_sym_is_replaced(sym));
}


/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_defined_locally(const KXLDSym *sym)
{
    check(sym);

    return (kxld_sym_is_defined(sym) && !sym->is_resolved);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_external(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_external);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_exported(const KXLDSym *sym)
{
    check(sym);

    return (kxld_sym_is_defined_locally(sym) && kxld_sym_is_external(sym));
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_undefined(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_undefined);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_indirect(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_indirect);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_replaced(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_replaced);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_common(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_common);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_unresolved(const KXLDSym *sym)
{
    return ((kxld_sym_is_undefined(sym) && !kxld_sym_is_replaced(sym)) ||
            kxld_sym_is_indirect(sym) || kxld_sym_is_common(sym));
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_obsolete(const KXLDSym *sym)
{
    return (0 != sym->is_obsolete);
}

#if KXLD_USER_OR_GOT
/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_got(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_got);
}
#endif /* KXLD_USER_OR_GOT */

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_stab(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_stab);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_weak(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_weak);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_cxx(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_cxx);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_pure_virtual(const KXLDSym *sym)
{
    return (0 != sym->is_pure_virtual);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_vtable(const KXLDSym *sym)
{
    check(sym);

    return kxld_sym_is_class_vtable(sym) || kxld_sym_is_metaclass_vtable(sym);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_class_vtable(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_class_vtable);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_metaclass_vtable(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_meta_vtable);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_padslot(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_padslot);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_metaclass(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_metaclass);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_is_super_metaclass_pointer(const KXLDSym *sym)
{
    check(sym);

    return (0 != sym->is_super_metaclass_pointer);
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_name_is_pure_virtual(const char *name)
{
    return streq_safe(CXX_PURE_VIRTUAL, name, sizeof(CXX_PURE_VIRTUAL));
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_sym_name_is_padslot(const char *name)
{
    check(name);

    return (kxld_strstr(name, RESERVED_TOKEN) != 0);
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_sym_get_section_offset(const KXLDSym *sym, const KXLDSect *sect)
{
    check(sym);

    return (u_int) (sym->base_addr - sect->base_addr);
}

#if KXLD_USER_OR_COMMON
/*******************************************************************************
*******************************************************************************/
kxld_size_t
kxld_sym_get_common_size(const KXLDSym *sym)
{
    return sym->base_addr;
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_sym_get_common_align(const KXLDSym *sym)
{
    u_int align = GET_COMM_ALIGN(sym->desc);
    if (!align) align = 3;

    return align;
}
#endif /* KXLD_USER_OR_COMMON */

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_get_class_name_from_metaclass(const KXLDSym *sym,
    char class_name[], u_long class_name_len)
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);
    require_action(kxld_sym_is_metaclass(sym), finish, rval=KERN_FAILURE);

    rval = extract_inner_string(sym->name, OSOBJ_PREFIX, METACLASS_TOKEN, 
        class_name, class_name_len);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_get_class_name_from_super_metaclass_pointer(const KXLDSym *sym,
    char class_name[], u_long class_name_len)
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);
    require_action(kxld_sym_is_super_metaclass_pointer(sym), finish, 
        rval=KERN_FAILURE);

    rval = extract_inner_string(sym->name, OSOBJ_PREFIX, 
        SUPER_METACLASS_POINTER_TOKEN, class_name, class_name_len);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_get_class_name_from_vtable(const KXLDSym *sym,
    char class_name[], u_long class_name_len)
{
    kern_return_t rval = KERN_FAILURE;
    
    check(sym);
    require_action(kxld_sym_is_class_vtable(sym), finish, rval=KERN_FAILURE);

    rval = kxld_sym_get_class_name_from_vtable_name(sym->name,
        class_name, class_name_len);
    require_noerr(rval, finish);
    
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_sym_get_class_name_from_vtable_name(const char *vtable_name,
    char class_name[], u_long class_name_len)
{
    kern_return_t rval = KERN_FAILURE;

    check(vtable_name);

    rval = extract_inner_string(vtable_name, VTABLE_PREFIX, NULL,
        class_name, class_name_len);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_get_vtable_name_from_class_name(const char *class_name, 
    char vtable_name[], u_long vtable_name_len)
{
    kern_return_t rval = KERN_FAILURE;
    u_long outlen = 0;

    check(class_name);
    check(vtable_name);

    outlen = strlcpy(vtable_name, VTABLE_PREFIX, vtable_name_len);
    require_action(outlen < vtable_name_len, finish, 
        rval=KERN_FAILURE);

    outlen = strlcat(vtable_name, class_name, vtable_name_len);
    require_action(outlen < vtable_name_len, finish, 
        rval=KERN_FAILURE);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_get_meta_vtable_name_from_class_name(const char *class_name, 
    char meta_vtable_name[], u_long meta_vtable_name_len)
{
    kern_return_t rval = KERN_FAILURE;
    u_long outlen = 0;

    check(class_name);
    check(meta_vtable_name);

    outlen = strlcpy(meta_vtable_name, METACLASS_VTABLE_PREFIX,
        meta_vtable_name_len);
    require_action(outlen < meta_vtable_name_len, finish,
        rval=KERN_FAILURE);

    outlen = strlcat(meta_vtable_name, class_name, meta_vtable_name_len);
    require_action(outlen < meta_vtable_name_len, finish, 
        rval=KERN_FAILURE);

    outlen = strlcat(meta_vtable_name, METACLASS_VTABLE_SUFFIX, 
        meta_vtable_name_len);
    require_action(outlen < meta_vtable_name_len, finish, 
        rval=KERN_FAILURE);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_get_final_sym_name_from_class_name(const char *class_name, 
    char final_sym_name[], u_long final_sym_name_len)
{
    kern_return_t rval = KERN_FAILURE;
    u_long outlen = 0;

    check(class_name);
    check(final_sym_name);

    outlen = strlcpy(final_sym_name, OSOBJ_PREFIX, final_sym_name_len);
    require_action(outlen < final_sym_name_len, finish, 
        rval=KERN_FAILURE);

    outlen = strlcat(final_sym_name, class_name, final_sym_name_len);
    require_action(outlen < final_sym_name_len, finish, 
        rval=KERN_FAILURE);

    outlen = strlcat(final_sym_name, FINAL_CLASS_TOKEN, final_sym_name_len);
    require_action(outlen < final_sym_name_len, finish, 
        rval=KERN_FAILURE);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_sym_get_function_prefix_from_class_name(const char *class_name,
    char function_prefix[], u_long function_prefix_len)
{
    u_long rval = 0;
    u_long outlen = 0;

    check(class_name);
    check(function_prefix);

    outlen = strlcpy(function_prefix, OSOBJ_PREFIX, function_prefix_len);
    require(outlen < function_prefix_len, finish);

    outlen = strlcat(function_prefix, class_name, function_prefix_len);
    require(outlen < function_prefix_len, finish);

    rval = outlen;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
extract_inner_string(const char *str, const char *prefix, const char *suffix, 
    char *buf, u_long len)
{
    kern_return_t rval = KERN_FAILURE;
    u_long prelen = 0, suflen = 0, striplen = 0;

    check(str);
    check(buf);

    prelen = (prefix) ? strlen(prefix) : 0;
    suflen = (suffix) ? strlen(suffix) : 0;
    striplen = strlen(str) - prelen - suflen;

    require_action(striplen < len, finish, rval=KERN_FAILURE);

    strncpy(buf, str + prelen, striplen);
    buf[striplen] = '\0';

    rval = KERN_SUCCESS;
finish:
    return rval;
}

#if KXLD_USER_OR_GOT
/*******************************************************************************
*******************************************************************************/
void
kxld_sym_set_got(KXLDSym *sym)
{
    sym->is_got = 1;
}
#endif /* KXLD_USER_OR_GOT */

/*******************************************************************************
*******************************************************************************/
void
kxld_sym_relocate(KXLDSym *sym, const KXLDSect *sect)
{
    if (kxld_sym_is_section(sym)) {
        sym->link_addr = sym->base_addr - sect->base_addr + sect->link_addr;
        sym->relocated_sectnum = sect->sectnum;
    }
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_export_macho_32(const KXLDSym *sym, u_char *_nl, char *strtab, 
    u_long *stroff, u_long strsize)
{
    kern_return_t rval = KERN_FAILURE;
    struct nlist *nl = (struct nlist *) ((void *) _nl);
    char *str = NULL;
    long bytes = 0;

    check(sym);
    check(nl);
    check(strtab);
    check(stroff);

    bytes = strlen(sym->name) + 1;
    require_action((u_long)bytes <= strsize - *stroff, finish,
        rval = KERN_FAILURE);

    nl->n_type = sym->type;
    nl->n_sect = (kxld_sym_is_section(sym)) ? sym->relocated_sectnum + 1 : 0;
    nl->n_desc = sym->desc;
    nl->n_un.n_strx = (uint32_t) *stroff;
    nl->n_value = (uint32_t) sym->link_addr;
    if (sym->is_thumb) {
        nl->n_value &= ~0x1U;
    }

    str = (char *) (strtab + *stroff);
    strlcpy(str, sym->name, strsize - *stroff);

    *stroff += bytes;
    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_export_macho_64(const KXLDSym *sym, u_char *_nl, char *strtab,
    u_long *stroff, u_long strsize)
{
    kern_return_t rval = KERN_FAILURE;
    struct nlist_64 *nl = (struct nlist_64 *) ((void *) _nl);
    char *str = NULL;
    long bytes = 0;

    check(sym);
    check(nl);
    check(strtab);
    check(stroff);

    bytes = strlen(sym->name) + 1;
    require_action((u_long)bytes <= strsize - *stroff, finish,
        rval = KERN_FAILURE);

    nl->n_type = sym->type;
    nl->n_sect = (kxld_sym_is_section(sym)) ? sym->relocated_sectnum + 1 : 0;
    nl->n_desc = sym->desc;
    nl->n_un.n_strx = (uint32_t) *stroff;
    nl->n_value = (uint64_t) sym->link_addr;
    if (sym->is_thumb) {
        nl->n_value &= ~0x1ULL;
    }

    str = (char *) (strtab + *stroff);
    strlcpy(str, sym->name, strsize - *stroff);

    *stroff += bytes;
    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_resolve(KXLDSym *sym, kxld_addr_t addr) 
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);

    require_action(kxld_sym_is_undefined(sym) || kxld_sym_is_indirect(sym), 
        finish, rval=KERN_FAILURE);

    /* Set the n_list data types */

    sym->link_addr = addr;
    sym->type = N_ABS | N_EXT;
    sym->sectnum = NO_SECT;
 
    /* Set the predicate bits for an externally resolved symbol. */
    
    sym->is_external = TRUE;
    sym->is_absolute = TRUE;
    sym->is_resolved = TRUE;

    /* Clear the predicate bits for types that can be resolved */

    sym->is_undefined = FALSE;
    sym->is_indirect = FALSE;

    rval = KERN_SUCCESS;

finish:

    return rval;
}

#if KXLD_USER_OR_COMMON
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sym_resolve_common(KXLDSym *sym, u_int sectnum, kxld_addr_t base_addr)
{
    kern_return_t rval = KERN_FAILURE;

    check(sym);

    require_action(kxld_sym_is_common(sym), finish, 
        rval=KERN_FAILURE);

    sym->base_addr = base_addr;
    sym->link_addr = base_addr;
    sym->type = N_SECT | N_EXT;
    sym->sectnum = sectnum;
    sym->desc = 0;

    sym->is_absolute = FALSE;
    sym->is_section = TRUE;
    sym->is_undefined = FALSE;
    sym->is_indirect = FALSE;
    sym->is_common = FALSE;
    sym->is_external = TRUE;

    rval = KERN_SUCCESS;

finish:

    return rval;
}
#endif /* KXLD_USER_OR_COMMON */

/*******************************************************************************
*******************************************************************************/
void
kxld_sym_delete(KXLDSym *sym)
{
    check(sym);

    bzero(sym, sizeof(*sym));
    sym->is_replaced = TRUE;
}


/*******************************************************************************
*******************************************************************************/
void
kxld_sym_patch(KXLDSym *sym)
{
    check(sym);

    sym->is_replaced = TRUE;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_sym_mark_private(KXLDSym *sym)
{
    check(sym);

    sym->type |= N_PEXT;
    sym->is_external = FALSE;
}

