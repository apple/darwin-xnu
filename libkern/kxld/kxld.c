/*
 * Copyright (c) 2007-2008 Apple Inc. All rights reserved.
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
#include <sys/types.h>
#include <mach/vm_param.h>  /* For PAGE_SIZE */

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#if !KERNEL
    #include "kxld.h"
    #include "kxld_types.h"
#else 
    #include <libkern/kxld.h>
    #include <libkern/kxld_types.h>
#endif /* KERNEL */

#include "kxld_array.h"
#include "kxld_dict.h"
#include "kxld_kext.h"
#include "kxld_state.h"
#include "kxld_sym.h"
#include "kxld_symtab.h"
#include "kxld_util.h"
#include "kxld_vtable.h"

struct kxld_vtable;

struct kxld_context {
    KXLDKext *kext;
    KXLDArray *section_order;
    KXLDArray deps;
    KXLDArray tmps;
    KXLDDict defined_symbols;
    KXLDDict obsolete_symbols;
    KXLDDict vtables;
    KXLDFlags flags;
    KXLDAllocateCallback allocate_callback;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
};

/*******************************************************************************
* Globals
*******************************************************************************/

/* Certain architectures alter the order of a kext's sections from its input
 * binary, so we track that order in a dictionary of arrays, with one array for
 * each architecture.  Since the kernel only has one architecture, we can
 * eliminate the dictionary and use a simple array.  
 * XXX: If we ever use the linker in a multithreaded environment, we will need 
 * locks around these global structures.
 */
#if KXLD_USER_OR_OBJECT
#if KERNEL
static KXLDArray *s_section_order;
#else
static KXLDDict *s_order_dict;
#endif
#endif

/*******************************************************************************
* Prototypes
*******************************************************************************/

static void clear_context(KXLDContext *context);

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_create_context(KXLDContext **_context, 
    KXLDAllocateCallback allocate_callback, KXLDLoggingCallback logging_callback,
    KXLDFlags flags, cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDContext *context = NULL;
    KXLDArray *section_order = NULL;
#if !KERNEL
    cpu_type_t *cputype_p = NULL;
#endif

    check(_context);
    check(allocate_callback);
    check(logging_callback);
    *_context = NULL;

    context = kxld_alloc(sizeof(*context));
    require_action(context, finish, rval=KERN_RESOURCE_SHORTAGE);
    bzero(context, sizeof(*context));

    context->flags = flags;
    context->allocate_callback = allocate_callback;
    context->cputype = cputype;
    context->cpusubtype = cpusubtype;

    kxld_set_logging_callback(logging_callback);

    context->kext = kxld_alloc(kxld_kext_sizeof());
    require_action(context->kext, finish, rval=KERN_RESOURCE_SHORTAGE);
    bzero(context->kext, kxld_kext_sizeof());

    /* Check if we already have an order array for this arch */

#if KXLD_USER_OR_OBJECT
#if KERNEL   
    context->section_order = s_section_order;
#else
    /* In userspace, create the dictionary if it doesn't already exist */
    if (!s_order_dict) {
        s_order_dict = kxld_alloc(sizeof(*s_order_dict));
        require_action(s_order_dict, finish, rval=KERN_RESOURCE_SHORTAGE);
        bzero(s_order_dict, sizeof(*s_order_dict));

        rval = kxld_dict_init(s_order_dict, kxld_dict_uint32_hash,
            kxld_dict_uint32_cmp, 0);
        require_noerr(rval, finish);
    }

    context->section_order = kxld_dict_find(s_order_dict, &cputype);
#endif /* KERNEL */

    /* Create an order array for this arch if needed */
    
    if (!context->section_order) {

        section_order = kxld_alloc(sizeof(*section_order));
        require_action(section_order, finish, rval=KERN_RESOURCE_SHORTAGE);
        bzero(section_order, sizeof(*section_order));

#if KERNEL
        s_section_order = section_order;
#else
        /* In userspace, add the new array to the order dictionary */
        cputype_p = kxld_alloc(sizeof(*cputype_p));
        require_action(cputype_p, finish, rval=KERN_RESOURCE_SHORTAGE);
        *cputype_p = cputype;

        rval = kxld_dict_insert(s_order_dict, cputype_p, section_order);
        require_noerr(rval, finish);

        cputype_p = NULL;
#endif /* KERNEL */

        context->section_order = section_order;

        section_order = NULL;
    }
#endif /* KXLD_USER_OR_OBJECT */

    rval = KERN_SUCCESS;
    *_context = context;
    context = NULL;

finish:
    if (context) kxld_free(context, sizeof(*context));
    if (section_order) kxld_free(section_order, sizeof(*section_order));
#if !KERNEL
    if (cputype_p) kxld_free(cputype_p, sizeof(*cputype_p));
#endif

    return rval;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_destroy_context(KXLDContext *context)
{
    KXLDState *dep = NULL;
    u_int i = 0;

    check(context);

    kxld_kext_deinit(context->kext);

    for (i = 0; i < context->deps.maxitems; ++i) {
        dep = kxld_array_get_slot(&context->deps, i);
        kxld_state_deinit(dep);
    }

    kxld_array_deinit(&context->deps);
    kxld_array_deinit(&context->tmps);

    kxld_dict_deinit(&context->defined_symbols);
    kxld_dict_deinit(&context->obsolete_symbols);
    kxld_dict_deinit(&context->vtables);

    kxld_free(context->kext, kxld_kext_sizeof());
    kxld_free(context, sizeof(*context));

    kxld_print_memory_report();
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_link_file(
    KXLDContext *context,
    u_char *file,
    u_long size,
    const char *name,
    void *callback_data,
    u_char **deps,
    u_int ndeps,
    u_char **_linked_object,
    kxld_addr_t *kmod_info_kern,
    u_char **_link_state,
    u_long *_link_state_size,
    u_char **_symbol_file __unused,
    u_long *_symbol_file_size __unused)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDState *state = NULL;
    KXLDAllocateFlags flags = 0;
    kxld_addr_t vmaddr = 0;
    u_long header_size = 0;
    u_long vmsize = 0;
    u_int nsyms = 0;
    u_int nvtables = 0;
    u_int i = 0;
    u_char *linked_object = NULL;
    u_char *linked_object_alloc = NULL;
    u_char *link_state = NULL;
    u_char *symbol_file = NULL;
    u_long link_state_size = 0;
    u_long symbol_file_size = 0;

    kxld_set_logging_callback_data(name, callback_data);

    require_action(context, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(file, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(size, finish, rval=KERN_INVALID_ARGUMENT);

    rval = kxld_array_init(&context->deps, sizeof(struct kxld_state), ndeps);
    require_noerr(rval, finish);

    if (deps) {
        /* Initialize the dependencies */
        for (i = 0; i < ndeps; ++i) {
            state = kxld_array_get_item(&context->deps, i);

            rval = kxld_state_init_from_file(state, deps[i], 
                context->section_order);
            require_noerr(rval, finish);
        }
    }

    rval = kxld_kext_init(context->kext, file, size, name, 
        context->flags, (deps == 0) /* is_kernel */, context->section_order, 
        context->cputype, context->cpusubtype);
    require_noerr(rval, finish);

    if (deps) {

        /* Calculate the base number of symbols and vtables in the kext */

        nsyms += kxld_kext_get_num_symbols(context->kext);
        nvtables += kxld_kext_get_num_vtables(context->kext);

        /* Extract the symbol and vtable counts from the dependencies.
         */

        for (i = 0; i < ndeps; ++i) {
            cpu_type_t cputype; 
            cpu_subtype_t cpusubtype; 

            state = kxld_array_get_item(&context->deps, i);

            kxld_state_get_cputype(state, &cputype, &cpusubtype);

            rval = kxld_kext_validate_cputype(context->kext, 
                cputype, cpusubtype);
            require_noerr(rval, finish);

            nsyms += kxld_state_get_num_symbols(state);
            nvtables += kxld_state_get_num_vtables(state);
        }

        /* Create the global symbol and vtable tables */

        rval = kxld_dict_init(&context->defined_symbols, kxld_dict_string_hash,
            kxld_dict_string_cmp, nsyms);
        require_noerr(rval, finish);

        rval = kxld_dict_init(&context->obsolete_symbols, kxld_dict_string_hash,
            kxld_dict_string_cmp, 0);
        require_noerr(rval, finish);

        rval = kxld_dict_init(&context->vtables, kxld_dict_string_hash,
            kxld_dict_string_cmp, nvtables);
        require_noerr(rval, finish);

        /* Populate the global tables */

        for (i = 0; i < ndeps; ++i) {
            state = kxld_array_get_item(&context->deps, i);

            rval = kxld_state_get_symbols(state, &context->defined_symbols,
                &context->obsolete_symbols);
            require_noerr(rval, finish);

            rval = kxld_state_get_vtables(state, &context->vtables);
            require_noerr(rval, finish);
        }

        if (kxld_kext_is_true_kext(context->kext)) {

            /* Allocate the kext object */

            kxld_kext_get_vmsize(context->kext, &header_size, &vmsize);
            vmaddr = context->allocate_callback(vmsize, &flags, callback_data);
            require_action(!(vmaddr & (PAGE_SIZE-1)), finish, rval=KERN_FAILURE;
                kxld_log(kKxldLogLinking, kKxldLogErr,
                    "Load address %p is not page-aligned.",
                    (void *) (uintptr_t) vmaddr));

            if (flags & kKxldAllocateWritable) {
                linked_object = (u_char *) (u_long) vmaddr;
            } else {
                linked_object_alloc = kxld_page_alloc_untracked(vmsize);
                require_action(linked_object_alloc, finish, rval=KERN_RESOURCE_SHORTAGE);
                linked_object = linked_object_alloc;
            }

            /* Zero out the memory before we fill it.  We fill this buffer in a
             * sparse fashion, and it's simpler to clear it now rather than
             * track and zero any pieces we didn't touch after we've written
             * all of the sections to memory.
             */
            bzero(linked_object, vmsize);

            /* Relocate to the new link address */

            rval = kxld_kext_relocate(context->kext, vmaddr, &context->vtables, 
                &context->defined_symbols, &context->obsolete_symbols);
            require_noerr(rval, finish);

            /* Generate linked object if requested */

            if (_linked_object) {
                check(kmod_info_kern);
                *_linked_object = NULL;
                *kmod_info_kern = 0;

                rval = kxld_kext_export_linked_object(context->kext, linked_object, 
                    kmod_info_kern);
                require_noerr(rval, finish);
            }

        } else  {
            /* Resolve the pseudokext's symbols */

            rval = kxld_kext_resolve(context->kext, &context->vtables, 
                &context->defined_symbols);
            require_noerr(rval, finish);
        }
    }

    /* Generate link state if requested */

    if (_link_state) {
        check(_link_state_size);
        *_link_state = NULL;
        *_link_state_size = 0;

        kxld_dict_clear(&context->defined_symbols);
        rval = kxld_state_export_kext_to_file(context->kext, &link_state,
            &link_state_size, &context->defined_symbols, &context->tmps);
        require_noerr(rval, finish);
    }

#if !KERNEL
    /* Generate symbol file if requested */

    if (_symbol_file) {
        check(_symbol_file_size);
        *_symbol_file = NULL;
        *_symbol_file_size = 0;

        rval = kxld_kext_export_symbol_file(context->kext, &symbol_file,
            &symbol_file_size);
        require_noerr(rval, finish);
    }
#endif /* !KERNEL */

    /* Commit output to return variables */

    if (_linked_object) {
        *_linked_object = linked_object;
        linked_object = NULL;
        linked_object_alloc = NULL;
    }

    if (_link_state) {
        *_link_state = link_state;
        *_link_state_size = link_state_size;
        link_state = NULL;
    }

#if !KERNEL
    if (_symbol_file) {
        *_symbol_file = symbol_file;
        *_symbol_file_size = symbol_file_size;
        symbol_file = NULL;
    }
#endif

    rval = KERN_SUCCESS;

finish:

    if (linked_object_alloc) kxld_page_free_untracked(linked_object_alloc, vmsize);
    if (link_state) kxld_page_free_untracked(link_state, link_state_size);
    if (symbol_file) kxld_page_free_untracked(symbol_file, symbol_file_size);

    clear_context(context);

    kxld_set_logging_callback_data(NULL, NULL);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static void
clear_context(KXLDContext *context)
{
    KXLDState *state = NULL;
    u_int i = 0;

    check(context);

    kxld_kext_clear(context->kext);
    for (i = 0; i < context->deps.nitems; ++i) {
        state = kxld_array_get_item(&context->deps, i);
        kxld_state_clear(state);
    }
    kxld_array_reset(&context->deps);

    kxld_array_clear(&context->tmps);
    kxld_dict_clear(&context->defined_symbols);
    kxld_dict_clear(&context->obsolete_symbols);
    kxld_dict_clear(&context->vtables);
}

