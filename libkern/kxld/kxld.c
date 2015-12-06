/*
 * Copyright (c) 2007-2008, 2012 Apple Inc. All rights reserved.
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

#if KERNEL
#define __KXLD_KERNEL_UNUSED __unused
#else
#define __KXLD_KERNEL_UNUSED
#endif

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
#include "kxld_object.h"
#include "kxld_sym.h"
#include "kxld_symtab.h"
#include "kxld_util.h"
#include "kxld_vtable.h"

struct kxld_vtable;

struct kxld_context {
    KXLDKext *kext;
    KXLDArray *section_order;
    KXLDArray objects;
    KXLDArray dependencies;
    KXLDDict defined_symbols_by_name;
    KXLDDict defined_cxx_symbols_by_value;
    KXLDDict obsolete_symbols_by_name;
    KXLDDict vtables_by_name;
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

static kern_return_t init_context(KXLDContext *context, u_int ndependencies);
static kern_return_t init_kext_objects(KXLDContext *context, u_char *file, 
    u_long size, const char *name, KXLDDependency *dependencies, 
    u_int ndependencies);
static KXLDObject * get_object_for_file(KXLDContext *context, 
    u_char *file, u_long size, const char *name);
static u_char * allocate_kext(KXLDContext *context, void *callback_data,
    kxld_addr_t *vmaddr, u_long *vmsize, u_char **linked_object_alloc_out);
static void clear_context(KXLDContext *context);

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_create_context(KXLDContext **_context, 
    KXLDAllocateCallback allocate_callback, KXLDLoggingCallback logging_callback,
    KXLDFlags flags, cpu_type_t cputype, cpu_subtype_t cpusubtype,
    vm_size_t pagesize __KXLD_KERNEL_UNUSED)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDContext       * context         = NULL;
    KXLDArray         * section_order   = NULL;
#if !KERNEL
    cpu_type_t        * cputype_p       = NULL;
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

#if !KERNEL
    if (pagesize) {
        kxld_set_cross_link_page_size(pagesize);
    }
#endif /* !KERNEL */

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
    if (context) kxld_destroy_context(context);
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
    KXLDObject *object = NULL;
    KXLDKext *dep = NULL;
    u_int i = 0;

    check(context);

    kxld_kext_deinit(context->kext);

    for (i = 0; i < context->objects.maxitems; ++i) {
        object = kxld_array_get_slot(&context->objects, i);
        kxld_object_deinit(object);
    }
    kxld_array_deinit(&context->objects);

    for (i = 0; i < context->dependencies.maxitems; ++i) {
        dep = kxld_array_get_slot(&context->dependencies, i);
        kxld_kext_deinit(dep);
    }
    kxld_array_deinit(&context->dependencies);

    kxld_dict_deinit(&context->defined_symbols_by_name);
    kxld_dict_deinit(&context->defined_cxx_symbols_by_value);
    kxld_dict_deinit(&context->obsolete_symbols_by_name);
    kxld_dict_deinit(&context->vtables_by_name);

    kxld_free(context->kext, kxld_kext_sizeof());
    kxld_free(context, sizeof(*context));

    kxld_print_memory_report();
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_link_file(
    KXLDContext       * context,
    u_char            * file,
    u_long              size,
    const char        * name,
    void              * callback_data,
    KXLDDependency    * dependencies,
    u_int               ndependencies,
    u_char           ** linked_object_out,
    kxld_addr_t       * kmod_info_kern)
{
    kern_return_t       rval                    = KERN_FAILURE;
    kxld_addr_t         vmaddr                  = 0;
    u_long              vmsize                  = 0;
    u_char            * linked_object           = NULL;
    u_char            * linked_object_alloc     = NULL;

    kxld_set_logging_callback_data(name, callback_data);

    kxld_log(kKxldLogLinking, kKxldLogBasic, "Linking kext %s", name);

    require_action(context, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(file, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(size, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(dependencies, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(ndependencies, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(linked_object_out, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(kmod_info_kern, finish, rval=KERN_INVALID_ARGUMENT);

    rval = init_context(context, ndependencies);
    require_noerr(rval, finish);

    rval = init_kext_objects(context, file, size, name, 
        dependencies, ndependencies);
    require_noerr(rval, finish);

    linked_object = allocate_kext(context, callback_data, 
        &vmaddr, &vmsize, &linked_object_alloc);
    require_action(linked_object, finish, rval=KERN_RESOURCE_SHORTAGE);

    rval = kxld_kext_relocate(context->kext, vmaddr, 
        &context->vtables_by_name, 
        &context->defined_symbols_by_name, 
        &context->obsolete_symbols_by_name,
        &context->defined_cxx_symbols_by_value);
    require_noerr(rval, finish);

    rval = kxld_kext_export_linked_object(context->kext, 
        linked_object, kmod_info_kern);
    require_noerr(rval, finish);

    *linked_object_out = linked_object;
    linked_object_alloc = NULL;

    rval = KERN_SUCCESS;
finish:
    if (linked_object_alloc) {
        kxld_page_free_untracked(linked_object_alloc, vmsize);
    }

    clear_context(context);
    kxld_set_logging_callback_data(NULL, NULL);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_context(KXLDContext *context, u_int ndependencies)
{
    kern_return_t rval = KERN_FAILURE;

    /* Create an array of objects large enough to hold an object
     * for every dependency, an interface for each dependency, and a kext. */
    rval = kxld_array_init(&context->objects,
        kxld_object_sizeof(), 2 * ndependencies + 1);
    require_noerr(rval, finish);

    rval = kxld_array_init(&context->dependencies, 
        kxld_kext_sizeof(), ndependencies);
    require_noerr(rval, finish);

    rval = kxld_dict_init(&context->defined_symbols_by_name, 
        kxld_dict_string_hash, kxld_dict_string_cmp, 0);
    require_noerr(rval, finish);

    rval = kxld_dict_init(&context->defined_cxx_symbols_by_value, 
        kxld_dict_kxldaddr_hash, kxld_dict_kxldaddr_cmp, 0);
    require_noerr(rval, finish);

    rval = kxld_dict_init(&context->obsolete_symbols_by_name, 
        kxld_dict_string_hash, kxld_dict_string_cmp, 0);
    require_noerr(rval, finish);

    rval = kxld_dict_init(&context->vtables_by_name, kxld_dict_string_hash,
        kxld_dict_string_cmp, 0);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
init_kext_objects(KXLDContext *context, u_char *file, u_long size, 
    const char *name, KXLDDependency *dependencies, u_int ndependencies)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDKext *kext = NULL;
    KXLDObject *kext_object = NULL;
    KXLDObject *interface_object = NULL;
    u_int i = 0;

    /* Create a kext object for each dependency.  If it's a direct dependency,
     * export its symbols by name by value.  If it's indirect, just export the
     * C++ symbols by value.
     */
    for (i = 0; i < ndependencies; ++i) {
        kext = kxld_array_get_item(&context->dependencies, i);
        kext_object = NULL;
        interface_object = NULL;

        kext_object = get_object_for_file(context, dependencies[i].kext,
            dependencies[i].kext_size, dependencies[i].kext_name);
        require_action(kext_object, finish, rval=KERN_FAILURE);

        if (dependencies[i].interface) {
            interface_object = get_object_for_file(context, 
                dependencies[i].interface, dependencies[i].interface_size,
                dependencies[i].interface_name);
            require_action(interface_object, finish, rval=KERN_FAILURE);
        }

        rval = kxld_kext_init(kext, kext_object, interface_object);
        require_noerr(rval, finish);

        if (dependencies[i].is_direct_dependency) {
            rval = kxld_kext_export_symbols(kext,
                &context->defined_symbols_by_name, 
                &context->obsolete_symbols_by_name,
                &context->defined_cxx_symbols_by_value);
            require_noerr(rval, finish);
        } else {
            rval = kxld_kext_export_symbols(kext, 
                /* defined_symbols */ NULL, /* obsolete_symbols */ NULL, 
                &context->defined_cxx_symbols_by_value);
            require_noerr(rval, finish);
        }
    }

    /* Export the vtables for all of the dependencies. */
    for (i = 0; i < context->dependencies.nitems; ++i) {
        kext = kxld_array_get_item(&context->dependencies, i);

        rval = kxld_kext_export_vtables(kext,
            &context->defined_cxx_symbols_by_value,
            &context->defined_symbols_by_name,
            &context->vtables_by_name);
        require_noerr(rval, finish);
    }

    /* Create a kext object for the kext we're linking and export its locally
     * defined C++ symbols. 
     */
    kext_object = get_object_for_file(context, file, size, name);
    require_action(kext_object, finish, rval=KERN_FAILURE);

    rval = kxld_kext_init(context->kext, kext_object, /* interface */ NULL);
    require_noerr(rval, finish);

    rval = kxld_kext_export_symbols(context->kext,
        /* defined_symbols */ NULL, /* obsolete_symbols */ NULL, 
        &context->defined_cxx_symbols_by_value);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static KXLDObject *
get_object_for_file(KXLDContext *context, u_char *file, u_long size,
    const char *name)
{
    KXLDObject *rval = NULL;
    KXLDObject *object = NULL;
    kern_return_t result = 0;
    u_int i = 0;

    for (i = 0; i < context->objects.nitems; ++i) {
        object = kxld_array_get_item(&context->objects, i);

        if (!kxld_object_get_file(object)) {
            result = kxld_object_init_from_macho(object, file, size, name,
                context->section_order, context->cputype, context->cpusubtype, context->flags);
            require_noerr(result, finish);

            rval = object;
            break;
        }

        if (kxld_object_get_file(object) == file) {
            rval = object;
            break;
        }
    }

finish:
    return rval;
}
 
/*******************************************************************************
*******************************************************************************/
static u_char *
allocate_kext(KXLDContext *context, void *callback_data,
    kxld_addr_t *vmaddr_out, u_long *vmsize_out, 
    u_char **linked_object_alloc_out)
{
    KXLDAllocateFlags   flags                   = 0;
    kxld_addr_t         vmaddr                  = 0;
    u_long              vmsize                  = 0;
    u_long              header_size             = 0;
    u_char            * linked_object           = NULL;

    *linked_object_alloc_out = NULL;

    kxld_kext_get_vmsize(context->kext, &header_size, &vmsize);
    vmaddr = context->allocate_callback(vmsize, &flags, callback_data);
    require_action(!(vmaddr & (kxld_get_effective_page_size()-1)), finish,
        kxld_log(kKxldLogLinking, kKxldLogErr,
            "Load address %p is not page-aligned.",
            (void *) (uintptr_t) vmaddr));

    if (flags & kKxldAllocateWritable) {
        linked_object = (u_char *) (u_long) vmaddr;
    } else {
        linked_object = kxld_page_alloc_untracked(vmsize);
        require(linked_object, finish);

        *linked_object_alloc_out = linked_object;
    }

    kxld_kext_set_linked_object_size(context->kext, vmsize);
    
    /* Zero out the memory before we fill it.  We fill this buffer in a
     * sparse fashion, and it's simpler to clear it now rather than
     * track and zero any pieces we didn't touch after we've written
     * all of the sections to memory.
     */
    bzero(linked_object, vmsize);
    *vmaddr_out = vmaddr;
    *vmsize_out = vmsize;

finish:
    return linked_object;
}

/*******************************************************************************
*******************************************************************************/
static void
clear_context(KXLDContext *context)
{
    KXLDObject * object = NULL;
    KXLDKext   * dep     = NULL;
    u_int i = 0;

    check(context);

    kxld_kext_clear(context->kext);
    
    for (i = 0; i < context->objects.nitems; ++i) {
        object = kxld_array_get_item(&context->objects, i);
        kxld_object_clear(object);
    }
    kxld_array_reset(&context->objects);

    for (i = 0; i < context->dependencies.nitems; ++i) {
        dep = kxld_array_get_item(&context->dependencies, i);
        kxld_kext_clear(dep);
    }
    kxld_array_reset(&context->dependencies);

    kxld_dict_clear(&context->defined_symbols_by_name);
    kxld_dict_clear(&context->defined_cxx_symbols_by_value);
    kxld_dict_clear(&context->obsolete_symbols_by_name);
    kxld_dict_clear(&context->vtables_by_name);
}

