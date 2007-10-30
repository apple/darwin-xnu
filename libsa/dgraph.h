/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
#ifndef __DGRAPH_H__
#define __DGRAPH_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef KERNEL
#include <libsa/stdlib.h>
#include <IOKit/IOLib.h>
#else
#include <stdlib.h>
#include <mach/mach.h>
#endif /* KERNEL */

typedef struct dgraph_entry_t {

    char is_kernel_component; // means that name is a CFBundleIdentifier!!!
    char is_symbol_set; 
    char opaques;
    char opaque_link;

    // What we have to start from
    char * name;   // filename if user space, bundleid if kernel or kernel comp.

    void * object;         // In kernel we keep track of the object file
    size_t object_length;  //    we don't own this, however; it's just a ref
#ifdef KERNEL
    bool   object_is_kmem; // Only used when mapping a file!
#endif /* KERNEL */

   /* If is_kernel_component is true then the do_load field is cleared and
    * the kmod_id field gets set.
    */

    // Immediate dependencies of this entry
    unsigned int dependencies_capacity;
    unsigned int num_dependencies;
    struct dgraph_entry_t ** dependencies;

    // These are filled in when the entry is created, and are written into
    // the kmod linked image at load time.
    char * expected_kmod_name;
    char * expected_kmod_vers;

    bool is_mapped;  // kld_file_map() has been called for this entry

    // For tracking already-loaded kmods or for doing symbol generation only
    int do_load;   // actually loading
    vm_address_t loaded_address;  // address loaded at or being faked at for symbol generation
#ifndef KERNEL
    char * link_output_file;
    bool link_output_file_alloc;
#endif
    struct mach_header * linked_image;
    vm_size_t	 linked_image_length;

    vm_address_t symbols;
    vm_size_t	 symbols_length;
    vm_address_t symbols_malloc;

    // for loading into kernel
    vm_address_t  kernel_alloc_address;
    unsigned long kernel_alloc_size;
    vm_address_t  kernel_load_address;
    unsigned long kernel_load_size;
    unsigned long kernel_hdr_size;
    unsigned long kernel_hdr_pad;
    int need_cleanup;  // true if load failed with kernel memory allocated
    kmod_t kmod_id;    // the id assigned by the kernel to a loaded kmod

#if CONFIG_MACF_KEXT
    // module-specific data from the plist
    kmod_args_t user_data;
    mach_msg_type_number_t user_data_length;
#endif

} dgraph_entry_t;

typedef struct {
    unsigned int      capacity;
    unsigned int      length;
    dgraph_entry_t ** graph;
    dgraph_entry_t ** load_order;
    dgraph_entry_t  * root;
    char	      have_loaded_symbols;
    char	      has_symbol_sets;
    char	      has_opaque_links;
    vm_address_t      opaque_base_image;
    vm_size_t	      opaque_base_length;
} dgraph_t;

typedef enum {
    dgraph_error = -1,
    dgraph_invalid = 0,
    dgraph_valid = 1
} dgraph_error_t;


enum { kOpaqueLink = 0x01, kRawKernelLink = 0x02 };

dgraph_error_t dgraph_init(dgraph_t * dgraph);

#ifndef KERNEL
/**********
 * Initialize a dependency graph passed in. Returns nonzero on success, zero
 * on failure.
 *
 *     dependency_graph: a pointer to the dgraph to initialize.
 *     argc: the number of arguments in argv
 *     argv: an array of strings defining the dependency graph. This is a
 *         series of dependency lists, delimited by "-d" (except before
 *         the first list, naturally). Each list has as its first entry
 *         the dependent, followed by any number of DIRECT dependencies.
 *         The lists may be given in any order, but the first item in each
 *         list must be the dependent. Also, there can only be one root
 *         item (an item with no dependents upon it), and it must not be
 *         a kernel component.
 */
dgraph_error_t dgraph_init_with_arglist(
    dgraph_t * dgraph,
    int expect_addresses,
    const char * dependency_delimiter,
    const char * kernel_dependency_delimiter,
    int argc,
    char * argv[]);
#endif /* not KERNEL */

void dgraph_free(
    dgraph_t * dgraph,
    int free_graph);

dgraph_entry_t * dgraph_find_root(dgraph_t * dgraph);

int dgraph_establish_load_order(dgraph_t * dgraph);

#ifndef KERNEL
void dgraph_print(dgraph_t * dgraph);
#endif /* not kernel */
void dgraph_log(dgraph_t * depgraph);


/*****
 * These functions are useful for hand-building a dgraph.
 */
dgraph_entry_t * dgraph_find_dependent(dgraph_t * dgraph, const char * name);

dgraph_entry_t * dgraph_add_dependent(
    dgraph_t * dgraph,
    const char * name,
#ifdef KERNEL
    void * object,
    size_t object_length,
    bool   object_is_kmem,
#if CONFIG_MACF_KEXT
    kmod_args_t user_data,
    mach_msg_type_number_t user_data_length,
#endif
#endif /* KERNEL */
    const char * expected_kmod_name,
    const char * expected_kmod_vers,
    vm_address_t load_address,
    char is_kernel_component);

dgraph_entry_t * dgraph_add_dependency(
    dgraph_t * dgraph,
    dgraph_entry_t * current_dependent,
    const char * name,
#ifdef KERNEL
    void * object,
    size_t object_length,
    bool   object_is_kmem,
#if CONFIG_MACF_KEXT
    kmod_args_t user_data,
    mach_msg_type_number_t user_data_length,
#endif 
#endif /* KERNEL */
    const char * expected_kmod_name,
    const char * expected_kmod_vers,
    vm_address_t load_address,
    char is_kernel_component);

dgraph_entry_t ** fill_backward_load_order(
    dgraph_entry_t ** backward_load_order,
    unsigned int * list_length,
    dgraph_entry_t * first_entry,
    unsigned int * last_index /* out param */);

#ifdef __cplusplus
}
#endif

#endif /* __DGRAPH_H__ */
