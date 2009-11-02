/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#ifdef KERNEL
#include <libsa/vers_rsrc.h>
#else
#include <libc.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "KXKext.h"
#include "vers_rsrc.h"
#endif /* KERNEL */

#include "dgraph.h"
#include "load.h"


static void __dgraph_entry_free(dgraph_entry_t * entry);

#ifdef KERNEL
/*******************************************************************************
*
*******************************************************************************/
char * strdup(const char * string)
{
    char * dup = 0;
    unsigned int length;

    length = strlen(string);
    dup = (char *)malloc((1+length) * sizeof(char));
    if (!dup) {
        return NULL;
    }
    strcpy(dup, string);
    return dup;
}

#endif /* KERNEL */

/*******************************************************************************
*
*******************************************************************************/
dgraph_error_t dgraph_init(dgraph_t * dgraph)
{
    bzero(dgraph, sizeof(dgraph_t));

    dgraph->capacity = (5);  // pulled from a hat

   /* Make sure list is big enough & graph has a good start size.
    */
    dgraph->graph = (dgraph_entry_t **)malloc(
        dgraph->capacity * sizeof(dgraph_entry_t *));

    if (!dgraph->graph) {
        return dgraph_error;
    }

    return dgraph_valid;
}

#ifndef KERNEL
/*******************************************************************************
*
*******************************************************************************/
dgraph_error_t dgraph_init_with_arglist(
    dgraph_t * dgraph,
    int expect_addresses,
    const char * dependency_delimiter,
    const char * kernel_dependency_delimiter,
    int argc,
    char * argv[])
{
    dgraph_error_t result = dgraph_valid;
    unsigned int i;
    int found_zero_load_address = 0;
    int found_nonzero_load_address = 0;
    dgraph_entry_t * current_dependent = NULL;
    char kernel_dependencies = 0;

    result = dgraph_init(dgraph);
    if (result != dgraph_valid) {
        return result;
    }

    for (i = 0; i < argc; i++) {
        vm_address_t load_address = 0;

        if (0 == strcmp(argv[i], dependency_delimiter)) {
            kernel_dependencies = 0;
            current_dependent = NULL;
            continue;
        } else if (0 == strcmp(argv[i], kernel_dependency_delimiter)) {
            kernel_dependencies = 1;
            current_dependent = NULL;
            continue;
        }

        if (expect_addresses) {
            char * address = rindex(argv[i], '@');
            if (address) {
                *address++ = 0;  // snip the address from the filename
                load_address = strtoul(address, NULL, 0);
            }
        }

        if (!current_dependent) {
           current_dependent = dgraph_add_dependent(dgraph, argv[i],
               /* expected kmod name */ NULL, /* expected vers */ 0,
               load_address, 0);
           if (!current_dependent) {
               return dgraph_error;
           }
        } else {
            if (!dgraph_add_dependency(dgraph, current_dependent, argv[i],
               /* expected kmod name */ NULL, /* expected vers */ 0,
               load_address, kernel_dependencies)) {

               return dgraph_error;
            }
        }
    }

    dgraph->root = dgraph_find_root(dgraph);
    dgraph_establish_load_order(dgraph);

    if (!dgraph->root) {
        kload_log_error("dependency graph has no root" KNL);
        return dgraph_invalid;
    }

    if (dgraph->root->is_kernel_component && !dgraph->root->is_symbol_set) {
        kload_log_error("dependency graph root is a kernel component" KNL);
        return dgraph_invalid;
    }

    for (i = 0; i < dgraph->length; i++) {
        if (dgraph->graph[i]->loaded_address == 0) {
            found_zero_load_address = 1;
        } else {
            found_nonzero_load_address = 1;
        }
        if ( (i > 0) &&
             (found_zero_load_address && found_nonzero_load_address)) {

            kload_log_error(
                "load addresses must be specified for all module files" KNL);
            return dgraph_invalid;
        }
    }

    return dgraph_valid;
}
#endif /* not KERNEL */

/*******************************************************************************
*
*******************************************************************************/
static void __dgraph_entry_free(dgraph_entry_t * entry)
{
    if (entry->name) {
        free(entry->name);
        entry->name = NULL;
    }
    if (entry->expected_kmod_name) {
        free(entry->expected_kmod_name);
        entry->expected_kmod_name = NULL;
    }
    if (entry->expected_kmod_vers) {
        free(entry->expected_kmod_vers);
        entry->expected_kmod_vers = NULL;
    }
    if (entry->dependencies) {
        free(entry->dependencies);
        entry->dependencies = NULL;
    }
    if (entry->symbols_malloc) {
        free((void *) entry->symbols_malloc);
        entry->symbols_malloc = NULL;
    }
    free(entry);
    return;
}

/*******************************************************************************
*
*******************************************************************************/
void dgraph_free(
    dgraph_t * dgraph,
    int free_graph)
{
    unsigned int entry_index;

    if (!dgraph) {
        return;
    }

    for (entry_index = 0; entry_index < dgraph->length; entry_index++) {
        dgraph_entry_t * current = dgraph->graph[entry_index];
        __dgraph_entry_free(current);
    }

    if (dgraph->graph) {
        free(dgraph->graph);
        dgraph->graph = NULL;
    }

    if (dgraph->load_order) {
        free(dgraph->load_order);
        dgraph->load_order = NULL;
    }

    if (free_graph && dgraph) {
        free(dgraph);
    }

    return;
}


/*******************************************************************************
*
*******************************************************************************/
dgraph_entry_t * dgraph_find_root(dgraph_t * dgraph) {
    dgraph_entry_t * root = NULL;
    dgraph_entry_t * candidate = NULL;
    unsigned int candidate_index;
    unsigned int scan_index;
    unsigned int dep_index;


   /* Scan each entry in the graph for one that isn't in any other entry's
    * dependencies.
    */
    for (candidate_index = 0; candidate_index < dgraph->length;
         candidate_index++) {

        candidate = dgraph->graph[candidate_index];

        for (scan_index = 0; scan_index < dgraph->length; scan_index++) {

            dgraph_entry_t * scan_entry = dgraph->graph[scan_index];
            if (candidate == scan_entry) {
                // don't check yourself
                continue;
            }
            for (dep_index = 0; dep_index < scan_entry->num_dependencies;
                 dep_index++) {

               /* If the dependency being checked is the candidate,
                *  then the candidate can't be the root.
                */
                dgraph_entry_t * check = scan_entry->dependencies[dep_index];

                if (check == candidate) {
                    candidate = NULL;
                    break;
                }
            }

           /* If the candidate was rejected, then hop out of this loop.
            */
            if (!candidate) {
                break;
            }
        }

       /* If we got here, the candidate is a valid one. However, if we already
        * found another, that means we have two possible roots (or more), which
        * is NOT ALLOWED.
        */
        if (candidate) {
            if (root) {
                kload_log_error("dependency graph has multiple roots "
                    "(%s and %s)" KNL, root->name, candidate->name);
                return NULL;  // two valid roots, illegal
            } else {
                root = candidate;
            }
        }
    }

    if (!root) {
        kload_log_error("dependency graph has no root node" KNL);
    }

    return root;
}

/*******************************************************************************
*
*******************************************************************************/
dgraph_entry_t ** fill_backward_load_order(
    dgraph_entry_t ** backward_load_order,
    unsigned int * list_length,
    dgraph_entry_t * first_entry,
    unsigned int * last_index /* out param */)
{
    int i;
    unsigned int scan_index = 0;
    unsigned int add_index = 0;
    dgraph_entry_t * scan_entry;

    if (*list_length == 0) {
        if (backward_load_order) {
            free(backward_load_order);
            backward_load_order = NULL;
        }
        goto finish;
    }

    backward_load_order[add_index++] = first_entry;

    while (scan_index < add_index) {

        if (add_index > 255) {
            kload_log_error(
                "dependency list for %s ridiculously long; probably a loop" KNL,
                first_entry->name);
            if (backward_load_order) {
                free(backward_load_order);
                backward_load_order = NULL;
            }
            goto finish;
        }

        scan_entry = backward_load_order[scan_index++];

       /* Increase the load order list if needed.
        */
        if (add_index + scan_entry->num_dependencies > (*list_length)) {
            (*list_length) *= 2;
            backward_load_order = (dgraph_entry_t **)realloc(
                backward_load_order,
                (*list_length) * sizeof(dgraph_entry_t *));
            if (!backward_load_order) {
                goto finish;
            }
        }

       /* Put the dependencies of the scanning entry into the list.
        */
        for (i = 0; i < scan_entry->num_dependencies; i++) {
            backward_load_order[add_index++] =
                scan_entry->dependencies[i];
        }
    }

finish:

    if (last_index) {
        *last_index = add_index;
    }
    return backward_load_order;
}

/*******************************************************************************
*
*******************************************************************************/
int dgraph_establish_load_order(dgraph_t * dgraph) {
    unsigned int total_dependencies;
    unsigned int entry_index;
    unsigned int list_index;
    unsigned int backward_index;
    unsigned int forward_index;
    size_t load_order_size;
    size_t backward_load_order_size;
    dgraph_entry_t ** backward_load_order;

   /* Lose the old load_order list. Size can change, so it's easier to just
    * recreate from scratch.
    */
    if (dgraph->load_order) {
        free(dgraph->load_order);
        dgraph->load_order = NULL;
    }

   /* Figure how long the list needs to be to accommodate the max possible
    * entries from the graph. Duplicates get weeded out, but the list
    * initially has to accommodate them all.
    */
    total_dependencies = dgraph->length;

    for (entry_index = 0; entry_index < dgraph->length; entry_index ++) {
        dgraph_entry_t * curdep = dgraph->graph[entry_index];
        total_dependencies += curdep->num_dependencies;
    }

   /* Hmm, nothing to do!
    */
    if (!total_dependencies) {
        return 1;
    }

    backward_load_order_size = total_dependencies * sizeof(dgraph_entry_t *);

    backward_load_order = (dgraph_entry_t **)malloc(backward_load_order_size);
    if (!backward_load_order) {
        kload_log_error("malloc failure" KNL);
        return 0;
    }
    bzero(backward_load_order, backward_load_order_size);

    backward_load_order = fill_backward_load_order(backward_load_order,
        &total_dependencies, dgraph->root, &list_index);
    if (!backward_load_order) {
        kload_log_error("error establishing load order" KNL);
        return 0;
    }

    load_order_size = dgraph->length * sizeof(dgraph_entry_t *);
    dgraph->load_order = (dgraph_entry_t **)malloc(load_order_size);
    if (!dgraph->load_order) {
        kload_log_error("malloc failure" KNL);
        return 0;
    }
    bzero(dgraph->load_order, load_order_size);


   /* Reverse the list into the dgraph's load_order list,
    * removing any duplicates.
    */
    backward_index = list_index;
    //
    // the required 1 is taken off in loop below!

    forward_index = 0;
    do {
        dgraph_entry_t * current_entry;
        unsigned int already_got_it = 0;

        backward_index--;

       /* Get the entry to check.
        */
        current_entry = backward_load_order[backward_index];

       /* Did we already get it?
        */
        for (list_index = 0; list_index < forward_index; list_index++) {
            if (current_entry == dgraph->load_order[list_index]) {
                already_got_it = 1;
                break;
            }
        }

        if (already_got_it) {
            continue;
        }

       /* Haven't seen it before; tack it onto the load-order list.
        */
        dgraph->load_order[forward_index++] = current_entry;

    } while (backward_index > 0);

    free(backward_load_order);

    return 1;
}

/*******************************************************************************
*
*******************************************************************************/
void dgraph_log(dgraph_t * depgraph)
{
    unsigned int i, j;

    kload_log_message("flattened dependency list: " KNL);
    for (i = 0; i < depgraph->length; i++) {
        dgraph_entry_t * current = depgraph->graph[i];

        kload_log_message("    %s" KNL, current->name);
        kload_log_message("      is kernel component: %s" KNL,
            current->is_kernel_component ? "yes" : "no");
        kload_log_message("      expected kmod name: [%s]" KNL,
            current->expected_kmod_name);
        kload_log_message("      expected kmod vers: [%s]" KNL,
            current->expected_kmod_vers);
    }
    kload_log_message("" KNL);

    kload_log_message("load order dependency list: " KNL);
    for (i = 0; i < depgraph->length; i++) {
        dgraph_entry_t * current = depgraph->load_order[i];
        kload_log_message("    %s" KNL, current->name);
    }
    kload_log_message("" KNL);

    kload_log_message("dependency graph: " KNL);
    for (i = 0; i < depgraph->length; i++) {
        dgraph_entry_t * current = depgraph->graph[i];
        for (j = 0; j < current->num_dependencies; j++) {
            dgraph_entry_t * cdep = current->dependencies[j];
            kload_log_message("  %s -> %s" KNL, current->name, cdep->name);
        }
    }
    kload_log_message("" KNL);

    return;
}

/*******************************************************************************
*
*******************************************************************************/
dgraph_entry_t * dgraph_find_dependent(dgraph_t * dgraph, const char * name)
{
    unsigned int i;

    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * current_entry = dgraph->graph[i];
        if (0 == strcmp(name, current_entry->name)) {
            return current_entry;
        }
    }

    return NULL;
}

/*******************************************************************************
*
*******************************************************************************/
dgraph_entry_t * dgraph_add_dependent(
    dgraph_t * dgraph,
    const char * name,
#ifdef KERNEL
    void * object,
    size_t object_length,
    bool   object_is_kmem,
#endif /* KERNEL */
    const char * expected_kmod_name,
    const char * expected_kmod_vers,
    vm_address_t load_address,
    char is_kernel_component)
{
    int error = 0;
    dgraph_entry_t * found_entry = NULL;
    dgraph_entry_t * new_entry = NULL;    // free on error
    dgraph_entry_t * the_entry = NULL;    // returned

   /* Already got it? Great!
    */
    found_entry = dgraph_find_dependent(dgraph, name);
    if (found_entry) {
        if (found_entry->is_kernel_component != is_kernel_component) {
            kload_log_error(
                "%s is already defined as a %skernel component" KNL,
                name, found_entry->is_kernel_component ? "" : "non-");
            error = 1;
            goto finish;
        }

        if (load_address != 0) {
            if (found_entry->loaded_address == 0) {
                found_entry->do_load = 0;
                found_entry->loaded_address = load_address;
            } else if (found_entry->loaded_address != load_address) {
                kload_log_error(
                   "%s has been assigned two different addresses (0x%x, 0x%x) KNL",
                    found_entry->name,
                    found_entry->loaded_address,
                    load_address);
                error = 1;
                goto finish;
            }
        }
        the_entry = found_entry;
        goto finish;
    }

   /* If the graph is full, make it bigger.
    */
    if (dgraph->length == dgraph->capacity) {
        unsigned int old_capacity = dgraph->capacity;
        dgraph_entry_t ** newgraph;

        dgraph->capacity *= 2;
        newgraph = (dgraph_entry_t **)malloc(dgraph->capacity *
            sizeof(dgraph_entry_t *));
        if (!newgraph) {
            return NULL;
        }
        memcpy(newgraph, dgraph->graph, old_capacity * sizeof(dgraph_entry_t *));
        free(dgraph->graph);
        dgraph->graph = newgraph;
    }

    if (strlen(expected_kmod_name) > KMOD_MAX_NAME - 1) {
        kload_log_error("expected kmod name \"%s\" is too long" KNL,
            expected_kmod_name);
        error = 1;
        goto finish;
    }

   /* Fill it.
    */
    new_entry = (dgraph_entry_t *)malloc(sizeof(dgraph_entry_t));
    if (!new_entry) {
        error = 1;
        goto finish;
    }
    bzero(new_entry, sizeof(dgraph_entry_t));
    new_entry->expected_kmod_name = strdup(expected_kmod_name);
    if (!new_entry->expected_kmod_name) {
        error = 1;
        goto finish;
    }
    new_entry->expected_kmod_vers = strdup(expected_kmod_vers);
    if (!new_entry->expected_kmod_vers) {
        error = 1;
        goto finish;
    }
    new_entry->is_kernel_component = is_kernel_component;

    // /hacks
    new_entry->is_symbol_set = (2 & is_kernel_component);

    new_entry->opaques = 0;
    if (!strncmp(new_entry->expected_kmod_name, 
				    "com.apple.kpi", strlen("com.apple.kpi")))
        new_entry->opaques |= kOpaqueLink;
    if (!strcmp(new_entry->expected_kmod_name, 
				    "com.apple.kernel"))
        new_entry->opaques |= kOpaqueLink | kRawKernelLink;
    // hacks/

    dgraph->has_symbol_sets |= new_entry->is_symbol_set;

    new_entry->do_load = !is_kernel_component;

#ifndef KERNEL
    new_entry->object = NULL;   // provided elswehere in userland
    new_entry->object_length = 0;
#else
    new_entry->object = object;
    new_entry->object_length = object_length;
    new_entry->object_is_kmem = object_is_kmem;
#endif /* KERNEL */
    new_entry->name = strdup(name);
    if (!new_entry->name) {
        error = 1;
        goto finish;
    }
    dgraph->graph[dgraph->length++] = new_entry;


   /* Create a dependency list for the entry. Start with 5 slots.
    */
    new_entry->dependencies_capacity = 5;
    new_entry->num_dependencies = 0;
    new_entry->dependencies = (dgraph_entry_t **)malloc(
        new_entry->dependencies_capacity * sizeof(dgraph_entry_t *));
    if (!new_entry->dependencies) {
        error = 1;
        goto finish;
    }

    if (new_entry->loaded_address == 0) {
        new_entry->loaded_address = load_address;
        if (load_address != 0) {
            new_entry->do_load = 0;
        }
    }

    the_entry = new_entry;

finish:
    if (error) {
        if (new_entry) __dgraph_entry_free(new_entry);
        the_entry = new_entry = NULL;
    }
    return the_entry;
}

/*******************************************************************************
*
*******************************************************************************/
dgraph_entry_t * dgraph_add_dependency(
    dgraph_t * dgraph,
    dgraph_entry_t * current_dependent,
    const char * name,
#ifdef KERNEL
    void * object,
    size_t object_length,
    bool   object_is_kmem,
#endif /* KERNEL */
    const char * expected_kmod_name,
    const char * expected_kmod_vers,
    vm_address_t load_address,
    char is_kernel_component)
{
    dgraph_entry_t * dependency = NULL;
    unsigned int i = 0;

   /* If the dependent's dependency list is full, make it bigger.
    */
    if (current_dependent->num_dependencies ==
        current_dependent->dependencies_capacity) {

        unsigned int old_capacity = current_dependent->dependencies_capacity;
        dgraph_entry_t ** newlist;

        current_dependent->dependencies_capacity *= 2;
        newlist = (dgraph_entry_t **)malloc(
            (current_dependent->dependencies_capacity *
             sizeof(dgraph_entry_t *)) );

        if (!newlist) {
            return NULL;
        }
        memcpy(newlist, current_dependent->dependencies,
            old_capacity * sizeof(dgraph_entry_t *));
        free(current_dependent->dependencies);
        current_dependent->dependencies = newlist;
    }


   /* Find or add the entry for the new dependency.
    */
    dependency = dgraph_add_dependent(dgraph, name,
#ifdef KERNEL
         object, object_length, object_is_kmem,
#endif /* KERNEL */
         expected_kmod_name, expected_kmod_vers, load_address,
         is_kernel_component);
    if (!dependency) {
       return NULL;
    }

    if (dependency == current_dependent) {
        kload_log_error("attempt to set dependency on itself: %s" KNL,
            current_dependent->name);
        return NULL;
    }

    for (i = 0; i < current_dependent->num_dependencies; i++) {
        dgraph_entry_t * this_dependency = current_dependent->dependencies[i];
        if (this_dependency == dependency) {
            return dependency;
        }
    }

   /* Fill in the dependency.
    */
    current_dependent->dependencies[current_dependent->num_dependencies] =
        dependency;
    current_dependent->num_dependencies++;

    current_dependent->opaque_link |= dependency->opaques;
    dgraph->has_opaque_links       |= current_dependent->opaque_link;

    return dependency;
}
