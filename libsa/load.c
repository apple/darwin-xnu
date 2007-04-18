/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
 
/***************
* HEADERS
***************/
#ifndef KERNEL

#include <CoreFoundation/CoreFoundation.h>

#include <libc.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <mach/mach_types.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#include <mach-o/kld.h>
#include <mach-o/arch.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <libkern/OSByteOrder.h>

#include "vers_rsrc.h"

#else

#include <mach-o/kld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libsa/vers_rsrc.h>

#endif /* not KERNEL */

#include "load.h"
#include "dgraph.h"
#include "kld_patch.h"

/***************
* MACROS
***************/

#ifndef KERNEL

#define PRIV_EXT

#else

#define PRIV_EXT  __private_extern__

#ifdef DEBUG
#define LOG_DELAY(x)    IODelay((x) * 1000000)
#define VTYELLOW  "\033[33m"
#define VTRESET   "\033[0m"
#else
#define LOG_DELAY()
#define VTYELLOW
#define VTRESET
#endif /* DEBUG */

#endif /* not KERNEL */

/***************
* FUNCTION PROTOS
***************/

#ifdef KERNEL
extern kern_return_t
kmod_create_internal(
            kmod_info_t *info,
            kmod_t *id);

extern kern_return_t
kmod_destroy_internal(kmod_t id);

extern kern_return_t
kmod_start_or_stop(
    kmod_t id,
    int start,
    kmod_args_t *data,
    mach_msg_type_number_t *dataCount);

extern kern_return_t kmod_retain(kmod_t id);
extern kern_return_t kmod_release(kmod_t id);

extern struct mach_header _mh_execute_header;
#endif /* KERNEL */


// Used to pass info between kld library and callbacks
static dgraph_entry_t * G_current_load_entry = NULL;

#ifndef KERNEL
static mach_port_t G_kernel_port = PORT_NULL;
static mach_port_t G_kernel_priv_port = PORT_NULL;
static int G_syms_only;

static kload_error
register_prelink(dgraph_entry_t * entry,
		    kmod_info_t * local_kmod_info, vm_offset_t kernel_kmod_info);

struct PrelinkState
{
    kmod_info_t modules[1];
};
struct PrelinkState *	G_prelink;
CFMutableDataRef	G_prelink_data;
CFMutableDataRef	G_prelink_dependencies;

#endif /* not KERNEL */

// used by dgraph.c so can't be static
kload_log_level log_level = 0;

#ifndef KERNEL
static void __kload_null_log(const char * format, ...);
static void __kload_null_err_log(const char * format, ...);
static int __kload_null_approve(int default_answer, const char * format, ...);
static int __kload_null_veto(int default_answer, const char * format, ...);
static const char * __kload_null_input(const char * format, ...);

void (*__kload_log_func)(const char * format, ...) =
    &__kload_null_log;
void (*__kload_err_log_func)(const char * format, ...) = &__kload_null_err_log;
int (*__kload_approve_func)(int default_answer,
    const char * format, ...) = &__kload_null_approve;
int (*__kload_veto_func)(int default_answer,
    const char * format, ...) = &__kload_null_veto;
const char * (*__kload_input_func)(const char * format, ...) =
    &__kload_null_input;
#endif /* not KERNEL */

static unsigned long __kload_linkedit_address(
    unsigned long size,
    unsigned long headers_size);
static void __kload_clean_up_entry(dgraph_entry_t * entry);
static void __kload_clear_kld_globals(void);
static kload_error __kload_patch_dgraph(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file
#endif /* not KERNEL */
    );
static kload_error __kload_load_modules(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file,
    const char * patch_file, const char * patch_dir,
    const char * symbol_file, const char * symbol_dir,
    int do_load, int do_start_kmod, int do_prelink,
    int interactive_level,
    int ask_overwrite_symbols, int overwrite_symbols
#endif /* not KERNEL */
    );

static kload_error __kload_check_module_loaded(
    dgraph_t * dgraph,
    dgraph_entry_t * entry,
#ifndef KERNEL
    kmod_info_t * kmod_list,
#endif /* not KERNEL */
    int log_if_already);

static kload_error __kload_load_module(dgraph_t * dgraph,
    dgraph_entry_t * entry,
    int is_root
#ifndef KERNEL
    ,
    const char * symbol_file,
    const char * symbol_dir,
    int do_load,
    int interactive_level,
    int ask_overwrite_symbols,
    int overwrite_symbols
#endif /* not KERNEL */
    );
static kload_error __kload_set_module_dependencies(dgraph_entry_t * entry);
static kload_error __kload_start_module(dgraph_entry_t * entry);

#ifndef KERNEL
static kload_error __kload_output_patches(
    dgraph_t * dgraph,
    const char * patch_file,
    const char * patch_dir,
    int ask_overwrite_symbols,
    int overwrite_symbols);

Boolean _IOReadBytesFromFile(CFAllocatorRef alloc, const char *path, void **bytes,
				CFIndex *length, CFIndex maxLength);
Boolean _IOWriteBytesToFile(const char *path, const void *bytes, CFIndex length);

#endif /* not KERNEL */

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
kload_error kload_load_dgraph(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file,
    const char * patch_file, const char * patch_dir,
    const char * symbol_file, const char * symbol_dir,
    int do_load, int do_start_kmod, int do_prelink,
    int interactive_level,
    int ask_overwrite_symbols, int overwrite_symbols
#endif /* not KERNEL */
    )
{
    kload_error result = kload_error_none;
    int one_has_address = 0;
    int one_lacks_address = 0;
    unsigned int i;
#ifndef KERNEL
    int syms_only;

    syms_only = (!do_load) && (symbol_dir || symbol_file);

    if (log_level >= kload_log_level_load_details) {
        kload_log_message("loading dependency graph:" KNL);
        dgraph_log(dgraph);
    }

    if (syms_only && log_level >= kload_log_level_load_details) {
        kload_log_message("loading for symbol generation only" KNL);
    }

   /*****
    * If we're not loading and have no request to emit a symbol
    * or patch file, there's nothing to do!
    */
    if (!do_load && !symbol_dir && !symbol_file &&
        !patch_dir && !patch_file) {

        if (syms_only && log_level >= kload_log_level_load_details) {
            kload_log_message("loader has no work to do" KNL);
        }

        result = kload_error_none;  // fixme: should this be USAGE error?
        goto finish;
    }

   /*****
    * If we're doing symbols only, then all entries in the dgraph must
    * have addresses assigned, or none must.
    */
    if (syms_only) {
        if (log_level >= kload_log_level_load_details) {
            kload_log_message("checking whether modules have addresses assigned" KNL);
        }
        for (i = 0; i < dgraph->length; i++) {
            struct dgraph_entry_t * entry = dgraph->load_order[i];
            if (entry->is_kernel_component) {
                continue;
            }
            if (entry->loaded_address != 0) {
                one_has_address = 1;
            } else {
                one_lacks_address = 1;
            }
        }
    }
#endif /* not KERNEL */

    if (one_has_address && one_lacks_address) {
        kload_log_error(
            "either all modules must have addresses set to nonzero values or "
            "none must" KNL);
        result = kload_error_invalid_argument;
        goto finish;
    }

#ifndef KERNEL
   /* we need the priv port to check/load modules in the kernel.
    */
    if (PORT_NULL == G_kernel_priv_port) {
        G_kernel_priv_port = mach_host_self();  /* if we are privileged */
    }
#endif /* not KERNEL */

/*****
 * In the kernel, ALWAYS get load addresses of existing loaded kmods.
 */
#ifndef KERNEL
   /*****
    * If we don't have addresses, then get them from the kernel.
    */
    if (!one_has_address && !do_prelink && (do_load || symbol_file || symbol_dir)) {
#endif /* not KERNEL */
        if (log_level >= kload_log_level_load_details) {
            kload_log_message("getting module addresses from kernel" KNL);
        }
#ifndef KERNEL
        result = kload_set_load_addresses_from_kernel(dgraph, kernel_file,
            do_load);
#else
        result = kload_set_load_addresses_from_kernel(dgraph);
#endif /* not KERNEL */
        if (result == kload_error_already_loaded) {

#ifndef KERNEL
            if (do_load) {
                goto finish;
            }
#else
            goto finish;
#endif /* not KERNEL */

        } else if (result != kload_error_none) {
            kload_log_error("can't check load addresses of modules" KNL);
            goto finish;
        }
#ifndef KERNEL
    }
#endif /* not KERNEL */

#ifndef KERNEL
   /*****
    * At this point, if we're doing symbols only, it's an error to not
    * have a load address for every module.
    */
    if (syms_only && !do_prelink) {
        if (log_level >= kload_log_level_load_details) {
            kload_log_message("checking that all modules have addresses assigned" KNL);
        }
        for (i = 0; i < dgraph->length; i++) {
            struct dgraph_entry_t * entry = dgraph->load_order[i];
            if (entry->is_kernel_component) {
                continue;
            }
            if (!entry->loaded_address) {
                kload_log_error(
                    "missing load address during symbol generation: %s" KNL,
                    entry->name);
                result = kload_error_unspecified;
                goto finish;
            }
       }
    }

    if (do_prelink)
    {
        void *  	bytes;
        CFIndex        length;
	CFAllocatorRef alloc;

	// We need a real allocator to pass to _IOReadBytesFromFile
	alloc = CFRetain(CFAllocatorGetDefault());
        if (_IOReadBytesFromFile(alloc, "prelinkstate", &bytes, &length, 0))
	{
	    G_prelink_data = CFDataCreateMutable(alloc, 0);
	    CFDataAppendBytes(G_prelink_data, (UInt8 *) bytes, length);
            CFAllocatorDeallocate(alloc, bytes);
        }
	G_prelink_dependencies = CFDataCreateMutable(alloc, 0);
	if (_IOReadBytesFromFile(alloc, "prelinkdependencies", &bytes, &length, 0))
	{
	    CFDataAppendBytes(G_prelink_dependencies, (UInt8 *) bytes, length);
            CFAllocatorDeallocate(alloc, bytes);
        }
	CFRelease(alloc);

	if (!G_prelink_data) {
            kload_log_error(
                "can't get load address for prelink %s" KNL, kernel_file);
            result = kload_error_link_load;
            goto finish;
	}
	else
	    G_prelink = (struct PrelinkState *) CFDataGetMutableBytePtr(G_prelink_data);
    }
    else
        G_prelink = 0;
#endif /* not KERNEL */

#ifndef KERNEL

    result = __kload_load_modules(dgraph, kernel_file,
        patch_file, patch_dir, symbol_file, symbol_dir,
        do_load, do_start_kmod, do_prelink, interactive_level,
        ask_overwrite_symbols, overwrite_symbols);
#else
    result = __kload_load_modules(dgraph);
#endif /* not KERNEL */

finish:

#ifndef KERNEL
   /* Dispose of the host port to prevent security breaches and port
    * leaks. We don't care about the kern_return_t value of this
    * call for now as there's nothing we can do if it fails.
    */
    if (PORT_NULL != G_kernel_priv_port) {
        mach_port_deallocate(mach_task_self(), G_kernel_priv_port);
        G_kernel_priv_port = PORT_NULL;
    }
#endif /* not KERNEL */

    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * current_entry = dgraph->graph[i];
        __kload_clean_up_entry(current_entry);
    }

#ifndef KERNEL
    if (G_prelink)
    {
	SInt32       length;
	const void * bytes;
	Boolean      success;

	length = CFDataGetLength(G_prelink_data);
	bytes = (0 == length) ? (const void *)"" : CFDataGetBytePtr(G_prelink_data);
	success = _IOWriteBytesToFile("prelinkstate", bytes, length);
	if (!success)
	{
	    kload_log_error("write prelinkstate" KNL);
	    result = kload_error_link_load;
	}
	length = CFDataGetLength(G_prelink_dependencies);
	bytes = (0 == length) ? (const void *)"" : CFDataGetBytePtr(G_prelink_dependencies);
	success = _IOWriteBytesToFile("prelinkdependencies", bytes, length);
	if (!success)
	{
	    kload_log_error("write prelinkdependencies" KNL);
	    result = kload_error_link_load;
	}
    }
#endif /* not KERNEL */

    return result;
}

#ifndef KERNEL
/*******************************************************************************
* This function claims the option flags d and D for object file dependencies
* and in-kernel dependencies, respectively.
*******************************************************************************/
kload_error kload_load_with_arglist(
    int argc, char **argv,
    const char * kernel_file,
    const char * patch_file, const char * patch_dir,
    const char * symbol_file, const char * symbol_dir,
    int do_load, int do_start_kmod,
    int interactive_level,
    int ask_overwrite_symbols, int overwrite_symbols)
{
    kload_error result = kload_error_none;
    dgraph_error_t dgraph_result;
    int syms_only = (!do_load) && (symbol_file || symbol_dir);

    static dgraph_t dependency_graph;

   /* Zero out fields in dependency graph for proper error handling later.
    */
    bzero(&dependency_graph, sizeof(dependency_graph));

    dgraph_result = dgraph_init_with_arglist(&dependency_graph,
        syms_only, "-d", "-D", argc, argv);
    if (dgraph_result == dgraph_error) {
        kload_log_error("error processing dependency list" KNL);
        result = kload_error_unspecified;
        goto finish;
    } else if (dgraph_result == dgraph_invalid) {
        // anything to print here, or did init call print something?
        result = kload_error_invalid_argument;
        goto finish;
    }

    result = kload_load_dgraph(&dependency_graph, kernel_file,
        patch_file, patch_dir, symbol_file, symbol_dir,
        do_load, do_start_kmod, false /* do_prelink */, interactive_level,
        ask_overwrite_symbols, overwrite_symbols);

finish:
    return result;
}
#endif /* not KERNEL */
/*******************************************************************************
* This function can only operate on 32 bit mach object file symbol table
* entries.
*******************************************************************************/
static
kload_error __kload_keep_symbols(dgraph_entry_t * entry)
{
    struct mach_header *     	hdr;
    struct segment_command * 	seg;
    struct nlist *	     	sym;
    struct symtab_command *	symcmd;
    unsigned long		idx, ncmds;
    vm_size_t	  		size;
    vm_address_t  		mem;

    if (entry->symbols)
	return kload_error_none;

    hdr   = entry->linked_image;
    ncmds = hdr->ncmds;
    seg   = (struct segment_command *)(hdr + 1);
    for (idx = 0;
            idx < ncmds;
            idx++, seg = (struct segment_command *)(((vm_offset_t)seg) + seg->cmdsize))
    {
        if (LC_SYMTAB == seg->cmd)
	    break;
    }
    if (idx >= ncmds)
    {
        kload_log_error("no LC_SYMTAB" KNL);
	return kload_error_unspecified;
    }

    symcmd = (struct symtab_command *) seg;

    struct load_cmds {
	struct mach_header     hdr;
	struct segment_command seg;
	struct symtab_command  symcmd;
    };
    struct load_cmds * cmd;
    unsigned int symtabsize;

    symtabsize = symcmd->stroff + symcmd->strsize - symcmd->symoff;

    size = sizeof(struct load_cmds) + symtabsize;

    mem = (vm_offset_t) malloc(size);

    cmd = (struct load_cmds *) mem;
    sym = (struct nlist *) (cmd + 1);

    cmd->hdr    = *hdr;
    cmd->symcmd = *symcmd;
    bcopy((const void *) (((vm_offset_t) hdr) + symcmd->symoff), 
	    sym,
	    symtabsize);

    hdr                 = (struct mach_header *) mem;
    cmd->hdr.ncmds      = 2;
    cmd->hdr.sizeofcmds = sizeof(struct load_cmds) - sizeof(struct mach_header);
    cmd->hdr.flags     &= ~MH_INCRLINK;

    cmd->symcmd.stroff -= (symcmd->symoff - sizeof(struct load_cmds));
    cmd->symcmd.symoff  = sizeof(struct load_cmds);

    cmd->seg.cmd 	= LC_SEGMENT;
    cmd->seg.cmdsize 	= sizeof(struct segment_command);
    strcpy(cmd->seg.segname, SEG_LINKEDIT);
    cmd->seg.vmaddr 	= 0;
    cmd->seg.vmsize 	= 0;
    cmd->seg.fileoff 	= cmd->symcmd.symoff;
    cmd->seg.filesize 	= symtabsize;
    cmd->seg.maxprot 	= 7;
    cmd->seg.initprot 	= 1;
    cmd->seg.nsects 	= 0;
    cmd->seg.flags 	= 0;

    sym = (struct nlist *) (cmd + 1);
    for (idx = 0; idx < symcmd->nsyms; idx++, sym++)
    {
	if ( (sym->n_type & N_STAB) != 0)
	{
	    sym->n_type = N_ABS;
	    sym->n_desc  = 0;
	    sym->n_value = sym->n_un.n_strx;
	    sym->n_un.n_strx = 0;
	    sym->n_sect = NO_SECT;
	}
	else if ( (sym->n_type & N_TYPE) == N_SECT)
	{
	    sym->n_sect = NO_SECT;
	    sym->n_type = (sym->n_type & ~N_TYPE) | N_ABS;
	}
    }
    if (log_level >= kload_log_level_load_details)
    {
	kload_log_message("__kload_keep_symbols %s, nsyms %ld, 0x%x bytes" KNL, 
			    entry->name, symcmd->nsyms, size);
    }

    entry->symbols	  = mem;
    entry->symbols_malloc = mem;
    entry->symbols_length = size;

    return kload_error_none;
}


/*******************************************************************************
* This function can only operate on 32 bit mach object files
*******************************************************************************/
static
kload_error __kload_make_opaque_basefile(dgraph_t * dgraph, struct mach_header * hdr)
{
    struct segment_command * 	seg;
    struct segment_command * 	data_seg;
    struct segment_command * 	text_seg;
    struct section *         	sec;
    unsigned int	     	j;
    vm_offset_t		     	offset;
    unsigned long		idx, ncmds;
    vm_size_t	  		size;
    vm_address_t  		mem, out;
    static vm_address_t		keep_base_image;
    static vm_size_t		keep_base_size;

    if (dgraph->opaque_base_image)
	return kload_error_none;

    if (keep_base_image)
    {
	dgraph->opaque_base_image  = keep_base_image;
	dgraph->opaque_base_length = keep_base_size;
	return kload_error_none;
    }

    data_seg = text_seg = NULL;
    ncmds = hdr->ncmds;
    seg = (struct segment_command *)(hdr + 1);
    for (idx = 0;
            idx < ncmds;
            idx++, seg = (struct segment_command *)(((vm_offset_t)seg) + seg->cmdsize))
    {
        if (LC_SEGMENT != seg->cmd)
	    continue;
	if (!strcmp(SEG_TEXT, seg->segname))
	    text_seg = seg;
	else if (!strcmp(SEG_DATA, seg->segname))
	    data_seg = seg;
    }
    if (!text_seg || !data_seg)
    {
        kload_log_error("no SEG_TEXT or SEG_DATA" KNL);
	return kload_error_unspecified;
    }

    size = sizeof(struct mach_header) + text_seg->cmdsize + data_seg->cmdsize;
    mem = (vm_offset_t) malloc(size);

    out = mem;
    bcopy(hdr, (void *) out, sizeof(struct mach_header));
    hdr = (struct mach_header *) out;
    out += sizeof(struct mach_header);

    bcopy(text_seg, (void *) out, text_seg->cmdsize);
    text_seg = (struct segment_command *) out;
    out += text_seg->cmdsize;

    bcopy(data_seg, (void *) out, data_seg->cmdsize);
    data_seg = (struct segment_command *) out;
    out += data_seg->cmdsize;

    hdr->ncmds = 2;
    hdr->sizeofcmds = text_seg->cmdsize + data_seg->cmdsize;

    offset = hdr->sizeofcmds;

    text_seg->fileoff  = offset;
    text_seg->filesize = 0;

    sec = (struct section *)(text_seg + 1);
    for (j = 0; j < text_seg->nsects; j++, sec++)
    {
//	sec->addr   = (unsigned long) addr;
	sec->size   = 0;
	sec->offset = offset;
	sec->nreloc = 0;
    }

    data_seg->fileoff  = offset;
    data_seg->filesize = 0;

    sec = (struct section *)(data_seg + 1);
    for (j = 0; j < data_seg->nsects; j++, sec++)
    {
//	sec->addr   = (unsigned long) addr;
	sec->size   = 0;
	sec->offset = offset;
	sec->nreloc = 0;
    }

    dgraph->opaque_base_image  = mem;
    dgraph->opaque_base_length = size;
    keep_base_image	       = mem;
    keep_base_size	       = size;

    return kload_error_none;
}

/*******************************************************************************
*
*******************************************************************************/
static
kload_error __kload_load_modules(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file,
    const char * patch_file,
    const char * patch_dir,
    const char * symbol_file,
    const char * symbol_dir,
    int do_load,
    int do_start_kmod,
    int do_prelink,
    int interactive_level,
    int ask_overwrite_symbols,
    int overwrite_symbols
#endif /* not KERNEL */
    )
{
    kload_error result = kload_error_none;
#ifndef KERNEL
    long int kernel_size = 0;
    kern_return_t mach_result = KERN_SUCCESS;
#endif /* not KERNEL */
    char * kernel_base_addr = 0;
    int kld_result;
    Boolean cleanup_kld_loader = false;
    unsigned int i;

   /* We have to map all object files to get their CFBundleIdentifier
    * names.
    */
#ifndef KERNEL
    result = kload_map_dgraph(dgraph, kernel_file);
#else
    result = kload_map_dgraph(dgraph);
#endif /* not KERNEL */
    if (result != kload_error_none) {
        kload_log_error("error mapping object files" KNL);
        goto finish;
    }

#ifndef KERNEL
    result = __kload_patch_dgraph(dgraph, kernel_file);
#else
    result = __kload_patch_dgraph(dgraph);
#endif /* not KERNEL */
    if (result != kload_error_none) {
        // FIXME: print an error message here?
        goto finish;
    }

#ifndef KERNEL
    // FIXME: check error return
    __kload_output_patches(dgraph, patch_file, patch_dir,
        ask_overwrite_symbols, overwrite_symbols);

   /*****
    * If we're not loading or writing symbols, we're done.
    */
    if (!do_load && !do_prelink && !symbol_file && !symbol_dir) {
        goto finish;
    }

    if (do_load && PORT_NULL == G_kernel_port) {
        mach_result = task_for_pid(mach_task_self(), 0, &G_kernel_port);
        if (mach_result != KERN_SUCCESS) {
            kload_log_error("unable to get kernel task port: %s" KNL,
                mach_error_string(mach_result));
            kload_log_error("you must be running as root to load "
                "modules into the kernel" KNL);
            result = kload_error_kernel_permission;
            goto finish;
        }
    }
#endif /* not KERNEL */

    kld_address_func(&__kload_linkedit_address);

#ifndef KERNEL
    G_syms_only = (!do_load) && (symbol_file || symbol_dir || patch_dir);

    kernel_base_addr = kld_file_getaddr(kernel_file, &kernel_size);
    if (!kernel_base_addr) {
        kload_log_error(
            "can't get load address for kernel %s" KNL, kernel_file);
        result = kload_error_link_load;
        goto finish;
    }
#else /* KERNEL */

    const char * kernel_file = "(kernel)";
    kernel_base_addr = (char *) &_mh_execute_header;

#endif /* not KERNEL */

    kld_result = true;
    if (dgraph->has_symbol_sets)
    {
	result = __kload_make_opaque_basefile(dgraph, (struct mach_header *) kernel_base_addr);
	if (result != kload_error_none) {
	    kload_log_error("can't construct opaque base image from %s" KNL, kernel_file);
	    goto finish;
	}

	kld_result = kld_load_basefile_from_memory(kernel_file,
			    (char *)  dgraph->opaque_base_image, 
				       dgraph->opaque_base_length);
    }
#ifndef KERNEL
    else
	kld_result = kld_load_basefile_from_memory(kernel_file,
			    (char *)  kernel_base_addr, kernel_size);
#endif /* not KERNEL */

    if (!kld_result) {
	kload_log_error("can't link base image %s" KNL, kernel_file);
	result = kload_error_link_load;
	goto finish;
    }

    cleanup_kld_loader = true;
    char opaque_now = false;

    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * current_entry = dgraph->load_order[i];

	opaque_now |= current_entry->opaque_link;

	if (kOpaqueLink & opaque_now)
	{
	    unsigned int k, j;

	    if (log_level >= kload_log_level_load_details)
	    {
		kload_log_message("opaque link for %s" KNL, current_entry->name);
	    }

	    kld_set_link_options(KLD_STRIP_ALL);	// KLD_STRIP_NONE

	    if (dgraph->have_loaded_symbols)
	    {
		kld_unload_all(1);
                if (kRawKernelLink & current_entry->opaque_link) {
#ifndef KERNEL
                    kld_result = kld_load_basefile_from_memory(kernel_file,
                                                       (char *)  kernel_base_addr, kernel_size);
#endif
                } else {
                    kld_result = kld_load_basefile_from_memory(kernel_file,
                                                        (char *)  dgraph->opaque_base_image, 
                                                                    dgraph->opaque_base_length);
                    dgraph->have_loaded_symbols = false;
                }
		if (!kld_result) {
		    kload_log_error("can't link base image %s" KNL, kernel_file);
		    result = kload_error_link_load;
		    goto finish;
		}
	    }

	    for (j = 0; j < i; j++)
	    {

		dgraph_entry_t * image_dep = dgraph->load_order[j];

                if (current_entry->opaque_link)
                {
                    for (k = 0;
                        (k < current_entry->num_dependencies)
                        && (current_entry->dependencies[k] != image_dep);
                        k++)	{}
    
                    if (k == current_entry->num_dependencies)
                        continue;
                }

                if (!current_entry->opaque_link && image_dep->opaques)
                {
                    // kpi not on direct dependency list
                    continue;
                }
                if (kRawKernelLink & image_dep->opaques)
                {
                    // raw kernel already in base image
                    continue;
                }

		if (!image_dep->symbols)
		{
		    kload_log_error("internal error; no dependent symbols" KNL);
                    result = kload_error_link_load;
		    goto finish;
		}
		else
		{
		    struct mach_header * kld_header;

#ifndef KERNEL
		    kld_result = kld_load_from_memory(&kld_header, image_dep->name,
			    (char *) image_dep->symbols, image_dep->symbols_length, NULL);
#else
		    kld_result = kld_load_from_memory(&kld_header, image_dep->name,
			    (char *) image_dep->symbols, image_dep->symbols_length);
#endif /* not KERNEL */
		    if (!kld_result) {
			kload_log_error("can't link dependent image %s" KNL, image_dep->name);
			result = kload_error_link_load;
			goto finish;
		    }
		    kld_forget_symbol("_kmod_info");
		    dgraph->have_loaded_symbols = true;
		}
	    }
	} /* opaque_now */

	if (dgraph->has_opaque_links
#ifndef KERNEL
	    || symbol_file || symbol_dir
#endif
	    )
	    kld_set_link_options(KLD_STRIP_NONE);
	else
	    kld_set_link_options(KLD_STRIP_ALL);

#ifndef KERNEL
	result = __kload_load_module(dgraph, current_entry,
	    (current_entry == dgraph->root),
	    symbol_file, symbol_dir, do_load,
	    interactive_level, ask_overwrite_symbols, overwrite_symbols);
#else
        result = __kload_load_module(dgraph, current_entry,
            (current_entry == dgraph->root));
#endif /* not KERNEL */
        if (result != kload_error_none) {
            goto finish;
        }

	if (dgraph->has_opaque_links && (current_entry != dgraph->root))
	{
            if (!(kRawKernelLink & current_entry->opaques)) {
                result = __kload_keep_symbols(current_entry);
            }
	    if (result != kload_error_none) {
		kload_log_error("__kload_keep_symbols() failed for module %s" KNL,
		    current_entry->name);
		goto finish;
	    }
	}

#ifndef KERNEL
        if (do_load && current_entry->do_load) {
#else
        if (current_entry->do_load) {
#endif /* not KERNEL */
            result = __kload_set_module_dependencies(current_entry);
            if ( ! (result == kload_error_none ||
                    result == kload_error_already_loaded) ) {
                goto finish;
            }

#ifndef KERNEL
            if ( (interactive_level == 1 && current_entry == dgraph->root) ||
                 (interactive_level == 2) ) {

                int approve = (*__kload_approve_func)(1,
                    "\nStart module %s (ansering no will abort the load)",
                    current_entry->name);

                if (approve > 0) {
                    do_start_kmod = true; // override 'cause user said so
                } else {
                    kern_return_t mach_result;
                    if (approve < 0) {
                         kload_log_message("error reading user response; "
                            "destroying loaded module" KNL);
                    } else {
                         kload_log_message("user canceled module start; "
                            "destroying loaded module" KNL);
                    }
                    mach_result = kmod_destroy(G_kernel_priv_port, current_entry->kmod_id);
                    if (mach_result != KERN_SUCCESS) {
                        kload_log_error("kmod_destroy() failed" KNL);
                    }
                    if (approve < 0) {
                        result = kload_error_unspecified;
                        goto finish;
                    } else {
                        result = kload_error_user_abort;
                        goto finish;
                    }
                }
            }
#endif /* not KERNEL */

#ifndef KERNEL
            if (current_entry != dgraph->root ||
                (current_entry == dgraph->root && do_start_kmod)) {
#endif /* not KERNEL */

                result = __kload_start_module(current_entry);
                if ( ! (result == kload_error_none ||
                        result == kload_error_already_loaded) ) {
                    goto finish;
#ifndef KERNEL
                } else if (interactive_level ||
                           log_level >= kload_log_level_load_details) {
#else
                } else if (log_level >= kload_log_level_load_details) {
#endif /* not KERNEL */

                     kload_log_message("started module %s" KNL,
                        current_entry->name);
                } /* log_level */
#ifndef KERNEL
            } /* current_entry... */
#endif /* not KERNEL */


#ifndef KERNEL
        } /* if do_load */
#else
        } /* if do_load */
#endif /* not KERNEL */
    } /* for i, dgraph->length */

finish:

#ifndef KERNEL
   /* Dispose of the kernel port to prevent security breaches and port
    * leaks. We don't care about the kern_return_t value of this
    * call for now as there's nothing we can do if it fails.
    */
    if (PORT_NULL != G_kernel_port) {
        mach_port_deallocate(mach_task_self(), G_kernel_port);
        G_kernel_port = PORT_NULL;
    }
#endif /* not KERNEL */

    if (cleanup_kld_loader) {
        kld_unload_all(1);
    }

    return result;
}


/*******************************************************************************
*
*******************************************************************************/

#ifndef KERNEL
#define __KLOAD_SYMBOL_EXTENSION   ".sym"
#endif /* not KERNEL */

static
kload_error __kload_load_module(dgraph_t * dgraph,
    dgraph_entry_t * entry,
#ifdef KERNEL
    __unused int is_root
#else	/* not KERNEL */
    int is_root,
    const char * symbol_file,
    const char * symbol_dir,
    int do_load,
    int interactive_level,
    int ask_overwrite_symbols,
    int overwrite_symbols
    #endif /* not KERNEL */
    )
{
    kload_error result = kload_error_none;

    int kld_result;
    int mach_result;
    struct mach_header * kld_header;
    const char * kmod_symbol = "_kmod_info";
    unsigned long kernel_kmod_info;
    kmod_info_t * local_kmod_info = NULL;
    char * dest_address = 0;
#ifndef KERNEL
    char * allocated_filename = NULL;
    char * symbol_filename = NULL;
    int file_check;
    vm_address_t vm_buffer = 0;
#endif /* not KERNEL */

   /* A kernel component is by nature already linked and loaded and has
    * no work to be done upon it.
    */
    if (entry->is_kernel_component && !entry->is_symbol_set) {
        result = kload_error_none;
        goto finish;
    }

    G_current_load_entry = entry;

    if (log_level >= kload_log_level_load_basic) {
#ifndef KERNEL
        if (do_load) {
#endif /* not KERNEL */
            kload_log_message("link/loading file %s" KNL, entry->name);
#ifndef KERNEL
        } else {
            kload_log_message("linking file %s" KNL, entry->name);
        }
#endif /* not KERNEL */
    }

#ifndef KERNEL
    if (entry->link_output_file != entry->name) {
	symbol_filename = entry->link_output_file;
    }

    if (symbol_filename) {
        file_check = kload_file_exists(symbol_filename);
        if (file_check < 0) {
            kload_log_error("error checking existence of file %s" KNL,
                symbol_filename);
        } else if (file_check > 0 && !overwrite_symbols) {

            if (!ask_overwrite_symbols) {
                kload_log_message("symbol file %s exists; not overwriting" KNL,
                    symbol_filename);
                symbol_filename = NULL;
            } else {
                int approve = (*__kload_approve_func)(1,
                    "\nSymbol file %s exists; overwrite", symbol_filename);

                if (approve < 0) {
                    result = kload_error_unspecified;
                    goto finish;
                } else if (approve == 0) {
                    if (allocated_filename) free(allocated_filename);
                    allocated_filename = NULL;
                    symbol_filename = NULL;
                }
            }
        }
    }

    if (symbol_filename &&
        (interactive_level ||
         log_level >= kload_log_level_basic) ) {

        kload_log_message("writing symbol file %s" KNL, symbol_filename);
    }

    if (do_load) {
        if (interactive_level && entry->loaded_address) {
            kload_log_message(
                "module %s is already loaded as %s at address 0x%08x" KNL,
                entry->name, entry->expected_kmod_name,
                entry->loaded_address);
        } else if ( (interactive_level == 1 && is_root) ||
             (interactive_level == 2) ) {

            int approve = (*__kload_approve_func)(1,
                "\nLoad module %s", entry->name);

            if (approve < 0) {
                result = kload_error_unspecified;
                goto finish;
            } else if (approve == 0) {
                result = kload_error_user_abort;
                goto finish;
            }
        }
    }
#endif /* not KERNEL */

    entry->object = kld_file_getaddr(entry->name, &entry->object_length);
    if (!entry->object) {
        kload_log_error("kld_file_getaddr() failed for module %s" KNL,
            entry->name);
        __kload_clear_kld_globals();
        result = kload_error_link_load;
        goto finish;
    }

    if (entry->is_symbol_set) {
	entry->symbols        = (vm_address_t) entry->object;
	entry->symbols_length = entry->object_length;

#ifndef KERNEL
	if (symbol_filename) {
	    if (!_IOWriteBytesToFile(symbol_filename, (void *) entry->symbols, entry->symbols_length)) {
		kload_log_error("write symbol file failed for module %s" KNL,
		    entry->name);
		__kload_clear_kld_globals();
		result = kload_error_link_load;
		goto finish;
	    }
	    symbol_filename = 0;
	    if (G_prelink && (entry->name != entry->link_output_file))
	    {
		kload_log_error("prelink %s %s %s" KNL,
		    entry->name, entry->link_output_file, entry->expected_kmod_name);
		register_prelink(entry, NULL, NULL);
	    }
	}
#endif /* not KERNEL */
	if (entry->opaques) {
	    result = kload_error_none;
	    goto finish;
	}
    }

#ifndef KERNEL
    kld_result = kld_load_from_memory(&kld_header, entry->name,
	    entry->object, entry->object_length, symbol_filename);
#else
    kld_result = kld_load_from_memory(&kld_header, entry->name,
	    entry->object, entry->object_length);
#endif /* not KERNEL */

#ifndef KERNEL
    fflush(stdout);
    fflush(stderr);
#endif /* not KERNEL */

    dgraph->have_loaded_symbols = true;

    if (!kld_result || !entry->kernel_load_address) {
        kload_log_error("kld_load_from_memory() failed for module %s" KNL,
            entry->name);
        __kload_clear_kld_globals();
        entry->need_cleanup = 1;
        result = kload_error_link_load;
        goto finish;
    }

    if (entry->is_symbol_set) {
        result = kload_error_none;
        goto finish;
    }

    entry->linked_image = kld_header;
    entry->linked_image_length = -1;	// unknown!

/* If we're in the kernel and not loading (as when handling an
 * already-loaded dependency), we don't need to waste any CPU
 * cycles looking up the kmod_info struct.
 */
#ifdef KERNEL
    if (entry->do_load) {
#endif /* KERNEL */

    kld_result = kld_lookup(kmod_symbol, &kernel_kmod_info);
    if (!kld_result) {
        kload_log_error("kld_lookup(\"%s\") failed for module %s" KNL,
            kmod_symbol, entry->name);
        entry->need_cleanup = 1;
        result = kload_error_link_load;
        goto finish;
    }

#ifdef KERNEL
    }
#endif /* KERNEL */

    kld_result = kld_forget_symbol(kmod_symbol);
#ifndef KERNEL
    fflush(stdout);
    fflush(stderr);
#endif /* not KERNEL */
    if (!kld_result) {
        kload_log_error("kld_forget_symbol(\"%s\") failed for module %s" KNL,
            kmod_symbol, entry->name);
        entry->need_cleanup = 1;
        result = kload_error_link_load;
        goto finish;
    }

/* This section is always done in userland, but in kernel space
 * only if we're loading the kext, because what we have in kernel
 * space for an already-loaded kext is the kext itself, which
 * must not be touched again after it's been loaded and started.
 */
#ifdef KERNEL
    if (entry->do_load)
#endif /* KERNEL */
    {


   /* Get the linked image's kmod_info by translating from the
    * destined kernel-space address at kernel_kmod_info to an
    * offset from kld_header.
    */
    local_kmod_info = (kmod_info_t *)((unsigned long)kernel_kmod_info -
        (unsigned long)G_current_load_entry->kernel_load_address +
        (unsigned long)kld_header);

   /* Stamp the bundle ID and version from the entry over anything
    * resident inside the kmod.
    */
    bzero(local_kmod_info->name, sizeof(local_kmod_info->name));
    strcpy(local_kmod_info->name, entry->expected_kmod_name);

    bzero(local_kmod_info->version, sizeof(local_kmod_info->version));
    strcpy(local_kmod_info->version, entry->expected_kmod_vers);

    if (log_level >= kload_log_level_details) {
        kload_log_message("kmod name: %s" KNL, local_kmod_info->name);
        kload_log_message("kmod start @ 0x%x (offset 0x%lx)" KNL,
           (vm_address_t)local_kmod_info->start,
           (unsigned long)local_kmod_info->start - (unsigned long)G_current_load_entry->kernel_load_address);
        kload_log_message("kmod stop @ 0x%x (offset 0x%lx)" KNL,
           (vm_address_t)local_kmod_info->stop,
           (unsigned long)local_kmod_info->stop - (unsigned long)G_current_load_entry->kernel_load_address);
    }

    if (!local_kmod_info->start || !local_kmod_info->start) {
        kload_log_error(
            "error for module file %s; start or stop address is zero" KNL,
            entry->name);
        entry->need_cleanup = 1;
        result = kload_error_link_load;
        goto finish;
    }

   /* Record link info into kmod_info struct, rounding the hdr_size
    * to fit the adjustment that was made in __kload_linkedit_address().
    */
    if (entry->kernel_alloc_address) {
        local_kmod_info->address = entry->kernel_alloc_address;
    } else {
        local_kmod_info->address = entry->loaded_address;
    }
    local_kmod_info->size = entry->kernel_alloc_size;
    local_kmod_info->hdr_size = round_page(entry->kernel_hdr_size);

    }

#ifndef KERNEL
    if (G_prelink && (entry->name != entry->link_output_file))
    {
	register_prelink(entry, local_kmod_info, kernel_kmod_info);
    }

    if (do_load && entry->do_load) {
        mach_result = vm_allocate(mach_task_self(), &vm_buffer,
            entry->kernel_alloc_size, VM_FLAGS_ANYWHERE);
        if (mach_result != KERN_SUCCESS) {
            kload_log_error("unable to vm_allocate() copy buffer" KNL);
            entry->need_cleanup = 1;
            result = kload_error_no_memory;  // FIXME: kernel error?
            goto finish;
        }

        dest_address = (char *)vm_buffer;

        memcpy(dest_address, kld_header, entry->kernel_hdr_size);
        memcpy(dest_address + round_page(entry->kernel_hdr_size),
               (void *)((unsigned long)kld_header + entry->kernel_hdr_size),
               entry->kernel_load_size - entry->kernel_hdr_size);

        mach_result = vm_write(G_kernel_port, entry->kernel_alloc_address,
            vm_buffer, entry->kernel_alloc_size);
        if (mach_result != KERN_SUCCESS) {
            kload_log_error("unable to write module to kernel memory" KNL);
            entry->need_cleanup = 1;
            result = kload_error_kernel_error;
            goto finish;
        }

        mach_result = kmod_create(G_kernel_priv_port,
            (vm_address_t)kernel_kmod_info, &(entry->kmod_id));

#else
    if (entry->do_load) {
        dest_address = (char *)entry->kernel_alloc_address;
        memcpy(dest_address, kld_header, entry->kernel_hdr_size);
        memcpy(dest_address + round_page(entry->kernel_hdr_size),
               (void *)((unsigned long)kld_header + entry->kernel_hdr_size),
               entry->kernel_load_size - entry->kernel_hdr_size);

       /* We've written data & instructions into kernel memory, so flush
        * the data cache and invalidate the instruction cache.
        */
        flush_dcache(entry->kernel_alloc_address, entry->kernel_alloc_size, false);
        invalidate_icache(entry->kernel_alloc_address, entry->kernel_alloc_size, false);

        mach_result = kmod_create_internal(
            (kmod_info_t *)kernel_kmod_info, &(entry->kmod_id));

#endif /* not KERNEL */

        if (mach_result != KERN_SUCCESS) {
            kload_log_error("unable to register module with kernel" KNL);
            entry->need_cleanup = 1;
            result = kload_error_kernel_error;
            goto finish;
        }

#ifndef KERNEL
        if (interactive_level || log_level >= kload_log_level_load_basic) {
#else
        if (log_level >= kload_log_level_load_basic) {
#endif /* not KERNEL */
            kload_log_message(
                "module %s created as # %d at address 0x%x, size %ld" KNL,
                entry->expected_kmod_name, entry->kmod_id,
                entry->kernel_alloc_address,
                entry->kernel_alloc_size);

#ifndef KERNEL
        }
#else
        }
#endif /* not KERNEL */

#ifndef KERNEL
        if (interactive_level) {
            kload_log_message(
                "You can now break to the debugger and set breakpoints "
                " for this extension." KNL);
        }
#endif /* not KERNEL */

#ifndef KERNEL
    }
#else
    }
#endif /* not KERNEL */

finish:

#ifndef KERNEL
    if (allocated_filename) {
        free(allocated_filename);
    }
    if (vm_buffer) {
        vm_deallocate(mach_task_self(), vm_buffer, entry->kernel_alloc_size);
    }
#endif /* not KERNEL */
    __kload_clear_kld_globals();

    return result;
}

/*******************************************************************************
*******************************************************************************/

#ifndef KERNEL
static kload_error
register_prelink(dgraph_entry_t * entry, 
		    kmod_info_t * local_kmod_info, vm_offset_t kernel_kmod_info)
{
    CFIndex i, j, depoffset;
    Boolean exists;
    kmod_info_t desc;

    depoffset = CFDataGetLength(G_prelink_dependencies) / sizeof(CFIndex);

    for (i = 0; i < entry->num_dependencies; i++)
    {
	exists = false;
	for (j = 1; (j < (1 + G_prelink->modules[0].id)); j++)
	{
	    exists = (0 == strcmp(entry->dependencies[i]->expected_kmod_name,
				    G_prelink->modules[j].name));
	    if (exists)
		break;
	}
	if (!exists)
	{
	    bzero(&desc, sizeof(desc));
	    strcpy(desc.name, entry->dependencies[i]->expected_kmod_name);

	    if (log_level >= kload_log_level_basic) {
		kload_log_message("[%d] (dep)\n    %s" KNL, 
				    G_prelink->modules[0].id + 1, desc.name);
	    }
	    G_prelink->modules[0].id++;
	    CFDataAppendBytes(G_prelink_data, (UInt8 *) &desc, sizeof(desc));
	    G_prelink = (struct PrelinkState *) CFDataGetMutableBytePtr(G_prelink_data);
	}

	G_prelink->modules[0].reference_count++;
	OSWriteBigInt32(&j, 0, j);
	CFDataAppendBytes(G_prelink_dependencies, (UInt8 *) &j, sizeof(j));
    }
    if (log_level >= kload_log_level_basic) {
	kload_log_message("[%d] 0x%08x info 0x%08x\n    %s,\n    %s" KNL, 
			    G_prelink->modules[0].id + 1, entry->kernel_load_address,
			    kernel_kmod_info, entry->link_output_file, entry->name);
    }

    if (local_kmod_info)
	desc = *local_kmod_info;
    else
    {
	bzero(&desc, sizeof(desc));
	desc.size = entry->symbols_length;
    }

    desc.id = kernel_kmod_info;
    desc.reference_count = entry->num_dependencies;
    desc.reference_list  = (kmod_reference_t *) depoffset;

    /* Stamp the bundle ID and version from the entry over anything
    * resident inside the kmod.
    */
    bzero(desc.name, sizeof(local_kmod_info->name));
    strcpy(desc.name, entry->expected_kmod_name);
    bzero(desc.version, sizeof(local_kmod_info->version));
    strcpy(desc.version, entry->expected_kmod_vers);

    G_prelink->modules[0].id++;
    CFDataAppendBytes(G_prelink_data, (UInt8 *) &desc, sizeof(desc));
    G_prelink = (struct PrelinkState *) CFDataGetMutableBytePtr(G_prelink_data);

    return kload_error_none;
}

#endif

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
#ifndef KERNEL
kload_error kload_map_dgraph(
    dgraph_t * dgraph,
    const char * kernel_file)
#else
kload_error kload_map_dgraph(
    dgraph_t * dgraph)
#endif /* not KERNEL */
{
    kload_error result = kload_error_none;
    unsigned int i;

    if (log_level >= kload_log_level_load_details) {
#ifndef KERNEL
        kload_log_message("mapping the kernel file %s" KNL, kernel_file);
#else
        kload_log_message("mapping the kernel" KNL);
#endif /* not KERNEL */
    }

#ifndef KERNEL
    if (!kld_file_map(kernel_file)) {
        result = kload_error_link_load;
        goto finish;
    }
#endif /* not KERNEL */

    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * entry = dgraph->load_order[i];

        if (entry->is_kernel_component && !entry->is_symbol_set) {
            continue;
        }

        result = kload_map_entry(entry);
        if (result != kload_error_none) {
            goto finish;
        }
    }

finish:
    return result;

}

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
kload_error kload_map_entry(dgraph_entry_t * entry)
{
    kload_error result = kload_error_none;

    if (entry->is_kernel_component && !entry->is_symbol_set) {
        kload_log_error("attempt to map kernel component %s" KNL, entry->name);
        result = kload_error_invalid_argument;
        goto finish;
    }

    if (log_level >= kload_log_level_load_details) {
        kload_log_message("mapping module file %s" KNL, entry->name);
    }

    if (kld_file_getaddr(entry->name, NULL)) {
        if (log_level >= kload_log_level_load_details) {
            kload_log_message("module file %s is already mapped" KNL, entry->name);
        }
        result = kload_error_none;
        goto finish;
    }

#ifndef KERNEL
    if (!kld_file_map(entry->name)) {
#else
    if (!kld_file_map(entry->name, entry->object, entry->object_length,
         entry->object_is_kmem)) {
#endif /* not KERNEL */
        kload_log_error("error mapping module file %s" KNL, entry->name);

        result = kload_error_link_load;
        goto finish;
#ifndef KERNEL
    }
#else
    }
#endif /* not KERNEL */

    entry->is_mapped = true;
    
   /* Clear these bits now, as the kld patch module now owns the info
    * and it is subject to change. We reset them in the entry from the
    * kld patch module as needed.
    */
    entry->object = 0;
    entry->object_length = 0;
#ifdef KERNEL
    entry->object_is_kmem = false;
#endif /* KERNEL */

    // FIXME: Stop using this symbol; have the info passed in by
    // FIXME: ...the kext management library.
#ifndef KERNEL
    if (!entry->is_kernel_component && !kld_file_lookupsymbol(entry->name, "_kmod_info")) {
        kload_log_error("%s does not not contain kernel extension code" KNL,
            entry->name);
        result = kload_error_executable_bad;
        goto finish;
    }
#endif /* not KERNEL */

finish:
    return result;
}

#ifndef KERNEL
/*******************************************************************************
*
*******************************************************************************/
kload_error kload_request_load_addresses(
    dgraph_t * dgraph,
    const char * kernel_file)
{
    kload_error result = kload_error_none;
    int i;
    const char * user_response = NULL;  // must free
    int scan_result;
    unsigned int address;

   /* We have to map all object files to get their CFBundleIdentifier
    * names.
    */
    result = kload_map_dgraph(dgraph, kernel_file);
    if (result != kload_error_none) {
        kload_log_error("error mapping object files" KNL);
        goto finish;
    }

    // fixme: this shouldn't be printf, should it?
    printf("enter the hexadecimal load addresses for these modules:\n");

    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * entry = dgraph->load_order[i];

        if (!entry) {
            result = kload_error_unspecified;
            goto finish;
        }

        if (entry->is_kernel_component) {
            continue;
        }

        if (!entry->is_mapped) {
            result = kload_error_unspecified;
            goto finish;
        }

        user_response = __kload_input_func("%s:",
            entry->expected_kmod_name);
        if (!user_response) {
            result = kload_error_unspecified;
            goto finish;
        }
        scan_result = sscanf(user_response, "%x", &address);
        if (scan_result < 1 || scan_result == EOF) {
            result = kload_error_unspecified;
            goto finish;
        }
        entry->loaded_address = address;
    }

finish:
    return result;

}

/*******************************************************************************
* addresses is a NULL-terminated list of string of the form "module_id@address"
*******************************************************************************/
kload_error kload_set_load_addresses_from_args(
    dgraph_t * dgraph,
    const char * kernel_file,
    char ** addresses)
{
    kload_error result = kload_error_none;
    int i, j;


   /* We have to map all object files to get their CFBundleIdentifier
    * names.
    */
    result = kload_map_dgraph(dgraph, kernel_file);
    if (result != kload_error_none) {
        kload_log_error("error mapping object files" KNL);
        goto finish;
    }

   /*****
    * Run through and assign all addresses to their relevant module
    * entries.
    */
    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * entry = dgraph->load_order[i];

        if (!entry) {
            result = kload_error_unspecified;
            goto finish;
        }

        if (entry->is_kernel_component) {
            continue;
        }

        if (!entry->is_mapped) {
            result = kload_error_unspecified;
            goto finish;
        }

        for (j = 0; addresses[j]; j++) {
            char * this_addr = addresses[j];
            char * address_string = NULL;
            unsigned int address;
            unsigned int module_namelen = strlen(entry->expected_kmod_name);

            if (!this_addr) {
                result = kload_error_unspecified;
                goto finish;
            }

            if (strncmp(this_addr, entry->expected_kmod_name, module_namelen)) {
                continue;
            }
            if (this_addr[module_namelen] != '@') {
                continue;
            }

            address_string = index(this_addr, '@');
            if (!address_string) {
                result = kload_error_unspecified;
                goto finish;
            }
            address_string++;
            address = strtoul(address_string, NULL, 16);
            entry->loaded_address = address;
        }
    }

   /*****
    * Now that we've done that see that all non-kernel modules do have
    * addresses set. If even one doesn't, we can't complete the link
    * relocation of symbols, so return a usage error.
    */
    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * entry = dgraph->load_order[i];

        if (entry->is_kernel_component) {
            continue;
        }

        if (!entry->loaded_address) {
            result = kload_error_invalid_argument;
            goto finish;
        }
    }

finish:
    return result;

}

/*******************************************************************************
* This function requires G_kernel_priv_port to be set before it will work.
*******************************************************************************/
kload_error kload_set_load_addresses_from_kernel(
    dgraph_t * dgraph,
    const char * kernel_file,
    int do_load)
{
    kload_error result = kload_error_none;
    int mach_result;
    kmod_info_t * loaded_modules = NULL;
    int           loaded_bytecount = 0;
    unsigned int i;


   /*****
    * We have to map the dgraph's modules before checking whether they've
    * been loaded.
    */
    result = kload_map_dgraph(dgraph, kernel_file);
    if (result != kload_error_none) {
        kload_log_error("can't map module files" KNL);
        goto finish;
    }


   /* First clear all the load addresses.
    */
    for (i = 0; i < dgraph->length; i++) {
        struct dgraph_entry_t * entry = dgraph->load_order[i];
        entry->loaded_address = 0;
    }

    mach_result = kmod_get_info(G_kernel_priv_port,
	    (void *)&loaded_modules, &loaded_bytecount);
    if (mach_result != KERN_SUCCESS) {
        kload_log_error("kmod_get_info() failed" KNL);
        result = kload_error_kernel_error;
        goto finish;
    }

   /*****
    * Find out which modules have already been loaded & verify
    * that loaded versions are same as requested.
    */
    for (i = 0; i < dgraph->length; i++) {
        kload_error cresult;
        dgraph_entry_t * current_entry = dgraph->load_order[i];

       /* If necessary, check whether the current module is already loaded.
        * (We already did the root module above.)
        */
        cresult = __kload_check_module_loaded(dgraph, current_entry,
            loaded_modules, do_load);
        if ( ! (cresult == kload_error_none ||
                cresult == kload_error_already_loaded) ) {
            goto finish;
        }
        if (current_entry == dgraph->root &&
            cresult == kload_error_already_loaded) {

            result = cresult;
        }
    }

finish:

    if (loaded_modules) {
        vm_deallocate(mach_task_self(), (vm_address_t)loaded_modules,
            loaded_bytecount);
        loaded_modules = 0;
    }

    return result;
}

#else
/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
kload_error kload_set_load_addresses_from_kernel(
    dgraph_t * dgraph)
{
    kload_error result = kload_error_none;
#ifndef KERNEL
    int mach_result;
    kmod_info_t * loaded_modules = NULL;
    int           loaded_bytecount = 0;
#endif /* not KERNEL */
    unsigned int i;


   /*****
    * We have to map the dgraph's modules before checking whether they've
    * been loaded.
    */
    result = kload_map_dgraph(dgraph);
    if (result != kload_error_none) {
        kload_log_error("can't map module files" KNL);
        goto finish;
    }


   /* First clear all the load addresses.
    */
    for (i = 0; i < dgraph->length; i++) {
        struct dgraph_entry_t * entry = dgraph->load_order[i];
        entry->loaded_address = 0;
    }

   /*****
    * Find out which modules have already been loaded & verify
    * that loaded versions are same as requested.
    */
    for (i = 0; i < dgraph->length; i++) {
        kload_error cresult;
        dgraph_entry_t * current_entry = dgraph->load_order[i];

       /* If necessary, check whether the current module is already loaded.
        * (We already did the root module above.)
        */
        cresult = __kload_check_module_loaded(dgraph, current_entry, false);
        if ( ! (cresult == kload_error_none ||
                cresult == kload_error_already_loaded) ) {
            goto finish;
        }
        if (current_entry == dgraph->root &&
            cresult == kload_error_already_loaded) {

            result = cresult;
        }
    }

finish:

    return result;
}
#endif /* not KERNEL */

/*******************************************************************************
*
*******************************************************************************/
#ifdef KERNEL
extern kern_return_t kmod_load_from_cache(const char * kmod_name);
#endif /* KERNEL */

static kmod_info_t * __kload_find_kmod_info(const char * kmod_name
#ifndef KERNEL
    ,
    kmod_info_t * kmod_list
#endif /* not KERNEL */
    )
{
#ifndef KERNEL
    unsigned int i;

    for (i = 0; ; i++) {
        kmod_info_t * current_kmod = &(kmod_list[i]);
        if (0 == strcmp(current_kmod->name, kmod_name)) {
            return current_kmod;
        }
        if (kmod_list[i].next == 0) {
            break;
        }
    }
    return NULL;
#else
    kmod_info_t * info;
    info = kmod_lookupbyname_locked(kmod_name);
    if (!info && (KERN_SUCCESS == kmod_load_from_cache(kmod_name))) {
	info = kmod_lookupbyname_locked(kmod_name);
    }
    return info;
#endif /* not KERNEL */
}

/*******************************************************************************
*
*******************************************************************************/
static
kload_error __kload_check_module_loaded(
    dgraph_t * dgraph,
    dgraph_entry_t * entry,
#ifndef KERNEL
    kmod_info_t * kmod_list,
#endif /* not KERNEL */
    int log_if_already)
{
    kload_error result = kload_error_none;
    const char * kmod_name;
    kmod_info_t * current_kmod = 0;

    VERS_version entry_vers;
    VERS_version loaded_vers;

    if (false && entry->is_kernel_component) {
        kmod_name = entry->name;
    } else {
        kmod_name = entry->expected_kmod_name;
        if (log_level >= kload_log_level_load_details) {
            kload_log_message("checking whether module file %s is already loaded" KNL,
                kmod_name);
        }
    }

#ifndef KERNEL
    current_kmod = __kload_find_kmod_info(kmod_name, kmod_list);
#else
    current_kmod = __kload_find_kmod_info(kmod_name);
#endif /* not KERNEL */

    if (!current_kmod) {
        goto finish;
    }

    entry->do_load = 0;
    entry->kmod_id = current_kmod->id;
    entry->loaded_address = current_kmod->address;

    if (entry->is_kernel_component) {
        goto finish;
    }

    if (log_level >= kload_log_level_load_details) {
        kload_log_message("module file %s is loaded; checking status" KNL,
            kmod_name);
    }

    // We really want to move away from having this info in a kmod....
    //
    loaded_vers = VERS_parse_string(current_kmod->version);
    if (loaded_vers < 0) {
        kload_log_error(
            "can't parse version string \"%s\" of loaded module %s" KNL,
            current_kmod->version,
            current_kmod->name);
        result = kload_error_unspecified;
        goto finish;
    }

    entry_vers = VERS_parse_string(entry->expected_kmod_vers);
    if (entry_vers < 0) {
        kload_log_error(
            "can't parse version string \"%s\" of module file %s" KNL,
            entry->expected_kmod_name,
            kmod_name);
        result = kload_error_unspecified;
        goto finish;
    }

    if (loaded_vers != entry_vers) {
        kload_log_error(
            "loaded version %s of module %s differs from "
            "requested version %s" KNL,
            current_kmod->version,
            current_kmod->name,
            entry->expected_kmod_name);
        if (entry == dgraph->root) {
            result = kload_error_loaded_version_differs;
        } else {
            result = kload_error_dependency_loaded_version_differs;
        }
        goto finish;
    } else {

        if (log_if_already && log_level >=
                kload_log_level_load_basic) {

            kload_log_message(
                "module %s (identifier %s) is already loaded" KNL,
                entry->name, kmod_name);
        }
        result = kload_error_already_loaded;
        goto finish;
    }

finish:
#ifdef KERNEL
    // Do this ONLY if in the kernel!
    if (current_kmod) {
        kfree(current_kmod, sizeof(kmod_info_t));
    }
#endif /* KERNEL */
    return result;
}

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
kload_error __kload_patch_dgraph(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file
#endif /* not KERNEL */
    )
{
    kload_error result = kload_error_none;
    unsigned int i;

#ifndef KERNEL
    if (!kld_file_merge_OSObjects(kernel_file)) {
        result = kload_error_link_load;
        goto finish;
    }
#endif /* not KERNEL */

    for (i = 0; i < dgraph->length; i++) {
        dgraph_entry_t * current_entry = dgraph->load_order[i];

       /* The kernel has already been patched.
        */
        if (current_entry->is_kernel_component) {
            continue;
        }

        if (log_level >= kload_log_level_load_details) {
            kload_log_message("patching C++ code in module %s" KNL,
                current_entry->name);
        }

#ifndef KERNEL
       /* In userland, we call the patch function for all kmods,
        * loaded or not, because we don't have all the info that
        * the kernel environment has.
        */
        if (!kld_file_patch_OSObjects(current_entry->name)) {
            result = kload_error_link_load;   // FIXME: need a "patch" error?
            goto finish;
        }
#else
       /* In the kernel, we call the merge function for already-loaded
        * kmods, since the kld patch environment retains info for kmods
        * that have already been patched. The patch function does a little
        * more work, and is only for kmods that haven't been processed yet.
        * NOTE: We are depending here on kload_check_module_loaded()
        * having been called, which is guaranteed by kload_load_dgraph()
        * is used, but not by its subroutines (such as
        * __kload_load_modules()).
        */
        if (current_entry->loaded_address) {
            if (!kld_file_merge_OSObjects(current_entry->name)) {
                result = kload_error_link_load;   // FIXME: need a "patch" error?
                goto finish;
            }
        } else {
            if (!kld_file_patch_OSObjects(current_entry->name)) {
                result = kload_error_link_load;   // FIXME: need a "patch" error?
                goto finish;
            }
        }
#endif /* not KERNEL */

    }

    if (!kld_file_prepare_for_link()) {
        result = kload_error_link_load;   // FIXME: need more specific error?
        goto finish;
    }

finish:
    return result;
}

#ifndef KERNEL
/*******************************************************************************
*
*******************************************************************************/
#define __KLOAD_PATCH_EXTENSION ".patch"

kload_error __kload_output_patches(
    dgraph_t * dgraph,
    const char * patch_file,
    const char * patch_dir,
    int ask_overwrite_symbols,
    int overwrite_symbols)
{
    kload_error result = kload_error_none;
    unsigned int i;
    char * allocated_filename = NULL;
    char * patch_filename = NULL;
    int file_check;
    int output_patch;

    if (patch_dir) {

        for (i = 0; i < dgraph->length; i++) {

            struct dgraph_entry_t * entry = dgraph->load_order[i];
            unsigned long length;

            if (entry->is_kernel_component) {
                continue;
            }

            length = strlen(patch_dir) +
                strlen(entry->expected_kmod_name) +
                strlen(__KLOAD_PATCH_EXTENSION) +
                1 + 1 ;   // 1 for '/' added, 1 for terminating null
            if (length >= MAXPATHLEN) {
                kload_log_error(
                    "output filename \"%s/%s%s\" would be too long" KNL,
                    patch_dir, entry->expected_kmod_name,
                    __KLOAD_PATCH_EXTENSION);
                result = kload_error_invalid_argument;
                goto finish;
            }

            allocated_filename = (char *)malloc(length);
            if (! allocated_filename) {
                kload_log_error("malloc failure" KNL);
                result = kload_error_no_memory;
                goto finish;
            }

            patch_filename = allocated_filename;
            strcpy(patch_filename, patch_dir);
            strcat(patch_filename, "/");
            strcat(patch_filename, entry->expected_kmod_name);
            strcat(patch_filename, __KLOAD_PATCH_EXTENSION);

            output_patch = 1;
            file_check = kload_file_exists(patch_filename);

            if (file_check < 0) {
                kload_log_error("error checking existence of file %s" KNL,
                    patch_filename);
            } else if (file_check > 0 && !overwrite_symbols) {
                if (!ask_overwrite_symbols) {
                    kload_log_error(
                        "patch file %s exists; not overwriting" KNL,
                        patch_filename);
                    output_patch = 0;
                } else {
                    int approve = (*__kload_approve_func)(1,
                        "\nPatch file %s exists; overwrite", patch_filename);

                    if (approve < 0) {
                        result = kload_error_unspecified;
                        goto finish;
                    } else {
                        output_patch = approve;
                    }
                }
            }

            if (output_patch) {
                if (log_level >= kload_log_level_basic) {
                    kload_log_message("writing patch file %s" KNL, patch_filename);
                }
                kld_file_debug_dump(entry->name, patch_filename);
            }

            if (allocated_filename) free(allocated_filename);
            allocated_filename = NULL;
        }

    } else if (patch_file) {
        output_patch = 1;
        file_check = kload_file_exists(patch_file);

        if (file_check < 0) {
            kload_log_error("error checking existence of file %s" KNL,
                patch_file);
        } else if (file_check > 0 && !overwrite_symbols) {
            if (!ask_overwrite_symbols) {
                kload_log_error("patch file %s exists; not overwriting" KNL,
                    patch_filename);
                output_patch = 0;
            } else {
                int approve = (*__kload_approve_func)(1,
                    "\nPatch file %s exists; overwrite", patch_filename);

                if (approve < 0) {
                    result = kload_error_unspecified;
                    goto finish;
                } else {
                    output_patch = approve;
                }
            }
        }

        if (output_patch) {
            if (log_level >= kload_log_level_basic) {
                kload_log_message("writing patch file %s" KNL, patch_filename);
            }
            kld_file_debug_dump(dgraph->root->name, patch_file);
        }
    }

finish:
    if (allocated_filename) free(allocated_filename);

    return result;
}
#endif /* not KERNEL */

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
kload_error __kload_set_module_dependencies(dgraph_entry_t * entry) {
    kload_error result = kload_error_none;
    int mach_result;
#ifndef KERNEL
    void * kmod_control_args = 0;
    int num_args = 0;
#endif /* not KERNEL */
    kmod_t packed_id;
    unsigned int i;
    dgraph_entry_t * current_dep = NULL;

    if (!entry->do_load) {
        result = kload_error_already_loaded;
        goto finish;
    }

    for (i = 0; i < entry->num_dependencies; i++) {
        current_dep = entry->dependencies[i];

        if (log_level >= kload_log_level_load_details) {
            kload_log_message("adding reference from %s (%d) to %s (%d)" KNL,
                entry->expected_kmod_name, entry->kmod_id,
                current_dep->expected_kmod_name, current_dep->kmod_id);
        }

        packed_id = KMOD_PACK_IDS(entry->kmod_id, current_dep->kmod_id);
#ifndef KERNEL
        mach_result = kmod_control(G_kernel_priv_port,
		packed_id, KMOD_CNTL_RETAIN, &kmod_control_args, &num_args);
#else
        mach_result = kmod_retain(packed_id);
#endif /* not KERNEL */
        if (mach_result != KERN_SUCCESS) {
            kload_log_error(
                "kmod retain failed for %s; destroying kmod" KNL,
                entry->expected_kmod_name);
#ifndef KERNEL
            mach_result = kmod_destroy(G_kernel_priv_port, entry->kmod_id);
#else
            mach_result = kmod_destroy_internal(entry->kmod_id);
#endif /* not KERNEL */
            if (mach_result != KERN_SUCCESS) {
                kload_log_error("kmod destroy failed" KNL);
            }
            result = kload_error_link_load;
            goto finish;
        }
    }

    if (log_level >= kload_log_level_load_basic) {
        kload_log_message("module # %d reference counts incremented" KNL,
            entry->kmod_id);
    }

finish:
    return result;
}

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
kload_error __kload_start_module(dgraph_entry_t * entry) {
    kload_error result = kload_error_none;
    int mach_result;
#ifndef KERNEL
    void * kmod_control_args = 0;
    int num_args = 0;
#endif /* not KERNEL */

    if (!entry->do_load) {
        result = kload_error_already_loaded;
        goto finish;
    }

#ifndef KERNEL
    mach_result = kmod_control(G_kernel_priv_port,
	    entry->kmod_id, KMOD_CNTL_START, &kmod_control_args, &num_args);
#else
    mach_result = kmod_start_or_stop(entry->kmod_id, 1, 0, 0);
#endif /* not KERNEL */

    if (mach_result != KERN_SUCCESS) {
        kload_log_error(
            "kmod_control/start failed for %s; destroying kmod" KNL,
            entry->expected_kmod_name);
#ifndef KERNEL
        mach_result = kmod_destroy(G_kernel_priv_port, entry->kmod_id);
#else
        mach_result = kmod_destroy_internal(entry->kmod_id);
#endif /* not KERNEL */
        if (mach_result != KERN_SUCCESS) {
            kload_log_error("kmod destroy failed" KNL);
        }
        result = kload_error_link_load;
        goto finish;
    }

    if (log_level >= kload_log_level_load_basic) {
        kload_log_message("module # %d started" KNL,
           entry->kmod_id);
    }

finish:
    return result;
}

/*******************************************************************************
*******************************************************************************/

/*******************************************************************************
* This function can only operate on 32 bit mach object file symbol table
* graphs represented by G_current_load_entry.
*******************************************************************************/
static
unsigned long __kload_linkedit_address(
    unsigned long size,
    unsigned long headers_size)
{
    unsigned long round_segments_size;
    unsigned long round_headers_size;
    unsigned long round_size;
    int mach_result;
    const struct machOMapping {
	struct mach_header h;
	struct segment_command seg[1];
    } *machO;

    if (!G_current_load_entry) {
        return 0;
    }

    // the actual size allocated by kld_load_from_memory()
    G_current_load_entry->kernel_load_size = size;

    round_headers_size = round_page(headers_size);
    round_segments_size = round_page(size - headers_size);
    round_size = round_headers_size + round_segments_size;

    G_current_load_entry->kernel_alloc_size = round_size;

    // will need to be rounded *after* load/link
    G_current_load_entry->kernel_hdr_size = headers_size;
    G_current_load_entry->kernel_hdr_pad = round_headers_size - headers_size;
    
    if (G_current_load_entry->loaded_address) {
        G_current_load_entry->kernel_load_address =
            G_current_load_entry->loaded_address +
            G_current_load_entry->kernel_hdr_pad;
        if (log_level >= kload_log_level_load_basic) {
            kload_log_message(
                "using %s load address 0x%x (0x%x with header pad)" KNL,
                G_current_load_entry->kmod_id ? "existing" : "provided",
                G_current_load_entry->loaded_address,
                G_current_load_entry->kernel_load_address);
        }
        return G_current_load_entry->kernel_load_address;
    }

    machO = (const struct machOMapping *) G_current_load_entry->object;
    if (machO->seg[0].vmaddr)
    {
	G_current_load_entry->loaded_address = trunc_page(machO->seg[0].vmaddr - machO->seg[0].fileoff);

	G_current_load_entry->kernel_load_address = G_current_load_entry->loaded_address 
		+ G_current_load_entry->kernel_hdr_pad;

	return G_current_load_entry->kernel_load_address;
    }

#ifndef KERNEL
    if (G_prelink) {
	G_current_load_entry->kernel_alloc_address = G_prelink->modules[0].address;
	G_prelink->modules[0].address += round_page(G_current_load_entry->kernel_alloc_size);
	mach_result = KERN_SUCCESS;
	
    } else if (G_syms_only) {
        kload_log_error(
            "internal error; asked to allocate kernel memory" KNL);
        // FIXME: no provision for cleanup here
        return kload_error_unspecified;

    } else
#endif /* not KERNEL */

    {
#ifndef KERNEL
	mach_result = vm_allocate(G_kernel_port,
		&G_current_load_entry->kernel_alloc_address,
		G_current_load_entry->kernel_alloc_size, VM_FLAGS_ANYWHERE);
#else
	mach_result = vm_allocate(kernel_map,
	    &G_current_load_entry->kernel_alloc_address,
	    G_current_load_entry->kernel_alloc_size, VM_FLAGS_ANYWHERE);
#endif /* not KERNEL */
    }

    if (mach_result != KERN_SUCCESS) {
        kload_log_error("can't allocate kernel memory" KNL);
        // FIXME: no provision for cleanup here
        return kload_error_kernel_error;
    }

    if (log_level >= kload_log_level_load_basic) {
        kload_log_message("allocated %ld bytes in kernel space at 0x%x" KNL,
            G_current_load_entry->kernel_alloc_size,
            G_current_load_entry->kernel_alloc_address);
    }

    G_current_load_entry->kernel_load_address =
        G_current_load_entry->kernel_alloc_address +
        G_current_load_entry->kernel_hdr_pad;

    G_current_load_entry->loaded_address = G_current_load_entry->kernel_alloc_address;

    if (log_level >= kload_log_level_load_basic) {
        kload_log_message(
            "using load address of 0x%x" KNL,
            G_current_load_entry->kernel_alloc_address);
    }

    return G_current_load_entry->kernel_load_address;
}

/*******************************************************************************
*
*******************************************************************************/
static
void __kload_clear_kld_globals(void) {
    G_current_load_entry = NULL;
    return;
}

/*******************************************************************************
*
*******************************************************************************/
static
void __kload_clean_up_entry(dgraph_entry_t * entry) {
    int mach_result;

    if (entry->need_cleanup && entry->kernel_alloc_address) {
#ifndef KERNEL
	if (G_prelink) {

	    if ((entry->kernel_alloc_address + entry->kernel_alloc_size) == G_prelink->modules[0].address) {
		G_prelink->modules[0].address = entry->kernel_alloc_address;
	    } else {
		kload_log_error(
		    "bad free load address of 0x%x (last 0x%x)" KNL,
		    entry->kernel_alloc_address, G_prelink->modules[0].address);
	    }
	} else {
	    mach_result = vm_deallocate(G_kernel_port, entry->kernel_alloc_address,
		entry->kernel_alloc_size);
	}
#else
        mach_result = vm_deallocate(kernel_map, entry->kernel_alloc_address,
            entry->kernel_alloc_size);
#endif /* not KERNEL */
        entry->kernel_alloc_address = 0;
    }
    return;
}

#ifndef KERNEL
/*******************************************************************************
*
*******************************************************************************/
int kload_file_exists(const char * path)
{
    int result = 0;  // assume it doesn't exist
    struct stat stat_buf;

    if (stat(path, &stat_buf) == 0) {
        result = 1;  // the file does exist; we don't care beyond that
        goto finish;
    }

    switch (errno) {
      case ENOENT:
        result = 0;  // the file doesn't exist
        goto finish;
        break;
      default:
        result = -1;  // unknown error
        goto finish;
        break;
    }

finish:
    return result;
}
#endif /* not KERNEL */

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
void kload_set_log_level(kload_log_level level)
{
    log_level = level;
    return;
}

#ifndef KERNEL
/*******************************************************************************
*
*******************************************************************************/
void kload_set_log_function(
    void (*func)(const char * format, ...))
{
    if (!func) {
        __kload_log_func = &__kload_null_log;
    } else {
        __kload_log_func = func;
    }
    return;
}

/*******************************************************************************
*
*******************************************************************************/
void kload_set_error_log_function(
    void (*func)(const char * format, ...))
{
    if (!func) {
        __kload_err_log_func = &__kload_null_err_log;
    } else {
        __kload_err_log_func = func;
    }
    return;
}

/*******************************************************************************
*
*******************************************************************************/
void kload_set_user_approve_function(
    int (*func)(int default_answer, const char * format, ...))
{
    if (!func) {
        __kload_approve_func = &__kload_null_approve;
    } else {
        __kload_approve_func = func;
    }
    return;
}

/*******************************************************************************
*
*******************************************************************************/
void kload_set_user_veto_function(
    int (*func)(int default_answer, const char * format, ...))
{
    if (!func) {
        __kload_veto_func = &__kload_null_veto;
    } else {
        __kload_veto_func = func;
    }
    return;
}

/*******************************************************************************
*
*******************************************************************************/
void kload_set_user_input_function(
    const char * (*func)(const char * format, ...))
{
    if (!func) {
        __kload_input_func = &__kload_null_input;
    } else {
        __kload_input_func = func;
    }
    return;
}

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
void kload_log_message(const char * format, ...)
{
    va_list ap;
    char fake_buffer[2];
    int output_length;
    char * output_string;

    if (log_level <= kload_log_level_silent) {
        return;
    }

    va_start(ap, format);
    output_length = vsnprintf(fake_buffer, 1, format, ap);
    va_end(ap);

    output_string = (char *)malloc(output_length + 1);
    if (!output_string) {
        return;
    }

    va_start(ap, format);
    vsprintf(output_string, format, ap);
    va_end(ap);

    __kload_log_func(output_string);
    free(output_string);

    return;
}

/*******************************************************************************
*
*******************************************************************************/
PRIV_EXT
void kload_log_error(const char * format, ...)
{
    va_list ap;
    char fake_buffer[2];
    int output_length;
    char * output_string;

    if (log_level <= kload_log_level_silent) {
        return;
    }

    va_start(ap, format);
    output_length = vsnprintf(fake_buffer, 1, format, ap);
    va_end(ap);

    output_string = (char *)malloc(output_length + 1);
    if (!output_string) {
        return;
    }

    va_start(ap, format);
    vsprintf(output_string, format, ap);
    va_end(ap);

    __kload_err_log_func(output_string);
    free(output_string);

    return;
}
/*******************************************************************************
*
*******************************************************************************/
void __kload_null_log(const char * format, ...)
{
    return;
}

/*******************************************************************************
*
*******************************************************************************/
void __kload_null_err_log(const char * format, ...)
{
    return;
}

/*******************************************************************************
*
*******************************************************************************/
int __kload_null_approve(int default_answer, const char * format, ...)
{
    return 0;
}

/*******************************************************************************
*
*******************************************************************************/
int __kload_null_veto(int default_answer, const char * format, ...)
{
    return 1;
}

/*******************************************************************************
*
*******************************************************************************/
const char * __kload_null_input(const char * format, ...)
{
    return NULL;
}

/*******************************************************************************
* The kld_patch.c module uses this function, if defined, to print errors. In
* the kernel this function is defined in libsa/misc.c.
*******************************************************************************/
void kld_error_vprintf(const char * format, va_list ap) {
    if (log_level <= kload_log_level_silent) return;
    vfprintf(stderr, format, ap);
    return;
}

#endif /* not KERNEL */
