/*
 * Copyright (c) 2000-2007 Apple Computer, Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 * 1999 Mar 29 rsulack created.
 */

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/kern_return.h>
#include <mach/host_priv_server.h>
#include <mach/vm_map.h>

#include <kern/clock.h>
#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/thread.h>

#include <vm/vm_kern.h>

#include <mach-o/mach_header.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <mach/kext_panic_report.h>

/*
 * XXX headers for which prototypes should be in a common include file;
 * XXX see libsa/kext.cpp for why.
 */
kern_return_t kmod_create_internal(kmod_info_t *info, kmod_t *id);
kern_return_t kmod_destroy_internal(kmod_t id);
kern_return_t kmod_start_or_stop(kmod_t id, int start, kmod_args_t *data,
    mach_msg_type_number_t *dataCount);
kern_return_t kmod_retain(kmod_t id);
kern_return_t kmod_release(kmod_t id);
kern_return_t kmod_queue_cmd(vm_address_t data, vm_size_t size);
kern_return_t kmod_get_info(host_t host, kmod_info_array_t *kmods,
    mach_msg_type_number_t *kmodCount);

static kern_return_t kmod_get_symbol_data(kmod_args_t * data,
    mach_msg_type_number_t * dataCount);
static kern_return_t kmod_free_linkedit_data(void);
static kern_return_t kmod_get_kext_uuid(
    const char * kext_id,
    kmod_args_t * data,
    mach_msg_type_number_t * dataCount);

extern int IODTGetLoaderInfo(const char * key, void ** infoAddr, vm_size_t * infoSize);
extern void IODTFreeLoaderInfo(const char * key, void * infoAddr, vm_size_t infoSize);
/* operates on 32 bit segments */
extern void OSRuntimeUnloadCPPForSegment(struct segment_command * segment);

#define WRITE_PROTECT_MODULE_TEXT   (0)

kmod_info_t *kmod;
static int kmod_index = 1;
static int kmod_load_disabled = 0;

mutex_t * kmod_lock = 0;
static mutex_t * kmod_queue_lock = 0;

typedef struct cmd_queue_entry {
    queue_chain_t    links;
    vm_address_t     data;
    vm_size_t        size;
} cmd_queue_entry_t;

queue_head_t kmod_cmd_queue;

/*******************************************************************************
*******************************************************************************/
#define KMOD_PANICLIST_SIZE  (2 * PAGE_SIZE)

char     * unloaded_kext_paniclist        = NULL;
uint32_t   unloaded_kext_paniclist_size   = 0;
uint32_t   unloaded_kext_paniclist_length = 0;
uint64_t   last_loaded_timestamp          = 0;

char     * loaded_kext_paniclist          = NULL;
uint32_t   loaded_kext_paniclist_size     = 0;
uint32_t   loaded_kext_paniclist_length   = 0;
uint64_t   last_unloaded_timestamp        = 0;

int substitute(
    const char * scan_string,
    char       * string_out,
    uint32_t   * to_index,
    uint32_t   * from_index,
    const char * substring,
    char         marker,
    char         substitution);

/* identifier_out must be at least KMOD_MAX_NAME bytes.
 */
int substitute(
    const char * scan_string,
    char       * string_out,
    uint32_t   * to_index,
    uint32_t   * from_index,
    const char * substring,
    char         marker,
    char         substitution)
{
    uint32_t substring_length = strnlen(substring, KMOD_MAX_NAME - 1);

    if (!strncmp(scan_string, substring, substring_length)) {
        if (marker) {
            string_out[(*to_index)++] = marker;
        }
        string_out[(*to_index)++] = substitution;
        (*from_index) += substring_length;
        return 1;
    }
    return 0;
}

void compactIdentifier(
    const char * identifier,
    char       * identifier_out,
    char      ** identifier_out_end);

void compactIdentifier(
    const char * identifier,
    char       * identifier_out,
    char      ** identifier_out_end)
{
    uint32_t       from_index, to_index;
    uint32_t       scan_from_index = 0;
    uint32_t       scan_to_index   = 0;
    subs_entry_t * subs_entry    = NULL;
    int            did_sub       = 0;

    from_index = to_index = 0;
    identifier_out[0] = '\0';

   /* Replace certain identifier prefixes with shorter @+character sequences.
    */
    for (subs_entry = &kext_identifier_prefix_subs[0];
         subs_entry->substring && !did_sub;
         subs_entry++) {

        did_sub = substitute(identifier, identifier_out,
            &scan_to_index, &scan_from_index,
            subs_entry->substring, /* marker */ '\0', subs_entry->substitute);
    }
    did_sub = 0;

   /* Now scan through the identifier looking for the common substrings
    * and replacing them with shorter !+character sequences.
    */
    for (/* see above */;
         scan_from_index < KMOD_MAX_NAME - 1 && identifier[scan_from_index];
         /* see loop */) {
         
        const char   * scan_string = &identifier[scan_from_index];

        did_sub = 0;

        if (scan_from_index) {
            for (subs_entry = &kext_identifier_substring_subs[0];
                 subs_entry->substring && !did_sub;
                 subs_entry++) {

                did_sub = substitute(scan_string, identifier_out,
                    &scan_to_index, &scan_from_index,
                    subs_entry->substring, '!', subs_entry->substitute);
            }
        }

        if (!did_sub) {
            identifier_out[scan_to_index++] = identifier[scan_from_index++];
        }
    }
    
    identifier_out[scan_to_index] = '\0';
    if (identifier_out_end) {
        *identifier_out_end = &identifier_out[scan_to_index];
    }
    
    return;
}

/* identPlusVers must be at least 2*KMOD_MAX_NAME in length.
 */
int assemble_identifier_and_version(
    kmod_info_t * kmod_info, 
    char        * identPlusVers);
int assemble_identifier_and_version(
    kmod_info_t * kmod_info, 
    char        * identPlusVers)
{
    int result = 0;

    compactIdentifier(kmod_info->name, identPlusVers, NULL);
    result = strnlen(identPlusVers, KMOD_MAX_NAME - 1);
    identPlusVers[result++] = '\t';  // increment for real char
    identPlusVers[result] = '\0';    // don't increment for nul char
    result = strlcat(identPlusVers, kmod_info->version, KMOD_MAX_NAME);

    return result;
}

#define LAST_LOADED " - last loaded "
#define LAST_LOADED_TS_WIDTH  (16)

uint32_t save_loaded_kext_paniclist_typed(
    const char * prefix,
    int          invertFlag,
    int          libsFlag,
    char       * paniclist,
    uint32_t     list_size,
    uint32_t   * list_length_ptr,
    int         (*printf_func)(const char *fmt, ...));
uint32_t save_loaded_kext_paniclist_typed(
    const char * prefix,
    int          invertFlag,
    int          libsFlag,
    char       * paniclist,
    uint32_t     list_size,
    uint32_t   * list_length_ptr,
    int         (*printf_func)(const char *fmt, ...))
{
    uint32_t      result = 0;
    int           error  = 0;
    kmod_info_t * kmod_info;

    for (kmod_info = kmod;
         kmod_info && (*list_length_ptr + 1 < list_size);
         kmod_info = kmod_info->next) {

        int      match;
        char     identPlusVers[2*KMOD_MAX_NAME];
        uint32_t identPlusVersLength;
        char     timestampBuffer[17]; // enough for a uint64_t

        if (!pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)kmod_info))) {
            (*printf_func)("kmod scan stopped due to missing kmod page: %p\n",
                kmod_info);
            error = 1;
            goto finish;
        }

       /* Skip all built-in/fake entries.
        */
        if (!kmod_info->address) {
            continue;
        }

       /* Filter for kmod name (bundle identifier).
        */
        match = !strncmp(kmod_info->name, prefix, strnlen(prefix, KMOD_MAX_NAME));
        if ((match && invertFlag) || (!match && !invertFlag)) {
            continue;
        }

       /* Filter for libraries. This isn't a strictly correct check,
        * but any kext that does have references to it has to be a library.
        * A kext w/o references may or may not be a library.
        */
        if ((libsFlag == 0 && kmod_info->reference_count) ||
            (libsFlag == 1 && !kmod_info->reference_count)) {

            continue;
        }

        identPlusVersLength = assemble_identifier_and_version(kmod_info,
            identPlusVers);
        if (!identPlusVersLength) {
            printf_func("error saving loaded kext info\n");
            goto finish;
        }

       /* We're going to note the last-loaded kext in the list.
        */
        if (kmod_info == kmod) {
            snprintf(timestampBuffer, sizeof(timestampBuffer), "%llu",
                last_loaded_timestamp);
            identPlusVersLength += sizeof(LAST_LOADED) - 1 +
                strnlen(timestampBuffer, sizeof(timestampBuffer));
        }

       /* Adding 1 for the newline.
        */
        if (*list_length_ptr + identPlusVersLength + 1 >= list_size) {
            goto finish;
        }
        
        *list_length_ptr = strlcat(paniclist, identPlusVers, list_size);
        if (kmod_info == kmod) {
            *list_length_ptr = strlcat(paniclist, LAST_LOADED, list_size);
            *list_length_ptr = strlcat(paniclist, timestampBuffer, list_size);
        }
        *list_length_ptr = strlcat(paniclist, "\n", list_size);
    }
    
finish:
    if (!error) {
        if (*list_length_ptr + 1 <= list_size) {
            result = list_size - (*list_length_ptr + 1);
        }
    }

    return result;
}

void save_loaded_kext_paniclist(
    int         (*printf_func)(const char *fmt, ...));

void save_loaded_kext_paniclist(
    int         (*printf_func)(const char *fmt, ...))
{
    char     * newlist        = NULL;
    uint32_t   newlist_size   = 0;
    uint32_t   newlist_length = 0;

    newlist_length = 0;
    newlist_size = KMOD_PANICLIST_SIZE;
    newlist = (char *)kalloc(newlist_size);
    
    if (!newlist) {
        printf_func("couldn't allocate kext panic log buffer\n");
        goto finish;
    }
    
    newlist[0] = '\0';

    // non-"com.apple." kexts
    if (!save_loaded_kext_paniclist_typed("com.apple.", /* invert? */ 1,
        /* libs? */ -1, newlist, newlist_size, &newlist_length,
        printf_func)) {
        
        goto finish;
    }
    // "com.apple." nonlibrary kexts
    if (!save_loaded_kext_paniclist_typed("com.apple.", /* invert? */ 0,
        /* libs? */ 0, newlist, newlist_size, &newlist_length,
        printf_func)) {
        
        goto finish;
    }
    // "com.apple." library kexts
    if (!save_loaded_kext_paniclist_typed("com.apple.", /* invert? */ 0,
        /* libs? */ 1, newlist, newlist_size, &newlist_length,
        printf_func)) {
        
        goto finish;
    }

    if (loaded_kext_paniclist) {
        kfree(loaded_kext_paniclist, loaded_kext_paniclist_size);
    }
    loaded_kext_paniclist = newlist;
    loaded_kext_paniclist_size = newlist_size;
    loaded_kext_paniclist_length = newlist_length;

finish:
    return;
}

void save_unloaded_kext_paniclist(
    kmod_info_t * kmod_info,
    int         (*printf_func)(const char *fmt, ...));
void save_unloaded_kext_paniclist(
    kmod_info_t * kmod_info,
    int         (*printf_func)(const char *fmt, ...))
{
    char     * newlist        = NULL;
    uint32_t   newlist_size   = 0;
    uint32_t   newlist_length = 0;
    char       identPlusVers[2*KMOD_MAX_NAME];
    uint32_t   identPlusVersLength;

    identPlusVersLength = assemble_identifier_and_version(kmod_info,
        identPlusVers);
    if (!identPlusVersLength) {
        printf_func("error saving unloaded kext info\n");
        goto finish;
    }

    newlist_length = identPlusVersLength;
    newlist_size = newlist_length + 1;
    newlist = (char *)kalloc(newlist_size);
    
    if (!newlist) {
        printf_func("couldn't allocate kext panic log buffer\n");
        goto finish;
    }
    
    newlist[0] = '\0';

    strlcpy(newlist, identPlusVers, newlist_size);

    if (unloaded_kext_paniclist) {
        kfree(unloaded_kext_paniclist, unloaded_kext_paniclist_size);
    }
    unloaded_kext_paniclist = newlist;
    unloaded_kext_paniclist_size = newlist_size;
    unloaded_kext_paniclist_length = newlist_length;

finish:
    return;
}

// proto is in header
void record_kext_unload(kmod_t kmod_id)
{
    kmod_info_t * kmod_info = NULL;

    mutex_lock(kmod_lock);
    
    kmod_info = kmod_lookupbyid(kmod_id);
    if (kmod_info) {
        clock_get_uptime(&last_unloaded_timestamp);
        save_unloaded_kext_paniclist(kmod_info, &printf);
    }
    mutex_unlock(kmod_lock);
    return;
}

void dump_kext_info(int (*printf_func)(const char *fmt, ...))
{
    printf_func("unloaded kexts:\n");
    if (unloaded_kext_paniclist && (pmap_find_phys(kernel_pmap, (addr64_t) (uintptr_t) unloaded_kext_paniclist))) {
        printf_func("%.*s - last unloaded %llu\n",
            unloaded_kext_paniclist_length, unloaded_kext_paniclist,
            last_unloaded_timestamp);
    } else {
        printf_func("(none)\n");
    }
    printf_func("loaded kexts:\n");
    if (loaded_kext_paniclist && (pmap_find_phys(kernel_pmap, (addr64_t) (uintptr_t) loaded_kext_paniclist)) && loaded_kext_paniclist[0]) {
        printf_func("%.*s", loaded_kext_paniclist_length, loaded_kext_paniclist);
    } else {
        printf_func("(none)\n");
    }
    return;
}

/*******************************************************************************
*******************************************************************************/
void
kmod_init(void)
{
    kmod_lock = mutex_alloc(0);
    kmod_queue_lock = mutex_alloc(0);
    queue_init(&kmod_cmd_queue);
}

kmod_info_t *
kmod_lookupbyid(kmod_t id)
{
    kmod_info_t *k = NULL;

    k = kmod;
    while (k) {
        if (k->id == id) break;
        k = k->next;
    }

    return k;
}

kmod_info_t *
kmod_lookupbyname(const char * name)
{
    kmod_info_t *k = NULL;

    k = kmod;
    while (k) {
        if (!strncmp(k->name, name, sizeof(k->name)))
        break;
        k = k->next;
    }

    return k;
}

// get the id of a kext in a given range, if the address is not in a kext
// -1 is returned
int kmod_lookupidbyaddress_locked(vm_address_t addr)
{
    kmod_info_t *k = 0;
    
    mutex_lock(kmod_queue_lock);
    k = kmod;
    if(NULL != k) {
        while (k) {
            if ((k->address <= addr) && ((k->address + k->size) > addr)) {
                break;
            }
            k = k->next;
        }
        mutex_unlock(kmod_queue_lock);
    } else {
        mutex_unlock(kmod_queue_lock);
        return -1;
    }
    
    if(NULL == k) {
        return -1;
    } else {
        return k->id;
    }
}

kmod_info_t *
kmod_lookupbyaddress(vm_address_t addr)
{
    kmod_info_t *k = 0;

    k = kmod;
    while (k) {
        if ((k->address <= addr) && ((k->address + k->size) > addr)) break;
        k = k->next;
    }

    return k;
}

kmod_info_t *
kmod_lookupbyid_locked(kmod_t id)
{
    kmod_info_t *k = NULL;
    kmod_info_t *kc = NULL;

    kc = (kmod_info_t *)kalloc(sizeof(kmod_info_t));
    if (!kc) return kc;

    mutex_lock(kmod_lock);
    k = kmod_lookupbyid(id);
    if (k) {
        bcopy((char*)k, (char *)kc, sizeof(kmod_info_t));
    }

    mutex_unlock(kmod_lock);

    if (k == 0) {
        kfree(kc, sizeof(kmod_info_t));
    kc = NULL;
    }
    return kc;
}

kmod_info_t *
kmod_lookupbyname_locked(const char * name)
{
    kmod_info_t *k = NULL;
    kmod_info_t *kc = NULL;

    kc = (kmod_info_t *)kalloc(sizeof(kmod_info_t));
    if (!kc) return kc;

    mutex_lock(kmod_lock);
    k = kmod_lookupbyname(name);
    if (k) {
        bcopy((char *)k, (char *)kc, sizeof(kmod_info_t));
    }

    mutex_unlock(kmod_lock);

    if (k == 0) {
        kfree(kc, sizeof(kmod_info_t));
    kc = NULL;
    }
    return kc;
}

// XXX add a nocopy flag??

kern_return_t
kmod_queue_cmd(vm_address_t data, vm_size_t size)
{
    kern_return_t rc;
    cmd_queue_entry_t *e = (cmd_queue_entry_t *)kalloc(sizeof(struct cmd_queue_entry));
    if (!e) return KERN_RESOURCE_SHORTAGE;

    rc = kmem_alloc(kernel_map, &e->data, size);
    if (rc != KERN_SUCCESS) {
        kfree(e, sizeof(struct cmd_queue_entry));
        return rc;
    }
    e->size = size;
    bcopy((void *)data, (void *)e->data, size);

    mutex_lock(kmod_queue_lock);
    enqueue_tail(&kmod_cmd_queue, (queue_entry_t)e);
    mutex_unlock(kmod_queue_lock);

    thread_wakeup_one((event_t)&kmod_cmd_queue);
    
    return KERN_SUCCESS;
}

kern_return_t
kmod_load_extension(char *name)
{
    kmod_load_extension_cmd_t data;

    if (kmod_load_disabled) {
        return KERN_NO_ACCESS;
    }

    data.type = KMOD_LOAD_EXTENSION_PACKET;
    strncpy(data.name, name, sizeof(data.name));

    return kmod_queue_cmd((vm_address_t)&data, sizeof(data));
}

kern_return_t
kmod_load_extension_with_dependencies(char *name, char **dependencies)
{
    kern_return_t result;
    kmod_load_with_dependencies_cmd_t * data;
    vm_size_t    size;
    char        **c;
    int         i, count = 0;

    if (kmod_load_disabled) {
        return KERN_NO_ACCESS;
    }

    c = dependencies;
    if (c) {
        while (*c) {
            count++; c++;
        }
    }
    size = sizeof(int) + KMOD_MAX_NAME * (count + 1) + 1; 
    data = (kmod_load_with_dependencies_cmd_t *)kalloc(size);
    if (!data) return KERN_RESOURCE_SHORTAGE;

    data->type = KMOD_LOAD_WITH_DEPENDENCIES_PACKET;
    strncpy(data->name, name, KMOD_MAX_NAME);

    c = dependencies;
    for (i=0; i < count; i++) {
        strncpy(data->dependencies[i], *c, KMOD_MAX_NAME);
        c++;
    }
    data->dependencies[count][0] = 0;

    result = kmod_queue_cmd((vm_address_t)data, size);
    kfree(data, size);
    return result;
}
kern_return_t
kmod_send_generic(int type, void *generic_data, int size)
{
    kern_return_t result;
    kmod_generic_cmd_t * data;
    vm_size_t cmd_size;

    // add sizeof(int) for the type field
    cmd_size = size + sizeof(int);
    data = (kmod_generic_cmd_t *)kalloc(cmd_size);
    if (!data) return KERN_RESOURCE_SHORTAGE;

    data->type = type;
    bcopy(data->data, generic_data, size);

    result = kmod_queue_cmd((vm_address_t)data, cmd_size);
    kfree(data, cmd_size);
    return result;
}

extern vm_offset_t sectPRELINKB;
extern int sectSizePRELINK;
extern int kth_started;

/*
 * Operates only on 32 bit mach keaders on behalf of kernel module loader
 * if WRITE_PROTECT_MODULE_TEXT is defined.
 */
kern_return_t
kmod_create_internal(kmod_info_t *info, kmod_t *id)
{
    kern_return_t rc;
    boolean_t     isPrelink;

    if (!info) return KERN_INVALID_ADDRESS;

    // double check for page alignment
    if ((info->address | info->hdr_size) & (PAGE_SIZE - 1)) {
        return KERN_INVALID_ADDRESS;
    }

    isPrelink = ((info->address >= sectPRELINKB) && (info->address < (sectPRELINKB + sectSizePRELINK)));
    if (!isPrelink && kth_started) {
        rc = vm_map_wire(kernel_map, info->address + info->hdr_size, 
            info->address + info->size, VM_PROT_DEFAULT, FALSE);
        if (rc != KERN_SUCCESS) {
            return rc;
        }
    }
#if WRITE_PROTECT_MODULE_TEXT
    {
        struct section * sect = getsectbynamefromheader(
            (struct mach_header*) info->address, "__TEXT", "__text");
        
        if(sect) {
            (void) vm_map_protect(kernel_map, round_page(sect->addr),
                trunc_page(sect->addr + sect->size),
                VM_PROT_READ|VM_PROT_EXECUTE, TRUE);
        }
    }
#endif /* WRITE_PROTECT_MODULE_TEXT */

    mutex_lock(kmod_lock);

    // check to see if already loaded
    if (kmod_lookupbyname(info->name)) {
        mutex_unlock(kmod_lock);
        if (!isPrelink) {
            rc = vm_map_unwire(kernel_map, info->address + info->hdr_size, 
            info->address + info->size, FALSE);
            assert(rc == KERN_SUCCESS);
        }
        return KERN_INVALID_ARGUMENT;
    }

    info->id = kmod_index++;
    info->reference_count = 0;

    info->next = kmod;
    kmod = info;

    *id = info->id;

    clock_get_uptime(&last_loaded_timestamp);
    save_loaded_kext_paniclist(&printf);

    mutex_unlock(kmod_lock);

#if DEBUG
    printf("kmod_create: %s (id %d), %d pages loaded at 0x%x, header size 0x%x\n", 
        info->name, info->id, info->size / PAGE_SIZE, info->address, info->hdr_size);
#endif /* DEBUG */

    return KERN_SUCCESS;
}


kern_return_t
kmod_create(host_priv_t host_priv,
        vm_address_t addr,
        kmod_t *id)
{
#ifdef SECURE_KERNEL
    return KERN_NOT_SUPPORTED;
#else
    kmod_info_t *info;
 
    if (kmod_load_disabled) {
        return KERN_NO_ACCESS;
    }

    info = (kmod_info_t *)addr;

    if (host_priv == HOST_PRIV_NULL) return KERN_INVALID_HOST;
    return kmod_create_internal(info, id);
#endif
}

kern_return_t
kmod_create_fake_with_address(const char *name, const char *version, 
                                vm_address_t address, vm_size_t size,
                                int * return_id)
{
    kmod_info_t *info;

    if (!name || ! version || 
        (1 + strlen(name) > KMOD_MAX_NAME) ||
        (1 + strlen(version) > KMOD_MAX_NAME)) {

        return KERN_INVALID_ARGUMENT;
    }
 
    info = (kmod_info_t *)kalloc(sizeof(kmod_info_t));
    if (!info) {
        return KERN_RESOURCE_SHORTAGE;
    }

    // make de fake
    info->info_version = KMOD_INFO_VERSION;
    bcopy(name, info->name, 1 + strlen(name));
    bcopy(version, info->version, 1 + strlen(version));  //NIK fixed this part
    info->reference_count = 1;    // keep it from unloading, starting, stopping
    info->reference_list = NULL;
    info->address = address;
    info->size = size;
    info->hdr_size = 0;
    info->start = info->stop = NULL;

    mutex_lock(kmod_lock);

    // check to see if already "loaded"
    if (kmod_lookupbyname(info->name)) {
        mutex_unlock(kmod_lock);
        kfree(info, sizeof(kmod_info_t));
        return KERN_INVALID_ARGUMENT;
    }

    info->id = kmod_index++;
    if (return_id)
        *return_id = info->id;

    info->next = kmod;
    kmod = info;

    mutex_unlock(kmod_lock);

    return KERN_SUCCESS;
}

kern_return_t
kmod_create_fake(const char *name, const char *version)
{
    return kmod_create_fake_with_address(name, version, 0, 0, NULL);
}


static kern_return_t
_kmod_destroy_internal(kmod_t id, boolean_t fake)
{
    kern_return_t rc;
    kmod_info_t *k;
    kmod_info_t *p;

    mutex_lock(kmod_lock);

    k = p = kmod;
    while (k) {
        if (k->id == id) {
            kmod_reference_t *r, *t;

            if (!fake && (k->reference_count != 0)) {
                mutex_unlock(kmod_lock);
                return KERN_INVALID_ARGUMENT;
            }
                
            if (k == p) {    // first element
                kmod = k->next;
            } else {
                p->next = k->next;
            }
            mutex_unlock(kmod_lock);

            r = k->reference_list;
            while (r) {
                r->info->reference_count--;
                t = r;
                r = r->next;
                kfree(t, sizeof(struct kmod_reference));
            }

            if (!fake)
            {
#if DEBUG
                printf("kmod_destroy: %s (id %d), deallocating %d pages starting at 0x%x\n", 
                    k->name, k->id, k->size / PAGE_SIZE, k->address);
#endif /* DEBUG */

                if( (k->address >= sectPRELINKB) && (k->address < (sectPRELINKB + sectSizePRELINK)))
                {
                    vm_offset_t
                    virt = ml_static_ptovirt(k->address);
                    if( virt) {
                        ml_static_mfree( virt, k->size);
                    }
                }
                else
                {
                    rc = vm_map_unwire(kernel_map, k->address + k->hdr_size, 
                            k->address + k->size, FALSE);
                    assert(rc == KERN_SUCCESS);
        
                    rc = vm_deallocate(kernel_map, k->address, k->size);
                    assert(rc == KERN_SUCCESS);
                }
            }
            return KERN_SUCCESS;
        }
        p = k;
        k = k->next;
    }

    if (!fake) {
        save_loaded_kext_paniclist(&printf);
    }

    mutex_unlock(kmod_lock);

    return KERN_INVALID_ARGUMENT;
}

kern_return_t
kmod_destroy_internal(kmod_t id)
{
    return _kmod_destroy_internal(id, FALSE);
}

kern_return_t
kmod_destroy(host_priv_t host_priv,
         kmod_t id)
{
    if (host_priv == HOST_PRIV_NULL) return KERN_INVALID_HOST;
    return _kmod_destroy_internal(id, FALSE);
}

kern_return_t
kmod_destroy_fake(kmod_t id)
{
    return _kmod_destroy_internal(id, TRUE);
}

kern_return_t
kmod_start_or_stop(
    kmod_t id,
    int start,
    kmod_args_t *data,
    mach_msg_type_number_t *dataCount)
{
    kern_return_t rc = KERN_SUCCESS;
    void * user_data = NULL;
    kern_return_t (*func)(kmod_info_t *, void *);
    kmod_info_t *k;

    if (start && kmod_load_disabled) {
        return KERN_NO_ACCESS;
    }

    mutex_lock(kmod_lock);

    k = kmod_lookupbyid(id);
    if (!k || k->reference_count) {
        mutex_unlock(kmod_lock);
        rc = KERN_INVALID_ARGUMENT;
        goto finish;
    }

    if (start) {
        func = (void *)k->start;
    } else {
        func = (void *)k->stop;
    }

    mutex_unlock(kmod_lock);

    //
    // call kmod entry point
    //
    if (data && dataCount && *data && *dataCount) {
        vm_map_offset_t map_addr;
        vm_map_copyout(kernel_map, &map_addr, (vm_map_copy_t)*data);
    user_data = CAST_DOWN(void *, map_addr);
    }

    rc = (*func)(k, user_data);

finish:

    if (user_data) {
        (void) vm_deallocate(kernel_map, (vm_offset_t)user_data, *dataCount);
    }
    if (data) *data = NULL;
    if (dataCount) *dataCount = 0;

    return rc;
}


/*
 * The retain and release calls take no user data, but the caller
 * may have sent some in error (the MIG definition allows it).
 * If this is the case, they will just return that same data
 * right back to the caller (since they never touch the *data and
 * *dataCount fields).
 */
kern_return_t
kmod_retain(kmod_t id)
{
    kern_return_t rc = KERN_SUCCESS;

    kmod_info_t *t;    // reference to
    kmod_info_t *f;    // reference from
    kmod_reference_t *r = NULL;

    r = (kmod_reference_t *)kalloc(sizeof(struct kmod_reference));
    if (!r) {
        rc = KERN_RESOURCE_SHORTAGE;
        goto finish;
    }

    mutex_lock(kmod_lock);

    t = kmod_lookupbyid(KMOD_UNPACK_TO_ID(id));
    f = kmod_lookupbyid(KMOD_UNPACK_FROM_ID(id));
    if (!t || !f) {
        mutex_unlock(kmod_lock);
        if (r) kfree(r, sizeof(struct kmod_reference));
        rc = KERN_INVALID_ARGUMENT;
        goto finish;
    }

    r->next = f->reference_list;
    r->info = t;
    f->reference_list = r;
    t->reference_count++;

    mutex_unlock(kmod_lock);

finish:

    return rc;
}


kern_return_t
kmod_release(kmod_t id)
{
    kern_return_t rc = KERN_INVALID_ARGUMENT;

    kmod_info_t *t;    // reference to
    kmod_info_t *f;    // reference from
    kmod_reference_t *r = NULL;
    kmod_reference_t * p;

    mutex_lock(kmod_lock);

    t = kmod_lookupbyid(KMOD_UNPACK_TO_ID(id));
    f = kmod_lookupbyid(KMOD_UNPACK_FROM_ID(id));
    if (!t || !f) {
        rc = KERN_INVALID_ARGUMENT;
        goto finish;
    }

    p = r = f->reference_list;
    while (r) {
        if (r->info == t) {
            if (p == r) {    // first element
                f->reference_list = r->next;
            } else {
                p->next = r->next;
            }
            r->info->reference_count--;

        mutex_unlock(kmod_lock);
            kfree(r, sizeof(struct kmod_reference));
        rc = KERN_SUCCESS;
            goto finish;
        }
        p = r;
        r = r->next;
    }

    mutex_unlock(kmod_lock);

finish:

    return rc;
}


kern_return_t
kmod_control(host_priv_t host_priv,
         kmod_t id,
         kmod_control_flavor_t flavor,
         kmod_args_t *data,
         mach_msg_type_number_t *dataCount)
{
    kern_return_t rc = KERN_SUCCESS;

   /* Only allow non-root access to retrieve kernel symbols or UUID.
    */
    if (flavor != KMOD_CNTL_GET_KERNEL_SYMBOLS &&
        flavor != KMOD_CNTL_GET_UUID) {

        if (host_priv == HOST_PRIV_NULL) return KERN_INVALID_HOST;
    }

    switch (flavor) {

      case KMOD_CNTL_START:
      case KMOD_CNTL_STOP:
        {
            rc = kmod_start_or_stop(id, (flavor == KMOD_CNTL_START),
                data, dataCount);
            break;
        }

      case KMOD_CNTL_RETAIN:
        {
            rc = kmod_retain(id);
            break;
        }

      case KMOD_CNTL_RELEASE:
        {
            rc = kmod_release(id);
            break;
        }

      case KMOD_CNTL_GET_CMD:
        {

            cmd_queue_entry_t *e;

           /* Throw away any data the user may have sent in error.
            * We must do this, because we are likely to return to
            * some data for these commands (thus causing a leak of
            * whatever data the user sent us in error).
            */
            if (*data && *dataCount) {
                vm_map_copy_discard(*data);
                *data = NULL;
                *dataCount = 0;
            }
            
            mutex_lock(kmod_queue_lock);

            if (queue_empty(&kmod_cmd_queue)) {
                wait_result_t res;

                res = thread_sleep_mutex((event_t)&kmod_cmd_queue,
                    kmod_queue_lock,
                    THREAD_ABORTSAFE);
                if (queue_empty(&kmod_cmd_queue)) {
                    // we must have been interrupted!
                    mutex_unlock(kmod_queue_lock);
                    assert(res == THREAD_INTERRUPTED);
                    return KERN_ABORTED;
                }
            }
            e = (cmd_queue_entry_t *)dequeue_head(&kmod_cmd_queue);

            mutex_unlock(kmod_queue_lock);

            rc = vm_map_copyin(kernel_map, (vm_map_address_t)e->data,
                   (vm_map_size_t)e->size, TRUE, (vm_map_copy_t *)data);
            if (rc) {
                mutex_lock(kmod_queue_lock);
                enqueue_head(&kmod_cmd_queue, (queue_entry_t)e);
                mutex_unlock(kmod_queue_lock);
                *data = NULL;
                *dataCount = 0;
                return rc;
            }
            *dataCount = e->size;

            kfree(e, sizeof(struct cmd_queue_entry));
        
            break;
        }

      case KMOD_CNTL_GET_KERNEL_SYMBOLS:
        {
           /* Throw away any data the user may have sent in error.
            * We must do this, because we are likely to return to
            * some data for these commands (thus causing a leak of
            * whatever data the user sent us in error).
            */
            if (*data && *dataCount) {
                vm_map_copy_discard(*data);
                *data = NULL;
                *dataCount = 0;
            }
            
            return kmod_get_symbol_data(data, dataCount);
            break;
        }

      case KMOD_CNTL_FREE_LINKEDIT_DATA:
        {
            return kmod_free_linkedit_data();
            break;
        }

      case KMOD_CNTL_GET_UUID:
        {
            uint32_t id_length = *dataCount;
            char * kext_id = NULL;
            vm_map_offset_t map_addr;
            void * user_data;
            kern_return_t result;

           /* Get the bundle id, if provided, and discard the buffer sent down.
            */
            if (*data && *dataCount) {
                kmem_alloc(kernel_map, (vm_offset_t *)&kext_id, id_length);
                if (!kext_id) {
                    return KERN_FAILURE;
                }
                
                vm_map_copyout(kernel_map, &map_addr, (vm_map_copy_t)*data);
                user_data = CAST_DOWN(void *, map_addr);

                memcpy(kext_id, user_data, id_length);
                kext_id[id_length-1] = '\0';
                if (user_data) {
                    (void)vm_deallocate(kernel_map, (vm_offset_t)user_data, *dataCount);
                }
                *data = NULL;
                *dataCount = 0;
            }
            
            result = kmod_get_kext_uuid(kext_id, data, dataCount);
            if (kext_id) {
                kmem_free(kernel_map, (vm_offset_t)kext_id, id_length);
            }
            return result;
            break;
        }

      case KMOD_CNTL_DISABLE_LOAD:
        {
            kmod_load_disabled = 1;
            rc = KERN_SUCCESS;
            break;
        }

      default:
        rc = KERN_INVALID_ARGUMENT;
    }

    return rc;
};

/*******************************************************************************
* This function creates a dummy symbol file for the running kernel based on data
* in the run-time image. This allows us to correctly link other executables
* (drivers, etc) against the kernel when the kernel image on the root filesystem
* does not match the live kernel, as c can occur during net-booting where the
* actual kernel image is obtained from the network via tftp rather than the root
* device.
*
* If a symbol table is available, then a link-suitable Mach-O file image is
* created containing a Mach Header and an LC_SYMTAB load command followed by the
* the symbol table data for mach_kernel. A UUID load command is also present for
* identification, so we don't link against the wrong kernel.
*
* NOTE: This file supports only 32 bit kernels; adding support for 64 bit
* kernels is possible, but is not necessary yet.
*******************************************************************************/
extern struct mach_header _mh_execute_header;
static int                _linkedit_segment_freed = 0;

static kern_return_t
kmod_get_symbol_data(
    kmod_args_t * symbol_data,
    mach_msg_type_number_t * data_size)
{
    kern_return_t            result = KERN_FAILURE;

    struct load_command    * load_cmd;
    struct mach_header     * orig_header = &_mh_execute_header;
    struct segment_command * orig_text = NULL;
    struct segment_command * orig_data = NULL;
    struct segment_command * orig_linkedit = NULL;
    struct uuid_command    * orig_uuid = NULL;
    struct symtab_command  * orig_symtab = NULL;
    struct section         * sect;
    struct section         * const_text = NULL;

    vm_size_t                header_size = 0;
    vm_offset_t              symtab_size;
    vm_offset_t              total_size;  // copied out to 'data_size'
    char                   * buffer = 0;  // copied out to 'symbol_data'

    struct mach_header     * header;
    struct segment_command * seg_cmd = NULL;
    struct symtab_command  * symtab;

    unsigned int             i;
    caddr_t                  addr;
    vm_offset_t              offset;

    // only want to do these 1st call
    static int               syms_marked = 0;

    mutex_lock(kmod_lock);

   /*****
    * Check for empty out parameter pointers, and zero them if ok.
    */
    if (!symbol_data || !data_size) {
        result = KERN_INVALID_ARGUMENT;
        goto finish;
    }

    *symbol_data = NULL;
    *data_size = 0;

    if (_linkedit_segment_freed) {
        result = KERN_MEMORY_FAILURE;
        goto finish;
    }
    
   /*****
    * Scan the in-memory kernel's mach header for the parts we need to copy:
    * TEXT (for basic file info + const section), DATA (for basic file info),
    * LINKEDIT (for the symbol table entries), SYMTAB (for the symbol table
    * overall).
    */
    load_cmd = (struct load_command *)&orig_header[1];
    for (i = 0; i < orig_header->ncmds; i++) {
        if (load_cmd->cmd == LC_SEGMENT) {
            struct segment_command * orig_seg_cmd =
                (struct segment_command *)load_cmd;

            if (!strncmp(SEG_TEXT, orig_seg_cmd->segname, strlen(SEG_TEXT))) {
                orig_text = orig_seg_cmd;
            } else if (!strncmp(SEG_DATA, orig_seg_cmd->segname,
                strlen(SEG_DATA))) {

                orig_data = orig_seg_cmd;
            } else if (!strncmp(SEG_LINKEDIT, orig_seg_cmd->segname,
                strlen(SEG_LINKEDIT))) {

                orig_linkedit = orig_seg_cmd;
            }
        } else if (load_cmd->cmd == LC_UUID) {
            orig_uuid = (struct uuid_command *)load_cmd;
        } else if (load_cmd->cmd == LC_SYMTAB) {
            orig_symtab = (struct symtab_command *)load_cmd;
        }

        load_cmd = (struct load_command *)((caddr_t)load_cmd + load_cmd->cmdsize);
    }

   /* Bail if any wasn't found.
    */
    if (!orig_text || !orig_data || !orig_linkedit || !orig_uuid || !orig_symtab) {
        goto finish;
    }

   /* Now seek out the const section of the TEXT segment, bailing if not found.
    */
    sect = (struct section *)&orig_text[1];
    for (i = 0; i < orig_text->nsects; i++, sect++) {
        if (!strncmp("__const", sect->sectname, sizeof("__const"))) {
            const_text = sect;
            break;
        }
    }
    if (!const_text) {
        goto finish;
    }

   /*****
    * Calculate the total size needed and allocate the buffer. In summing the
    * total size, every size before the last must be rounded to a
    * page-size increment.
    */
    header_size = sizeof(struct mach_header) +
        orig_text->cmdsize + orig_data->cmdsize +
        orig_uuid->cmdsize + orig_symtab->cmdsize;
    symtab_size = (orig_symtab->nsyms * sizeof(struct nlist)) +
        orig_symtab->strsize;
    total_size = round_page(header_size) + round_page(const_text->size) +
        symtab_size;

    (void)kmem_alloc(kernel_map, (vm_offset_t *)&buffer, total_size);
    if (!buffer) {
        goto finish;
    }
    bzero((void *)buffer, total_size);

   /*****
    * Set up the Mach-O header in the buffer.
    */
    header = (struct mach_header *)buffer;
    header->magic      = orig_header->magic;
    header->cputype    = orig_header->cputype;
    header->cpusubtype = orig_header->cpusubtype;
    header->filetype   = orig_header->filetype;
    header->ncmds      = 4;  // TEXT, DATA, UUID, SYMTAB
    header->sizeofcmds = header_size - sizeof(struct mach_header);
    header->flags      = orig_header->flags;

   /*****
    * Initialize the current file offset and addr; updated as we go through,
    * but only for fields that need proper info.
    */
    offset = round_page(header_size);
    addr   = (caddr_t)const_text->addr;

   /*****
    * Construct a TEXT segment load command. The only content of the TEXT
    * segment that we actually copy is the __TEXT,__const, which contains the
    * kernel vtables.  The other sections are just filled with unincremented
    * addr/offset and zero size and number fields.
    */
    seg_cmd = (struct segment_command *)&header[1]; // just past mach header
    memcpy(seg_cmd, orig_text, orig_text->cmdsize);
    seg_cmd->vmaddr   = (unsigned long)addr;
    seg_cmd->vmsize   = const_text->size;
    seg_cmd->fileoff  = 0;
    seg_cmd->filesize = const_text->size + round_page(header_size);
    seg_cmd->maxprot  = 0;
    seg_cmd->initprot = 0;
    seg_cmd->flags    = 0;
    sect = (struct section *)(seg_cmd + 1);
    for (i = 0; i < seg_cmd->nsects; i++, sect++) {
        sect->addr  = (unsigned long)addr; // only valid for __TEXT,__const
        sect->size  = 0;
        sect->offset = offset;
        sect->nreloc = 0;
        if (0 == strncmp("__const", sect->sectname, sizeof("__const"))) {
            sect->size = const_text->size;
            addr      += const_text->size;
            offset    += const_text->size;
            const_text = sect;  // retarget to constructed section
        }
    }
    offset = round_page(offset);

   /*****
    * Now copy the __DATA segment load command, but none of its content.
    */
    seg_cmd = (struct segment_command *)((int)seg_cmd + seg_cmd->cmdsize);
    memcpy(seg_cmd, orig_data, orig_data->cmdsize);

    seg_cmd->vmaddr   = (unsigned long)addr;
    seg_cmd->vmsize   = 0x1000;    // Why not just zero? DATA seg is empty.
    seg_cmd->fileoff  = offset;
    seg_cmd->filesize = 0;
    seg_cmd->maxprot  = 0;
    seg_cmd->initprot = 0;
    seg_cmd->flags    = 0;
    sect = (struct section *)(seg_cmd+1);
    for (i = 0; i < seg_cmd->nsects; i++, sect++) {
        sect->addr   = (unsigned long)addr;
        sect->size   = 0;
        sect->offset = offset;
        sect->nreloc = 0;
    }
    offset = round_page(offset);

   /* Set up LC_UUID command
    */
    seg_cmd = (struct segment_command *)((int)seg_cmd + seg_cmd->cmdsize);
    memcpy(seg_cmd, orig_uuid, orig_uuid->cmdsize);

   /* Set up LC_SYMTAB command
    */
    symtab          = (struct symtab_command *)((int)seg_cmd + seg_cmd->cmdsize);
    symtab->cmd     = LC_SYMTAB;
    symtab->cmdsize = sizeof(struct symtab_command);
    symtab->symoff  = offset;
    symtab->nsyms   = orig_symtab->nsyms;
    symtab->strsize = orig_symtab->strsize;
    symtab->stroff  = offset + symtab->nsyms * sizeof(struct nlist);    

   /* Convert the symbol table in place (yes, in the running kernel)
    * from section references to absolute references.
    */
    if (!syms_marked) {
        struct nlist * sym = (struct nlist *) orig_linkedit->vmaddr;
        for (i = 0; i < orig_symtab->nsyms; i++, sym++) {
            if ((sym->n_type & N_TYPE) == N_SECT) {
                sym->n_sect = NO_SECT;
                sym->n_type = (sym->n_type & ~N_TYPE) | N_ABS;
            }
        }
        syms_marked = 1;
    }
    
   /*****
    * Copy the contents of the __TEXT,__const section and the linkedit symbol
    * data into the constructed object file buffer. The header has already been
    * filled in.
    */
    memcpy(buffer + const_text->offset, (void *)const_text->addr, const_text->size);
    memcpy(buffer + symtab->symoff, (void *)orig_linkedit->vmaddr, symtab_size);

    result = vm_map_copyin(kernel_map,
        (vm_offset_t)buffer,
        (vm_map_size_t)total_size,
        /* src_destroy */ TRUE,
        (vm_map_copy_t *)symbol_data);
    if (result != KERN_SUCCESS) {
        kmem_free(kernel_map, (vm_offset_t)buffer, total_size);
        *symbol_data = NULL;
        *data_size   = 0;
        goto finish;
    } else {
        *data_size = total_size;
    }

finish:
    mutex_unlock(kmod_lock);
    return result;
}

/*******************************************************************************
* Drop the LINKEDIT segment from the running kernel to recover wired memory.
* This is invoked by kextd after it has successfully determined a file is
* available in the root filesystem to link against (either a symbol file it
* wrote, or /mach_kernel).
*******************************************************************************/
// in IOCatalogue.cpp
extern int kernelLinkerPresent;

static kern_return_t
kmod_free_linkedit_data(void)
{
    kern_return_t result = KERN_FAILURE;

    const char * dt_kernel_header_name = "Kernel-__HEADER";
    const char * dt_kernel_symtab_name = "Kernel-__SYMTAB";
    struct mach_header_t * dt_mach_header = NULL;
    vm_size_t dt_mach_header_size = 0;
    struct symtab_command *dt_symtab = NULL;
    vm_size_t dt_symtab_size = 0;
    int dt_result;

    struct segment_command * segmentLE;
    boolean_t    keepsyms = FALSE;
    const char * segment_name = "__LINKEDIT";
#if __ppc__ || __arm__
    const char * devtree_segment_name = "Kernel-__LINKEDIT";
    void       * segment_paddress;
    vm_size_t    segment_size;
#endif

    mutex_lock(kmod_lock);

   /* The semantic is "make sure the linkedit segment is freed", so if we
    * previously did it, it's a success.
    */
    if (_linkedit_segment_freed) {
        result = KERN_SUCCESS;
        goto finish;
    } else if (kernelLinkerPresent) {
        // The in-kernel linker requires the linkedit segment to function.
        // Refuse to dump if it's still around.
        // XXX: We need a dedicated error return code for this.
        printf("can't remove kernel __LINKEDIT segment - in-kernel linker needs it\n");
        result = KERN_MEMORY_FAILURE;
        goto finish;
    }

   /* Dispose of unnecessary stuff that the booter didn't need to load.
    */
    dt_result = IODTGetLoaderInfo(dt_kernel_header_name,
        (void **)&dt_mach_header, &dt_mach_header_size);
    if (dt_result == 0 && dt_mach_header) {
        IODTFreeLoaderInfo(dt_kernel_header_name, (void *)dt_mach_header,
            round_page_32(dt_mach_header_size));
    }
    dt_result = IODTGetLoaderInfo(dt_kernel_symtab_name,
        (void **)&dt_symtab, &dt_symtab_size);
    if (dt_result == 0 && dt_symtab) {
        IODTFreeLoaderInfo(dt_kernel_symtab_name, (void *)dt_symtab,
            round_page_32(dt_symtab_size));
    }

    PE_parse_boot_argn("keepsyms", &keepsyms, sizeof (keepsyms));

    segmentLE = getsegbyname(segment_name);
    if (!segmentLE) {
        printf("error removing kernel __LINKEDIT segment\n");
        goto finish;
    }
    OSRuntimeUnloadCPPForSegment(segmentLE);
#if __ppc__ || __arm__
    if (!keepsyms && 0 == IODTGetLoaderInfo(devtree_segment_name,
        &segment_paddress, &segment_size)) {

        IODTFreeLoaderInfo(devtree_segment_name, (void *)segment_paddress,
            (int)segment_size);
    }
#elif __i386__
    if (!keepsyms && segmentLE->vmaddr && segmentLE->vmsize) {
        ml_static_mfree(segmentLE->vmaddr, segmentLE->vmsize);
    }
#else
#error arch
#endif
    result = KERN_SUCCESS;

finish:
    if (!keepsyms && result == KERN_SUCCESS) {
        _linkedit_segment_freed = 1;
    }
    mutex_unlock(kmod_lock);
    return result;
}

/*******************************************************************************
* Retrieve the UUID load command payload from the running kernel.
*******************************************************************************/
static kern_return_t
kmod_get_kext_uuid(
    const char * kext_id,
    kmod_args_t * data,
    mach_msg_type_number_t * dataCount)
{
    kern_return_t result = KERN_FAILURE;
    kmod_info_t * kmod_info = NULL;
    unsigned int i;
    char * uuid_data = 0;
    struct mach_header  * header = &_mh_execute_header;
    struct load_command * load_cmd = (struct load_command *)&header[1];
    struct uuid_command * uuid_cmd;

   /* If given no kext ID, retrieve the kernel UUID.
    */
    if (!kext_id) {
        header = &_mh_execute_header;
    } else {
        kmod_info = kmod_lookupbyname_locked(kext_id);
        if (!kmod_info) {
            result = KERN_INVALID_ARGUMENT;
            goto finish;
        }
        
       /* If the kmod is build-in, it's part of the kernel, so retrieve the
        * kernel UUID.
        */
        if (!kmod_info->address) {
            header = &_mh_execute_header;
        } else {
            header = (struct mach_header *)kmod_info->address;
        }
    }

    load_cmd = (struct load_command *)&header[1];

    for (i = 0; i < header->ncmds; i++) {
        if (load_cmd->cmd == LC_UUID) {
            uuid_cmd = (struct uuid_command *)load_cmd;

           /* kmem_alloc() a local buffer that's on a boundary known to work
            * with vm_map_copyin().
            */
            result = kmem_alloc(kernel_map, (vm_offset_t *)&uuid_data,
                sizeof(uuid_cmd->uuid));
            if (result != KERN_SUCCESS) {
                result = KERN_RESOURCE_SHORTAGE;
                goto finish;
            }
            
            memcpy(uuid_data, uuid_cmd->uuid, sizeof(uuid_cmd->uuid));
            
            result = vm_map_copyin(kernel_map, (vm_offset_t)uuid_data,
                sizeof(uuid_cmd->uuid), /* src_destroy */ TRUE,
                (vm_map_copy_t *)data);
            if (result == KERN_SUCCESS) {
                *dataCount = sizeof(uuid_cmd->uuid);
            } else {
                result = KERN_RESOURCE_SHORTAGE;
                kmem_free(kernel_map, (vm_offset_t)uuid_data,
                    sizeof(uuid_cmd->uuid));
            }
            goto finish;
        }
        
        load_cmd = (struct load_command *)((caddr_t)load_cmd + load_cmd->cmdsize);
    }

finish:
    return result;
}

kern_return_t
kmod_get_info(__unused host_t host,
          kmod_info_array_t *kmods,
          mach_msg_type_number_t *kmodCount)
{
    vm_offset_t data;
    kmod_info_t *k, *p1;
    kmod_reference_t *r, *p2;
    int ref_count;
    unsigned size = 0;
    kern_return_t rc = KERN_SUCCESS;

    *kmods = (void *)0;
    *kmodCount = 0;

retry:
    mutex_lock(kmod_lock);
    size = 0;
    k = kmod;
    while (k) {
        size += sizeof(kmod_info_t);
        r = k->reference_list;
        while (r) {
            size +=sizeof(kmod_reference_t);
            r = r->next;
        }
        k = k->next;
    }
    mutex_unlock(kmod_lock);
    if (!size) return KERN_SUCCESS;

    rc = kmem_alloc(kernel_map, &data, size);
    if (rc) return rc;

    // copy kmod into data, retry if kmod's size has changed (grown)
    // the copied out data is tweeked to figure what's what at user level
    // change the copied out k->next pointers to point to themselves
    // change the k->reference into a count, tack the references on
    // the end of the data packet in the order they are found

    mutex_lock(kmod_lock);
    k = kmod; p1 = (kmod_info_t *)data;
    while (k) {
        if ((p1 + 1) > (kmod_info_t *)(data + size)) {
            mutex_unlock(kmod_lock);
            kmem_free(kernel_map, data, size);
            goto retry;
        }

        *p1 = *k;
        if (k->next) p1->next = k;
        p1++; k = k->next;
    }

    p2 = (kmod_reference_t *)p1;
    k = kmod; p1 = (kmod_info_t *)data;
    while (k) {
        r = k->reference_list; ref_count = 0;
        while (r) {
            if ((p2 + 1) > (kmod_reference_t *)(data + size)) {
                mutex_unlock(kmod_lock);
                kmem_free(kernel_map, data, size);
                goto retry;
            }
            // note the last 'k' in the chain has its next == 0
            // since there can only be one like that, 
            // this case is handled by the caller
            *p2 = *r;
            p2++; r = r->next; ref_count++;
        }
        p1->reference_list = (kmod_reference_t *)ref_count;
        p1++; k = k->next;
    }
    mutex_unlock(kmod_lock);
    
    rc = vm_map_copyin(kernel_map, data, size, TRUE, (vm_map_copy_t *)kmods);
    if (rc) {
        kmem_free(kernel_map, data, size);
        *kmods = NULL;
        *kmodCount = 0;
        return rc;
    }
    *kmodCount = size;

    return KERN_SUCCESS;
}

/*
 * Operates only on 32 bit mach keaders on behalf of kernel module loader
 */
static kern_return_t
kmod_call_funcs_in_section(struct mach_header *header, const char *sectName)
{
    typedef void (*Routine)(void);
    Routine *     routines;
    int           size, i;

    if (header->magic != MH_MAGIC) {
        return KERN_INVALID_ARGUMENT;
    }

    routines = (Routine *) getsectdatafromheader(header, SEG_TEXT, /*(char *)*/ sectName, &size);
    if (!routines) return KERN_SUCCESS;

    size /= sizeof(Routine);
    for (i = 0; i < size; i++) {
        (*routines[i])();
    }

    return KERN_SUCCESS;
}

/*
 * Operates only on 32 bit mach keaders on behalf of kernel module loader
 */
kern_return_t
kmod_initialize_cpp(kmod_info_t *info)
{
    return kmod_call_funcs_in_section((struct mach_header *)info->address, "__constructor");
}

/*
 * Operates only on 32 bit mach keaders on behalf of kernel module loader
 */
kern_return_t
kmod_finalize_cpp(kmod_info_t *info)
{
    return kmod_call_funcs_in_section((struct mach_header *)info->address, "__destructor");
}

kern_return_t
kmod_default_start(__unused struct kmod_info *ki, __unused void *data)
{
    return KMOD_RETURN_SUCCESS;
}

kern_return_t
kmod_default_stop(__unused struct kmod_info *ki, __unused void *data)
{
    return KMOD_RETURN_SUCCESS;
}

static void
kmod_dump_to(vm_offset_t *addr, unsigned int cnt,
    int (*printf_func)(const char *fmt, ...))
{
    vm_offset_t * kscan_addr = NULL;
    kmod_info_t * k;
    kmod_reference_t * r;
    unsigned int i;
    int found_kmod = 0;
    kmod_info_t * stop_kmod = NULL;

    for (k = kmod; k; k = k->next) {
        if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)k)) == 0) {
            (*printf_func)("         kmod scan stopped due to missing "
                "kmod page: %08x\n", stop_kmod);
            break;
        }
        if (!k->address) {
            continue; // skip fake entries for built-in kernel components
        }
        for (i = 0, kscan_addr = addr; i < cnt; i++, kscan_addr++) {
            if ((*kscan_addr >= k->address) &&
                (*kscan_addr < (k->address + k->size))) {

                if (!found_kmod) {
                    (*printf_func)("      Kernel loadable modules in backtrace "
                        "(with dependencies):\n");
                }
                found_kmod = 1;
                (*printf_func)("         %s(%s)@0x%x->0x%x\n",
                    k->name, k->version, k->address, k->address + k->size - 1);

                for (r = k->reference_list; r; r = r->next) {
                    kmod_info_t * rinfo;

                    if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)r)) == 0) {
                        (*printf_func)("            kmod dependency scan stopped "
                            "due to missing dependency page: %08x\n", r);
                        break;
                    }

                    rinfo = r->info;

                    if (pmap_find_phys(kernel_pmap, (addr64_t)((uintptr_t)rinfo)) == 0) {
                        (*printf_func)("            kmod dependency scan stopped "
                            "due to missing kmod page: %08x\n", rinfo);
                        break;
                    }

                    if (!rinfo->address) {
                        continue; // skip fake entries for built-ins
                    }

                    (*printf_func)("            dependency: %s(%s)@0x%x\n",
                        rinfo->name, rinfo->version, rinfo->address);
                }

                break;  // only report this kmod for one backtrace address
            }
        }
    }

    return;
}

void
kmod_dump(vm_offset_t *addr, unsigned int cnt)
{
    kmod_dump_to(addr, cnt, &kdb_printf);
}

void kmod_dump_log(vm_offset_t *, unsigned); /* gcc 4 warn fix */

void
kmod_dump_log(vm_offset_t *addr, unsigned int cnt)
{
    kmod_dump_to(addr, cnt, &printf);
}
