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
#include <mach/machine.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <sys/types.h>

#if KERNEL
    #include <libkern/kernel_mach_header.h>
    #include <libkern/OSKextLib.h>
    #include <libkern/OSKextLibPrivate.h>
    #include <mach/vm_param.h>
    #include <mach-o/fat.h>
#else /* !KERNEL */
    #include <architecture/byte_order.h>
    #include <mach/mach_init.h>
    #include <mach-o/arch.h>
    #include <mach-o/swap.h>
#endif /* KERNEL */

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_demangle.h"
#include "kxld_dict.h"
#include "kxld_kext.h"
#include "kxld_reloc.h"
#include "kxld_sect.h"
#include "kxld_seg.h"
#include "kxld_state.h"
#include "kxld_symtab.h"
#include "kxld_util.h"
#include "kxld_uuid.h"
#include "kxld_vtable.h"

struct symtab_command;

enum kxld_link_type {
    KXLD_LINK_KERNEL,
    KXLD_LINK_PSEUDO_KEXT,
    KXLD_LINK_KEXT,
    KXLD_LINK_UNKNOWN
};

typedef enum kxld_link_type KXLDLinkType;

struct kxld_kext {
    u_char *file;
    u_long size;
    const char *name;
    uint32_t filetype;
    KXLDArray segs;
    KXLDArray sects;
    KXLDArray vtables;
    KXLDArray extrelocs;
    KXLDArray locrelocs;
    KXLDDict vtable_index;
    KXLDRelocator relocator;
    KXLDuuid uuid;
    KXLDSymtab *symtab;
    kxld_addr_t link_addr;
    kmod_info_t *kmod_info;
    kxld_addr_t kmod_link_addr;
    cpu_type_t cputype;
    cpu_subtype_t cpusubtype;
    KXLDLinkType link_type;
    KXLDFlags flags;
    boolean_t is_final_image;
    boolean_t got_is_created;
    struct dysymtab_command *dysymtab_hdr;
#if KXLD_USER_OR_OBJECT
    KXLDArray *section_order;
#endif
#if !KERNEL
    enum NXByteOrder host_order;
    enum NXByteOrder target_order;
#endif
};

/*******************************************************************************
* Prototypes
*******************************************************************************/

static kern_return_t get_target_machine_info(KXLDKext *kext, cpu_type_t cputype, 
    cpu_subtype_t cpusubtype);
static kern_return_t get_file_for_arch(KXLDKext *kext, u_char *file, u_long size);

static u_long get_macho_header_size(const KXLDKext *kext);
static u_long get_macho_data_size(const KXLDKext *kext);
static kern_return_t export_macho_header(const KXLDKext *kext, u_char *buf, 
    u_int ncmds, u_long *header_offset, u_long header_size);

static kern_return_t init_from_execute(KXLDKext *kext);
static kern_return_t init_from_final_linked_image(KXLDKext *kext, u_int *filetype_out,
    struct symtab_command **symtab_hdr_out);

static boolean_t target_supports_protected_segments(const KXLDKext *kext)
    __attribute__((pure));

#if KXLD_USER_OR_OBJECT
static boolean_t target_supports_object(const KXLDKext *kext) __attribute((pure));
static kern_return_t init_from_object(KXLDKext *kext);
static kern_return_t process_relocs_from_sections(KXLDKext *kext);
#endif /* KXLD_USER_OR_OBJECT */

#if KXLD_USER_OR_BUNDLE
static boolean_t target_supports_bundle(const KXLDKext *kext) __attribute((pure));
static kern_return_t init_from_bundle(KXLDKext *kext);
static kern_return_t process_relocs_from_tables(KXLDKext *kext);
static kern_return_t process_symbol_pointers(KXLDKext *kext);
static void add_to_ptr(u_char *symptr, kxld_addr_t val, boolean_t is_32_bit);
#endif /* KXLD_USER_OR_BUNDLE */

static kern_return_t get_metaclass_symbol_from_super_meta_class_pointer_symbol(
    KXLDKext *kext, KXLDSym *super_metaclass_pointer_sym, KXLDSym **meta_class);

static kern_return_t resolve_symbols(KXLDKext *kext, KXLDDict *defined_symbols,
    KXLDDict *obsolete_symbols);
static kern_return_t patch_vtables(KXLDKext *kext, KXLDDict *patched_vtables,
    KXLDDict *defined_symbols);
static kern_return_t validate_symbols(KXLDKext *kext);
static kern_return_t populate_kmod_info(KXLDKext *kext);
static kern_return_t copy_vtables(KXLDKext *kext, const KXLDDict *patched_vtables);
static kern_return_t create_vtables(KXLDKext *kext);
static void restrict_private_symbols(KXLDKext *kext);

#if KXLD_USER_OR_GOT || KXLD_USER_OR_COMMON
static kern_return_t add_section(KXLDKext *kext, KXLDSect **sect);
#endif /* KXLD_USER_OR_GOT || KXLD_USER_OR_COMMON */

#if KXLD_USER_OR_GOT
static boolean_t target_has_got(const KXLDKext *kext) __attribute__((pure));
static kern_return_t create_got(KXLDKext *kext);
static kern_return_t populate_got(KXLDKext *kext);
#endif /* KXLD_USER_OR_GOT */

static boolean_t target_supports_common(const KXLDKext *kext) __attribute((pure));
#if KXLD_USER_OR_COMMON
static kern_return_t resolve_common_symbols(KXLDKext *kext);
#endif /* KXLD_USER_OR_COMMON */

static boolean_t target_supports_strict_patching(KXLDKext *kext)
    __attribute__((pure));

#if KXLD_USER_OR_ILP32
static u_long get_macho_cmd_data_32(u_char *file, u_long offset, 
    u_int *filetype, u_int *ncmds);
static kern_return_t export_macho_header_32(const KXLDKext *kext, u_char *buf, 
    u_int ncmds, u_long *header_offset, u_long header_size);
#endif /* KXLD_USER_OR_ILP32 */
#if KXLD_USER_OR_LP64
static u_long get_macho_cmd_data_64(u_char *file, u_long offset,
    u_int *filetype, u_int *ncmds);
static kern_return_t export_macho_header_64(const KXLDKext *kext, u_char *buf, 
    u_int ncmds, u_long *header_offset, u_long header_size);
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
size_t
kxld_kext_sizeof(void)
{
    return sizeof(KXLDKext);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_kext_init(KXLDKext *kext, u_char *file, u_long size,
    const char *name, KXLDFlags flags, boolean_t is_kernel,
    KXLDArray *section_order __unused, 
    cpu_type_t cputype, cpu_subtype_t cpusubtype)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    u_int i = 0;

    check(kext);
    check(file);
    check(size);

    kext->name = name;
    kext->flags = flags;
#if KXLD_USER_OR_OBJECT
    kext->section_order = section_order;
#endif

    /* Find the local architecture */

    rval = get_target_machine_info(kext, cputype, cpusubtype);
    require_noerr(rval, finish);

    /* Find the Mach-O file for the target architecture */

    rval = get_file_for_arch(kext, file, size);
    require_noerr(rval, finish);

    /* Build the relocator */

    rval = kxld_relocator_init(&kext->relocator, kext->cputype, 
        kext->cpusubtype, kxld_kext_target_needs_swap(kext));
    require_noerr(rval, finish);

    /* Allocate the symbol table */

    if (!kext->symtab) {
        kext->symtab = kxld_alloc(kxld_symtab_sizeof());
        require_action(kext->symtab, finish, rval=KERN_RESOURCE_SHORTAGE);
        bzero(kext->symtab, kxld_symtab_sizeof());
    }

    if (is_kernel) {
        kext->link_type = KXLD_LINK_KERNEL;
    } else {
        kext->link_type = KXLD_LINK_UNKNOWN;
    }

    /* There are four types of Mach-O files that we can support:
     *   1) 32-bit MH_OBJECT      - All pre-SnowLeopard systems
     *   2) 32-bit MH_KEXT_BUNDLE - Not supported
     *   3) 64-bit MH_OBJECT      - Needed for K64 bringup
     *   4) 64-bit MH_KEXT_BUNDLE - The likely 64-bit kext filetype
     */

    if (kxld_kext_is_32_bit(kext)) {
        struct mach_header *mach_hdr = (struct mach_header *) kext->file;
        kext->filetype = mach_hdr->filetype;
    } else {
        struct mach_header_64 *mach_hdr = (struct mach_header_64 *) kext->file;
        kext->filetype = mach_hdr->filetype;
    }

    switch (kext->filetype) {
#if KXLD_USER_OR_OBJECT
    case MH_OBJECT:
        rval = init_from_object(kext);
        require_noerr(rval, finish);
        break;
#endif /* KXLD_USER_OR_OBJECT */
#if KXLD_USER_OR_BUNDLE
    case MH_KEXT_BUNDLE:
        rval = init_from_bundle(kext);
        require_noerr(rval, finish);
        break;
#endif /* KXLD_USER_OR_BUNDLE */
    case MH_EXECUTE:
        rval = init_from_execute(kext);
        require_noerr(rval, finish);
        break;
    default:
        rval = KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr,
            kKxldLogFiletypeNotSupported, kext->filetype);
        goto finish;
    }

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        kxld_seg_set_vm_protections(seg, target_supports_protected_segments(kext));
    }

    switch (kext->link_type) {
    case KXLD_LINK_KEXT:
        (void) restrict_private_symbols(kext);
        /* Fallthrough */
    case KXLD_LINK_KERNEL:
        rval = create_vtables(kext);
        require_noerr(rval, finish);
        break;
    default:
        break;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
get_target_machine_info(KXLDKext *kext, cpu_type_t cputype __unused, 
    cpu_subtype_t cpusubtype __unused)
{
#if KERNEL

    /* Because the kernel can only link for its own architecture, we know what
     * the host and target architectures are at compile time, so we can use
     * a vastly simplified version of this function.
     */ 

    check(kext);

#if defined(__i386__)
    kext->cputype = CPU_TYPE_I386;
    kext->cpusubtype = CPU_SUBTYPE_I386_ALL;
    return KERN_SUCCESS;
#elif defined(__ppc__)
    kext->cputype = CPU_TYPE_POWERPC;
    kext->cpusubtype = CPU_SUBTYPE_POWERPC_ALL;
    return KERN_SUCCESS;
#elif defined(__x86_64__)
    kext->cputype = CPU_TYPE_X86_64;
    kext->cpusubtype = CPU_SUBTYPE_X86_64_ALL;
    return KERN_SUCCESS;
#else 
    kxld_log(kKxldLogLinking, kKxldLogErr, 
        kKxldLogArchNotSupported, _mh_execute_header->cputype);
    return KERN_NOT_SUPPORTED;
#endif /* Supported architecture defines */


#else /* !KERNEL */

    /* User-space must look up the architecture it's running on and the target
     * architecture at run-time.
     */

    kern_return_t rval = KERN_FAILURE;
    const NXArchInfo *host_arch = NULL;

    check(kext);

    host_arch = NXGetLocalArchInfo();
    require_action(host_arch, finish, rval=KERN_FAILURE);

    kext->host_order = host_arch->byteorder;

    /* If the user did not specify a cputype, use the local architecture.
     */

    if (cputype) {
        kext->cputype = cputype;
        kext->cpusubtype = cpusubtype;
    } else {
        kext->cputype = host_arch->cputype;
        kext->target_order = kext->host_order;

        switch (kext->cputype) {
        case CPU_TYPE_I386:
            kext->cpusubtype = CPU_SUBTYPE_I386_ALL;
            break;
        case CPU_TYPE_POWERPC:
            kext->cpusubtype = CPU_SUBTYPE_POWERPC_ALL;
            break;
        case CPU_TYPE_X86_64:
            kext->cpusubtype = CPU_SUBTYPE_X86_64_ALL;
            break;
        case CPU_TYPE_ARM:
            kext->cpusubtype = CPU_SUBTYPE_ARM_ALL;
            break;
        default:
            kext->cpusubtype = 0;
        }
    }

    /* Validate that we support the target architecture and record its 
     * endianness.
     */

    switch(kext->cputype) {
    case CPU_TYPE_ARM:
    case CPU_TYPE_I386:
    case CPU_TYPE_X86_64:
        kext->target_order = NX_LittleEndian;
        break;
    case CPU_TYPE_POWERPC:
        kext->target_order = NX_BigEndian;
        break;
    default:
        rval = KERN_NOT_SUPPORTED;
        kxld_log(kKxldLogLinking, kKxldLogErr, 
            kKxldLogArchNotSupported, kext->cputype);
        goto finish;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
#endif /* KERNEL */
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
get_file_for_arch(KXLDKext *kext, u_char *file, u_long size)
{
    kern_return_t rval = KERN_FAILURE;
    struct mach_header *mach_hdr = NULL;
#if !KERNEL
    struct fat_header *fat = (struct fat_header *) file;
    struct fat_arch *archs = (struct fat_arch *) &fat[1];
    boolean_t swap = FALSE;
#endif /* KERNEL */

    check(kext);
    check(file);
    check(size);

    kext->file = file;
    kext->size = size;

    /* We are assuming that we will never receive a fat file in the kernel */

#if !KERNEL
    require_action(size >= sizeof(*fat), finish, 
        rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogTruncatedMachO));

    /* The fat header is always big endian, so swap if necessary */
    if (fat->magic == FAT_CIGAM) {
        (void) swap_fat_header(fat, kext->host_order);
        swap = TRUE;
    }

    if (fat->magic == FAT_MAGIC) {
        struct fat_arch *arch = NULL;

        require_action(size >= (sizeof(*fat) + (fat->nfat_arch * sizeof(*archs))),
            finish, 
            rval=KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogTruncatedMachO));

        /* Swap the fat_arch structures if necessary */
        if (swap) {
            (void) swap_fat_arch(archs, fat->nfat_arch, kext->host_order);
        }

        /* Locate the Mach-O for the requested architecture */

        arch = NXFindBestFatArch(kext->cputype, kext->cpusubtype, archs, 
            fat->nfat_arch);
        require_action(arch, finish, rval=KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogArchNotFound));
        require_action(size >= arch->offset + arch->size, finish, 
            rval=KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogTruncatedMachO));

        kext->file = file + arch->offset;
        kext->size = arch->size;
    }
#endif /* !KERNEL */

    /* Swap the Mach-O's headers to this architecture if necessary */
    if (kxld_kext_is_32_bit(kext)) {
        rval = validate_and_swap_macho_32(kext->file, kext->size
#if !KERNEL
            , kext->host_order
#endif /* !KERNEL */
            );
    } else {
        rval = validate_and_swap_macho_64(kext->file, kext->size
#if !KERNEL
            , kext->host_order
#endif /* !KERNEL */
            );
    }
    require_noerr(rval, finish);

    mach_hdr = (struct mach_header *) kext->file;
    require_action(kext->cputype == mach_hdr->cputype, finish,
        rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogTruncatedMachO));

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_kext_is_32_bit(const KXLDKext *kext)
{
    check(kext);

    return kxld_is_32_bit(kext->cputype);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_kext_get_cputype(const KXLDKext *kext, cpu_type_t *cputype,
    cpu_subtype_t *cpusubtype)
{
    check(kext);
    check(cputype);
    check(cpusubtype);

    *cputype = kext->cputype;
    *cpusubtype = kext->cpusubtype;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_kext_validate_cputype(const KXLDKext *kext, cpu_type_t cputype,
    cpu_subtype_t cpusubtype __unused)
{
    if (kext->cputype != cputype) return KERN_FAILURE;
    return KERN_SUCCESS;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t
target_supports_protected_segments(const KXLDKext *kext)
{
    return (kext->is_final_image && 
            kext->cputype == CPU_TYPE_X86_64);
}

#if KXLD_USER_OR_OBJECT
/*******************************************************************************
*******************************************************************************/
static boolean_t target_supports_object(const KXLDKext *kext)
{
    return (kext->cputype == CPU_TYPE_POWERPC ||
            kext->cputype == CPU_TYPE_I386    ||
            kext->cputype == CPU_TYPE_ARM);
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
init_from_object(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    struct load_command *cmd_hdr = NULL;
    struct symtab_command *symtab_hdr = NULL;
    struct uuid_command *uuid_hdr = NULL;
    KXLDSect *sect = NULL;
    u_long offset = 0;
    u_long sect_offset = 0;
    u_int filetype = 0;
    u_int ncmds = 0;
    u_int nsects = 0;
    u_int i = 0;
    boolean_t has_segment = FALSE;

    check(kext);

    require_action(target_supports_object(kext),
        finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr,
            kKxldLogFiletypeNotSupported, MH_OBJECT));

    KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), offset,
        get_macho_cmd_data_32, get_macho_cmd_data_64,
        kext->file, offset, &filetype, &ncmds);

    require_action(filetype == MH_OBJECT, finish, rval=KERN_FAILURE);

    /* MH_OBJECTs use one unnamed segment to contain all of the sections.  We
     * loop over all of the load commands to initialize the structures we
     * expect.  Then, we'll use the unnamed segment to get to all of the
     * sections, and then use those sections to create the actual segments.
     */

    for (; i < ncmds; ++i, offset += cmd_hdr->cmdsize) {
        cmd_hdr = (struct load_command *) (kext->file + offset);

        switch(cmd_hdr->cmd) {
#if KXLD_USER_OR_ILP32
        case LC_SEGMENT:
            {
                struct segment_command *seg_hdr = 
                    (struct segment_command *) cmd_hdr;

                /* Ignore segments with no vm size */
                if (!seg_hdr->vmsize) continue;

                require_action(kxld_kext_is_32_bit(kext), finish, rval=KERN_FAILURE;
                    kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                        "LC_SEGMENT in 64-bit kext."));
                require_action(!has_segment, finish, rval=KERN_FAILURE;
                    kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                        "Multiple segments in an MH_OBJECT kext."));

                nsects = seg_hdr->nsects;
                sect_offset = offset + sizeof(*seg_hdr);
                has_segment = TRUE;
            }
            break;
#endif /* KXLD_USER_OR_ILP32 */
#if KXLD_USER_OR_LP64
        case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg_hdr =
                    (struct segment_command_64 *) cmd_hdr;

                /* Ignore segments with no vm size */
                if (!seg_hdr->vmsize) continue;

                require_action(!kxld_kext_is_32_bit(kext), finish, rval=KERN_FAILURE;
                    kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                        "LC_SEGMENT_64 in a 32-bit kext."));
                require_action(!has_segment, finish, rval=KERN_FAILURE;
                    kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                        "Multiple segments in an MH_OBJECT kext."));

                nsects = seg_hdr->nsects;
                sect_offset = offset + sizeof(*seg_hdr);
                has_segment = TRUE;
            }
            break;
#endif /* KXLD_USER_OR_LP64 */
        case LC_SYMTAB:
            symtab_hdr = (struct symtab_command *) cmd_hdr;

            KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), rval,
                kxld_symtab_init_from_macho_32, kxld_symtab_init_from_macho_64,
                kext->symtab, kext->file, symtab_hdr, 0);
            require_noerr(rval, finish);
            break;
        case LC_UUID:
            uuid_hdr = (struct uuid_command *) cmd_hdr;
            kxld_uuid_init_from_macho(&kext->uuid, uuid_hdr);
            break;
        case LC_UNIXTHREAD:
            /* Don't need to do anything with UNIXTHREAD */
            break;
        default:
            rval = KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                "Invalid segment type in MH_OBJECT kext: %u.", cmd_hdr->cmd);
            goto finish;
        }
    }

    if (has_segment) {

        /* Get the number of sections from the segment and build the section index */

        rval = kxld_array_init(&kext->sects, sizeof(KXLDSect), nsects);
        require_noerr(rval, finish);

        /* Loop over all of the sections to initialize the section index */

        for (i = 0; i < nsects; ++i) {
            sect = kxld_array_get_item(&kext->sects, i);
            KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), rval,
                kxld_sect_init_from_macho_32, kxld_sect_init_from_macho_64,
                sect, kext->file, &sect_offset, i, &kext->relocator); 
            require_noerr(rval, finish);
        }

        /* Create special sections */

#if KXLD_USER_OR_GOT
        rval = create_got(kext);
        require_noerr(rval, finish);
#endif /* KXLD_USER_OR_GOT */

#if KXLD_USER_OR_COMMON
        rval = resolve_common_symbols(kext);
        require_noerr(rval, finish);
#endif /* KXLD_USER_OR_COMMON */

        /* Create the segments from the section index */

        rval = kxld_seg_create_seg_from_sections(&kext->segs, &kext->sects);
        require_noerr(rval, finish);

        rval = kxld_seg_finalize_object_segment(&kext->segs, 
            kext->section_order, get_macho_header_size(kext));
        require_noerr(rval, finish);

        kext->link_type = KXLD_LINK_KEXT;
    } else {
        kext->link_type = KXLD_LINK_PSEUDO_KEXT;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}
#endif /* KXLD_USER_OR_OBJECT */

/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_from_final_linked_image(KXLDKext *kext, u_int *filetype_out,
    struct symtab_command **symtab_hdr_out)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    KXLDSect *sect = NULL;
    struct load_command *cmd_hdr = NULL;
    struct symtab_command *symtab_hdr = NULL;
    struct uuid_command *uuid_hdr = NULL;
    u_long base_offset = 0;
    u_long offset = 0;
    u_long sect_offset = 0;
    u_int filetype = 0;
    u_int i = 0;
    u_int j = 0;
    u_int segi = 0;
    u_int secti = 0;
    u_int nsegs = 0;
    u_int nsects = 0;
    u_int ncmds = 0;

    KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), base_offset,
        get_macho_cmd_data_32, get_macho_cmd_data_64,
        kext->file, offset, &filetype, &ncmds);

    /* First pass to count segments and sections */

    offset = base_offset;
    for (i = 0; i < ncmds; ++i, offset += cmd_hdr->cmdsize) {
        cmd_hdr = (struct load_command *) (kext->file + offset);

        switch(cmd_hdr->cmd) {
#if KXLD_USER_OR_ILP32
        case LC_SEGMENT:
            {
                struct segment_command *seg_hdr = 
                    (struct segment_command *) cmd_hdr;

                /* Ignore segments with no vm size */
                if (!seg_hdr->vmsize) continue;

                ++nsegs;
                nsects += seg_hdr->nsects;
            }
            break;
#endif /* KXLD_USER_OR_ILP32 */
#if KXLD_USER_OR_LP64
        case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg_hdr = 
                    (struct segment_command_64 *) cmd_hdr;

                /* Ignore segments with no vm size */
                if (!seg_hdr->vmsize) continue;

                ++nsegs;
                nsects += seg_hdr->nsects;
            }
            break;
#endif /* KXLD_USER_OR_LP64 */
        default:
            continue;
        }
    }

    /* Allocate the segments and sections */

    if (nsegs) {
        rval = kxld_array_init(&kext->segs, sizeof(KXLDSeg), nsegs);
        require_noerr(rval, finish);

        rval = kxld_array_init(&kext->sects, sizeof(KXLDSect), nsects);
        require_noerr(rval, finish);
    }

    /* Initialize the segments and sections */

    offset = base_offset;
    for (i = 0; i < ncmds; ++i, offset += cmd_hdr->cmdsize) {
        cmd_hdr = (struct load_command *) (kext->file + offset); 
        seg = NULL;

        switch(cmd_hdr->cmd) {
#if KXLD_USER_OR_ILP32
        case LC_SEGMENT:
            {
                struct segment_command *seg_hdr =
                    (struct segment_command *) cmd_hdr;

                /* Ignore segments with no vm size */
                if (!seg_hdr->vmsize) continue;

                seg = kxld_array_get_item(&kext->segs, segi++);

                rval = kxld_seg_init_from_macho_32(seg, seg_hdr);
                require_noerr(rval, finish);

                sect_offset = offset + sizeof(*seg_hdr);
            }
            break;
#endif /* KXLD_USER_OR_ILP32 */
#if KXLD_USER_OR_LP64
        case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg_hdr = 
                    (struct segment_command_64 *) cmd_hdr;

                /* Ignore segments with no vm size */
                if (!seg_hdr->vmsize) continue;

                seg = kxld_array_get_item(&kext->segs, segi++);

                rval = kxld_seg_init_from_macho_64(seg, seg_hdr);
                require_noerr(rval, finish);

                sect_offset = offset + sizeof(*seg_hdr);
            }
            break;
#endif /* KXLD_USER_OR_LP64 */
        case LC_SYMTAB:
            symtab_hdr = (struct symtab_command *) cmd_hdr;
            break;
        case LC_UUID:
            uuid_hdr = (struct uuid_command *) cmd_hdr;
            kxld_uuid_init_from_macho(&kext->uuid, uuid_hdr);
            break;
        case LC_DYSYMTAB:
            kext->dysymtab_hdr = (struct dysymtab_command *) cmd_hdr;            

            rval = kxld_reloc_create_macho(&kext->extrelocs, &kext->relocator,
                (struct relocation_info *) (kext->file + kext->dysymtab_hdr->extreloff), 
                kext->dysymtab_hdr->nextrel);
            require_noerr(rval, finish);

            rval = kxld_reloc_create_macho(&kext->locrelocs, &kext->relocator,
                (struct relocation_info *) (kext->file + kext->dysymtab_hdr->locreloff), 
                kext->dysymtab_hdr->nlocrel);
            require_noerr(rval, finish);

            break;
        case LC_UNIXTHREAD:
            /* Don't need to do anything with UNIXTHREAD for the kernel */
            require_action(kext->link_type == KXLD_LINK_KERNEL, finish, 
                rval=KERN_FAILURE;
                kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                    "LC_UNIXTHREAD segment is not valid in a kext."));
            break;
        default:
            rval=KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
                "Invalid segment type in MH_KEXT_BUNDLE kext: %u.", cmd_hdr->cmd);
            goto finish;
        }

        if (seg) {

            /* Initialize the sections */
            for (j = 0; j < seg->sects.nitems; ++j, ++secti) {
                sect = kxld_array_get_item(&kext->sects, secti);
                KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), rval,
                    kxld_sect_init_from_macho_32, kxld_sect_init_from_macho_64,
                    sect, kext->file, &sect_offset, secti, &kext->relocator);
                require_noerr(rval, finish);

                /* Add the section to the segment.  This will also make sure
                 * that the sections and segments have the same segname.
                 */
                rval = kxld_seg_add_section(seg, sect);
                require_noerr(rval, finish);
            }
            rval = kxld_seg_finish_init(seg);
            require_noerr(rval, finish);
        }
    }

    if (filetype_out) *filetype_out = filetype;
    if (symtab_hdr_out) *symtab_hdr_out = symtab_hdr;
    kext->is_final_image = TRUE;
    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
init_from_execute(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    struct symtab_command *symtab_hdr = NULL;
    kxld_addr_t linkedit_offset = 0;
    u_int filetype = 0;
#if KERNEL
    KXLDSeg *textseg = NULL;
    KXLDSeg *linkeditseg = NULL;
#endif /*KERNEL */
#if KXLD_USER_OR_OBJECT
    KXLDSeg *seg = NULL;
    KXLDSect *sect = NULL;
    KXLDSectionName *sname = NULL;
    u_int i = 0, j = 0, k = 0;
#endif /* KXLD_USER_OR_OBJECT */

    check(kext);

    require_action(kext->link_type == KXLD_LINK_KERNEL, finish,
        rval=KERN_FAILURE);

    rval = init_from_final_linked_image(kext, &filetype, &symtab_hdr);
    require_noerr(rval, finish);

    require_action(filetype == MH_EXECUTE, finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO 
            "The kernel file is not of type MH_EXECUTE."));

#if KERNEL
    /* When we're in the kernel, the symbol table can no longer be found by the
     * symtab_command alone because the command specifies offsets for the file
     * on disk, not the file mapped into memory.  We can find the additional
     * offset necessary by finding the difference between the linkedit segment's
     * vm address and the text segment's vm address.
     */

    textseg = kxld_kext_get_seg_by_name(kext, SEG_TEXT);
    require_action(textseg, finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO));

    linkeditseg = kxld_kext_get_seg_by_name(kext, SEG_LINKEDIT);
    require_action(linkeditseg, finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO));

    linkedit_offset = linkeditseg->base_addr - textseg->base_addr - 
        linkeditseg->fileoff;
#endif /* KERNEL */

    /* Initialize the symbol table */

    KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), rval,
        kxld_symtab_init_from_macho_32, kxld_symtab_init_from_macho_64,
        kext->symtab, kext->file, symtab_hdr, linkedit_offset);
    require_noerr(rval, finish);

#if KXLD_USER_OR_OBJECT
    /* Save off the order of section names so that we can lay out kext 
     * sections for MH_OBJECT-based systems.
     */
    if (target_supports_object(kext)) {

        rval = kxld_array_init(kext->section_order, sizeof(KXLDSectionName), 
            kext->sects.nitems);
        require_noerr(rval, finish);

        /* Copy the section names into the section_order array for future kext
         * section ordering.
         */
        for (i = 0, k = 0; i < kext->segs.nitems; ++i) {
            seg = kxld_array_get_item(&kext->segs, i);

            for (j = 0; j < seg->sects.nitems; ++j, ++k) {
                sect = *(KXLDSect **) kxld_array_get_item(&seg->sects, j);
                sname = kxld_array_get_item(kext->section_order, k);

                strlcpy(sname->segname, sect->segname, sizeof(sname->segname));
                strlcpy(sname->sectname, sect->sectname, sizeof(sname->sectname));
            }
        }
    }
#endif /* KXLD_USER_OR_OBJECT */

    rval = KERN_SUCCESS;
finish:
    return rval;
}

#if KXLD_USER_OR_BUNDLE
/*******************************************************************************
*******************************************************************************/
static boolean_t
target_supports_bundle(const KXLDKext *kext)
{
    return (kext->cputype == CPU_TYPE_X86_64);
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
init_from_bundle(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    struct symtab_command *symtab_hdr = NULL;
    u_int filetype = 0;
    u_int idx = 0;

    check(kext);

    require_action(target_supports_bundle(kext), finish,
        rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr,
            kKxldLogFiletypeNotSupported, MH_KEXT_BUNDLE));

    rval = init_from_final_linked_image(kext, &filetype, &symtab_hdr);
    require_noerr(rval, finish);

    require_action(filetype == MH_KEXT_BUNDLE, finish, 
        rval=KERN_FAILURE);

    KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), rval,
        kxld_symtab_init_from_macho_32, kxld_symtab_init_from_macho_64,
        kext->symtab, kext->file, symtab_hdr, /* linkedit offset */ 0);
    require_noerr(rval, finish);

    if (kext->segs.nitems) {
        /* Remove the __LINKEDIT segment, since we never keep the symbol
         * table around in memory for kexts.
         */
        seg = kxld_kext_get_seg_by_name(kext, SEG_LINKEDIT);
        if (seg) {
            rval = kxld_array_get_index(&kext->segs, seg, &idx);
            require_noerr(rval, finish);

            kxld_seg_deinit(seg);

            rval = kxld_array_remove(&kext->segs, idx);
            require_noerr(rval, finish);
        }

        kext->link_type = KXLD_LINK_KEXT;
    } else {
        kext->link_type = KXLD_LINK_PSEUDO_KEXT;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}
#endif /* KXLD_USER_OR_BUNDLE */

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static u_long
get_macho_cmd_data_32(u_char *file, u_long offset, u_int *filetype, u_int *ncmds)
{
    struct mach_header *mach_hdr = (struct mach_header *) (file + offset);

    if (filetype) *filetype = mach_hdr->filetype;
    if (ncmds) *ncmds = mach_hdr->ncmds;

    return sizeof(*mach_hdr);
}

#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
static u_long
get_macho_cmd_data_64(u_char *file, u_long offset, u_int *filetype,  u_int *ncmds)
{
    struct mach_header_64 *mach_hdr = (struct mach_header_64 *) (file + offset);

    if (filetype) *filetype = mach_hdr->filetype;
    if (ncmds) *ncmds = mach_hdr->ncmds;

    return sizeof(*mach_hdr);
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
create_vtables(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    KXLDSym *vtable_sym = NULL;
    KXLDSym *meta_vtable_sym = NULL;
    KXLDSect *vtable_sect = NULL;
    KXLDSect *meta_vtable_sect = NULL;
    KXLDVTable *vtable = NULL;
    KXLDVTable *meta_vtable = NULL;
    char class_name[KXLD_MAX_NAME_LEN];
    char vtable_name[KXLD_MAX_NAME_LEN];
    char meta_vtable_name[KXLD_MAX_NAME_LEN];
    char *demangled_name1 = NULL;
    char *demangled_name2 = NULL;
    size_t demangled_length1 = 0;
    size_t demangled_length2 = 0;
    u_int i = 0;
    u_int nvtables = 0;

    if (kext->link_type == KXLD_LINK_KERNEL) {
        /* Create a vtable object for every vtable symbol */
        kxld_symtab_iterator_init(&iter, kext->symtab, kxld_sym_is_vtable, FALSE);
        nvtables = kxld_symtab_iterator_get_num_remaining(&iter);
    } else {
        /* We walk over the super metaclass pointer symbols, because classes
         * with them are the only ones that need patching.  Then we double the
         * number of vtables we're expecting, because every pointer will have a
         * class vtable and a MetaClass vtable.
         */
        kxld_symtab_iterator_init(&iter, kext->symtab, 
            kxld_sym_is_super_metaclass_pointer, FALSE);
        nvtables = kxld_symtab_iterator_get_num_remaining(&iter) * 2;
    }

    /* Allocate the array of vtable objects.
     */
    rval = kxld_array_init(&kext->vtables, sizeof(KXLDVTable), nvtables);
    require_noerr(rval, finish);

    /* Initialize from each vtable symbol */
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {

        if (kext->link_type == KXLD_LINK_KERNEL) {
            vtable_sym = sym;
        } else {
            /* Get the class name from the smc pointer */
            rval = kxld_sym_get_class_name_from_super_metaclass_pointer(
                sym, class_name, sizeof(class_name));
            require_noerr(rval, finish);

            /* Get the vtable name from the class name */
            rval = kxld_sym_get_vtable_name_from_class_name(class_name,
                vtable_name, sizeof(vtable_name));
            require_noerr(rval, finish);

            /* Get the vtable symbol */
            vtable_sym = kxld_symtab_get_symbol_by_name(kext->symtab, vtable_name);
            require_action(vtable_sym, finish, rval=KERN_FAILURE;
                kxld_log(kKxldLogPatching, kKxldLogErr, kKxldLogMissingVtable,
                vtable_name, class_name));

            /* Get the meta vtable name from the class name */
            rval = kxld_sym_get_meta_vtable_name_from_class_name(class_name,
                meta_vtable_name, sizeof(meta_vtable_name));
            require_noerr(rval, finish);

            /* Get the meta vtable symbol */
            meta_vtable_sym = kxld_symtab_get_symbol_by_name(kext->symtab,
                meta_vtable_name);
            if (!meta_vtable_sym) {
                /* If we don't support strict patching and we can't find the vtable,
                 * log a warning and reduce the expected number of vtables by 1.
                 */
                if (target_supports_strict_patching(kext)) {
                    kxld_log(kKxldLogPatching, kKxldLogErr, kKxldLogMissingVtable, 
                        meta_vtable_name, class_name);
                    rval = KERN_FAILURE;
                    goto finish;
                } else {
                    kxld_log(kKxldLogPatching, kKxldLogErr, 
                        "Warning: " kKxldLogMissingVtable, 
                        kxld_demangle(meta_vtable_name, &demangled_name1, 
                            &demangled_length1), 
                        kxld_demangle(class_name, &demangled_name2, 
                            &demangled_length2));
                    kxld_array_resize(&kext->vtables, --nvtables);
                }
            }
        }

        /* Get the vtable's section */
        vtable_sect = kxld_array_get_item(&kext->sects, vtable_sym->sectnum);
        require_action(vtable_sect, finish, rval=KERN_FAILURE);

        vtable = kxld_array_get_item(&kext->vtables, i++);

        if (kext->link_type == KXLD_LINK_KERNEL) {
            /* Initialize the kernel vtable */
            rval = kxld_vtable_init_from_kernel_macho(vtable, vtable_sym, 
                vtable_sect, kext->symtab, &kext->relocator);
            require_noerr(rval, finish);
        } else {
            /* Initialize the class vtable */
            if (kext->is_final_image) {
                rval = kxld_vtable_init_from_final_macho(vtable, vtable_sym, 
                    vtable_sect, kext->symtab, &kext->relocator, &kext->extrelocs);
                require_noerr(rval, finish);
            } else {
                rval = kxld_vtable_init_from_object_macho(vtable, vtable_sym, 
                    vtable_sect, kext->symtab, &kext->relocator);
                require_noerr(rval, finish);
            }

            /* meta_vtable_sym will be null when we don't support strict patching
             * and can't find the metaclass vtable.
             */
            if (meta_vtable_sym) {
                /* Get the vtable's section */
                meta_vtable_sect = kxld_array_get_item(&kext->sects, 
                    meta_vtable_sym->sectnum);
                require_action(vtable_sect, finish, rval=KERN_FAILURE);
               
                meta_vtable = kxld_array_get_item(&kext->vtables, i++);
                
                /* Initialize the metaclass vtable */
                if (kext->is_final_image) {
                    rval = kxld_vtable_init_from_final_macho(meta_vtable, meta_vtable_sym, 
                        meta_vtable_sect, kext->symtab, &kext->relocator, &kext->extrelocs);
                    require_noerr(rval, finish);
                } else {
                    rval = kxld_vtable_init_from_object_macho(meta_vtable, meta_vtable_sym, 
                        meta_vtable_sect, kext->symtab, &kext->relocator);
                    require_noerr(rval, finish);
                }
            }
        }
    }
    require_action(i == kext->vtables.nitems, finish, 
        rval=KERN_FAILURE);

    /* Map vtable names to the vtable structures */
    rval = kxld_dict_init(&kext->vtable_index, kxld_dict_string_hash, 
        kxld_dict_string_cmp, kext->vtables.nitems);
    require_noerr(rval, finish);

    for (i = 0; i < kext->vtables.nitems; ++i) {
        vtable = kxld_array_get_item(&kext->vtables, i);
        rval = kxld_dict_insert(&kext->vtable_index, vtable->name, vtable);
        require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:

    if (demangled_name1) kxld_free(demangled_name1, demangled_length1);
    if (demangled_name2) kxld_free(demangled_name2, demangled_length2);

    return rval;
}

/*******************************************************************************
* Temporary workaround for PR-6668105 
* new, new[], delete, and delete[] may be overridden globally in a kext.
* We should do this with some sort of weak symbols, but we'll use a whitelist 
* for now to minimize risk.  
*******************************************************************************/
static void
restrict_private_symbols(KXLDKext *kext)
{
    const char *private_symbols[] = {
        KXLD_KMOD_INFO_SYMBOL,
        KXLD_OPERATOR_NEW_SYMBOL,
        KXLD_OPERATOR_NEW_ARRAY_SYMBOL,
        KXLD_OPERATOR_DELETE_SYMBOL,
        KXLD_OPERATOR_DELETE_ARRAY_SYMBOL
    };
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    const char *name = NULL;
    u_int i = 0;

    kxld_symtab_iterator_init(&iter, kext->symtab, kxld_sym_is_exported, FALSE);
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        for (i = 0; i < const_array_len(private_symbols); ++i) {
            name = private_symbols[i];
            if (!streq(sym->name, name)) {
                continue;
            }

            kxld_sym_mark_private(sym);
        }
    }
}

/*******************************************************************************
*******************************************************************************/
void
kxld_kext_clear(KXLDKext *kext)
{
    KXLDSeg *seg = NULL;
    KXLDSect *sect = NULL;
    KXLDVTable *vtable = NULL;
    u_int i;

    check(kext);

#if !KERNEL
    if (kext->link_type == KXLD_LINK_KERNEL) {
        unswap_macho(kext->file, kext->host_order, kext->target_order);
    }
#endif /* !KERNEL */

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        kxld_seg_clear(seg);
    }
    kxld_array_reset(&kext->segs);

    for (i = 0; i < kext->sects.nitems; ++i) {
        sect = kxld_array_get_item(&kext->sects, i);
        kxld_sect_clear(sect);
    }
    kxld_array_reset(&kext->sects);

    for (i = 0; i < kext->vtables.nitems; ++i) {
        vtable = kxld_array_get_item(&kext->vtables, i);
        kxld_vtable_clear(vtable);
    }
    kxld_array_reset(&kext->vtables);

    kxld_array_reset(&kext->extrelocs);
    kxld_array_reset(&kext->locrelocs);
    kxld_dict_clear(&kext->vtable_index);
    kxld_relocator_clear(&kext->relocator);
    kxld_uuid_clear(&kext->uuid);

    if (kext->symtab) kxld_symtab_clear(kext->symtab);

    kext->link_addr = 0;
    kext->kmod_link_addr = 0;
    kext->cputype = 0;
    kext->cpusubtype = 0;
    kext->link_type = KXLD_LINK_UNKNOWN;
    kext->is_final_image = FALSE;
    kext->got_is_created = FALSE;
}



/*******************************************************************************
*******************************************************************************/
void 
kxld_kext_deinit(KXLDKext *kext)
{
    KXLDSeg *seg = NULL;
    KXLDSect *sect = NULL;
    KXLDVTable *vtable = NULL;
    u_int i;

    check(kext);

#if !KERNEL
    if (kext->link_type == KXLD_LINK_KERNEL) {
        unswap_macho(kext->file, kext->host_order, kext->target_order);
    }
#endif /* !KERNEL */

    for (i = 0; i < kext->segs.maxitems; ++i) {
        seg = kxld_array_get_slot(&kext->segs, i);
        kxld_seg_deinit(seg);
    }
    kxld_array_deinit(&kext->segs);

    for (i = 0; i < kext->sects.maxitems; ++i) {
        sect = kxld_array_get_slot(&kext->sects, i);
        kxld_sect_deinit(sect);
    }
    kxld_array_deinit(&kext->sects);

    for (i = 0; i < kext->vtables.maxitems; ++i) {
        vtable = kxld_array_get_slot(&kext->vtables, i);
        kxld_vtable_deinit(vtable);
    }
    kxld_array_deinit(&kext->vtables);

    kxld_array_deinit(&kext->extrelocs);
    kxld_array_deinit(&kext->locrelocs);
    kxld_dict_deinit(&kext->vtable_index);

    if (kext->symtab) {
        kxld_symtab_deinit(kext->symtab);
        kxld_free(kext->symtab, kxld_symtab_sizeof());
    }

    bzero(kext, sizeof(*kext));
}

/*******************************************************************************
*******************************************************************************/
boolean_t
kxld_kext_is_true_kext(const KXLDKext *kext)
{
    return (kext->link_type == KXLD_LINK_KEXT);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_kext_get_vmsize(const KXLDKext *kext, u_long *header_size, u_long *vmsize)
{
    check(kext);
    check(header_size);
    check(vmsize);
    *header_size = 0;
    *vmsize = 0;

    /* vmsize is the padded header page(s) + segment vmsizes */

    *header_size = (kext->is_final_image) ?
        0 : round_page(get_macho_header_size(kext));
    *vmsize = *header_size + get_macho_data_size(kext);

}

/*******************************************************************************
*******************************************************************************/
const struct kxld_symtab * 
kxld_kext_get_symtab(const KXLDKext *kext)
{
    check(kext);

    return kext->symtab;
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_kext_get_num_symbols(const KXLDKext *kext)
{
    check(kext);

    return kxld_symtab_get_num_symbols(kext->symtab);
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_kext_get_vtables(KXLDKext *kext, const KXLDArray **vtables)
{
    check(kext);
    check(vtables);

    *vtables = &kext->vtables;
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_kext_get_num_vtables(const KXLDKext *kext)
{
    check(kext);

    return kext->vtables.nitems;
}

/*******************************************************************************
*******************************************************************************/
KXLDSeg *
kxld_kext_get_seg_by_name(const KXLDKext *kext, const char *segname)
{
    KXLDSeg *seg = NULL;
    u_int i = 0;

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);

        if (streq(segname, seg->segname)) break;

        seg = NULL;
    }

    return seg;
}

/*******************************************************************************
*******************************************************************************/
KXLDSect *
kxld_kext_get_sect_by_name(const KXLDKext *kext, const char *segname, 
    const char *sectname)
{
    KXLDSect *sect = NULL;
    u_int i = 0;

    for (i = 0; i < kext->sects.nitems; ++i) {
        sect = kxld_array_get_item(&kext->sects, i);

        if (streq(segname, sect->segname) && streq(sectname, sect->sectname)) {
            break;
        }

        sect = NULL;
    }

    return sect;
}

/*******************************************************************************
*******************************************************************************/
int
kxld_kext_get_sectnum_for_sect(const KXLDKext *kext, const KXLDSect *sect)
{
    kern_return_t rval = KERN_FAILURE;
    u_int idx = -1;

    rval = kxld_array_get_index(&kext->sects, sect, &idx);
    if (rval) idx = -1;

    return idx;
}

/*******************************************************************************
*******************************************************************************/
const KXLDArray * 
kxld_kext_get_section_order(const KXLDKext *kext __unused)
{
#if KXLD_USER_OR_OBJECT
    if (kext->link_type == KXLD_LINK_KERNEL && target_supports_object(kext)) {
        return kext->section_order;
    }
#endif /* KXLD_USER_OR_OBJECT */

    return NULL;
}

/*******************************************************************************
*******************************************************************************/
static u_long
get_macho_header_size(const KXLDKext *kext)
{
    KXLDSeg *seg = NULL;
    u_long header_size = 0;
    u_int i = 0;

    check(kext);

    /* Mach, segment, and UUID headers */

    if (kxld_kext_is_32_bit(kext)) {
        header_size += sizeof(struct mach_header);
    } else {
        header_size += sizeof(struct mach_header_64);
    }

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        header_size += kxld_seg_get_macho_header_size(seg, kxld_kext_is_32_bit(kext));
    }

    if (kext->uuid.has_uuid) {
        header_size += kxld_uuid_get_macho_header_size();
    }

    return header_size;
}

/*******************************************************************************
*******************************************************************************/
static u_long
get_macho_data_size(const KXLDKext *kext)
{
    KXLDSeg *seg = NULL;
    u_long data_size = 0;
    u_int i = 0;

    check(kext);

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        data_size += (u_long) kxld_seg_get_vmsize(seg);
    }

    return data_size;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t kxld_kext_export_linked_object(const KXLDKext *kext,
    u_char *linked_object, kxld_addr_t *kmod_info_kern)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    u_long size = 0;
    u_long header_size = 0;
    u_long header_offset = 0;
    u_long data_offset = 0;
    u_int ncmds = 0;
    u_int i = 0;

    check(kext);
    check(linked_object);
    check(kmod_info_kern);
    *kmod_info_kern = 0;

    /* Calculate the size of the headers and data */

    header_size = get_macho_header_size(kext);
    data_offset = (kext->is_final_image) ? header_size : round_page(header_size);
    size = data_offset + get_macho_data_size(kext);

    /* Copy data to the file */

    ncmds = kext->segs.nitems + (kext->uuid.has_uuid == TRUE);

    rval = export_macho_header(kext, linked_object, ncmds, 
        &header_offset, header_size);
    require_noerr(rval, finish);

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);

        rval = kxld_seg_export_macho_to_vm(seg, linked_object, &header_offset, 
            header_size, size, kext->link_addr, kxld_kext_is_32_bit(kext));
        require_noerr(rval, finish);
    }

    if (kext->uuid.has_uuid) {
        rval = kxld_uuid_export_macho(&kext->uuid, linked_object, 
            &header_offset, header_size);
        require_noerr(rval, finish);
    }

    *kmod_info_kern = kext->kmod_link_addr;

#if !KERNEL
    unswap_macho(linked_object, kext->host_order, kext->target_order);
#endif /* KERNEL */

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#if !KERNEL
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_kext_export_symbol_file(const KXLDKext *kext, 
    u_char **_symbol_file, u_long *_filesize)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    u_char *file = NULL;
    u_long size = 0;
    u_long header_size = 0;
    u_long header_offset = 0;
    u_long data_offset = 0;
    u_int ncmds = 0;
    u_int i = 0;

    check(kext);
    check(_symbol_file);
    *_symbol_file = NULL;

    /* Calculate the size of the file */

    if (kxld_kext_is_32_bit(kext)) {
        header_size += sizeof(struct mach_header);
    } else {
        header_size += sizeof(struct mach_header_64);
    }

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        header_size += kxld_seg_get_macho_header_size(seg, kxld_kext_is_32_bit(kext));
        size += kxld_seg_get_macho_data_size(seg);
    }

    header_size += kxld_symtab_get_macho_header_size();
    size += kxld_symtab_get_macho_data_size(kext->symtab, FALSE, 
        kxld_kext_is_32_bit(kext));

    if (kext->uuid.has_uuid) {
        header_size += kxld_uuid_get_macho_header_size();
    }

    data_offset = round_page(header_size);
    size += data_offset;

    /* Allocate the symbol file */

    file = kxld_page_alloc_untracked(size);
    require_action(file, finish, rval=KERN_RESOURCE_SHORTAGE);
    bzero(file, size);

    /* Copy data to the file */

    ncmds = kext->segs.nitems + (kext->uuid.has_uuid == TRUE) + 1; /* +1 for symtab */
    rval = export_macho_header(kext, file, ncmds, &header_offset, header_size);
    require_noerr(rval, finish);

    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        rval = kxld_seg_export_macho_to_file_buffer(seg, file, &header_offset, 
            header_size, &data_offset, size, kxld_kext_is_32_bit(kext));
        require_noerr(rval, finish);
    }

    rval = kxld_symtab_export_macho(kext->symtab, file, &header_offset,
        header_size, &data_offset, size, FALSE, kxld_kext_is_32_bit(kext));
    require_noerr(rval, finish);

    if (kext->uuid.has_uuid) {
        rval = kxld_uuid_export_macho(&kext->uuid, file, &header_offset, 
            header_size);
        require_noerr(rval, finish);
    }

    header_offset = header_size;

    /* Commit */

    unswap_macho(file, kext->host_order, kext->target_order);

    *_filesize = size;
    *_symbol_file = file;
    file = NULL;
    rval = KERN_SUCCESS;

finish:

    if (file) {
        kxld_page_free_untracked(file, size);
        file = NULL;
    }

    check(!file);
    check((!rval) ^ (!*_symbol_file));

    return rval;
}
#endif

/*******************************************************************************
*******************************************************************************/
boolean_t 
kxld_kext_target_needs_swap(const KXLDKext *kext __unused)
{
#if KERNEL
    return FALSE;
#else
    return (kext->target_order != kext->host_order);
#endif /* KERNEL */
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
export_macho_header(const KXLDKext *kext, u_char *buf, u_int ncmds,
    u_long *header_offset, u_long header_size)
{
    kern_return_t rval = KERN_FAILURE;

    check(kext);
    check(buf);
    check(header_offset);

    KXLD_3264_FUNC(kxld_kext_is_32_bit(kext), rval, 
        export_macho_header_32, export_macho_header_64, 
        kext, buf, ncmds, header_offset, header_size);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
export_macho_header_32(const KXLDKext *kext, u_char *buf, u_int ncmds,
    u_long *header_offset, u_long header_size)
{
    kern_return_t rval = KERN_FAILURE;
    struct mach_header *mach = NULL;

    check(kext);
    check(buf);
    check(header_offset);

    require_action(sizeof(*mach) <= header_size - *header_offset, finish,
        rval=KERN_FAILURE);
    mach = (struct mach_header *) (buf + *header_offset);

    mach->magic = MH_MAGIC;
    mach->cputype = kext->cputype;
    mach->filetype = kext->filetype;
    mach->ncmds = ncmds;
    mach->sizeofcmds = (uint32_t) (header_size - sizeof(*mach));
    mach->flags = MH_NOUNDEFS;

    *header_offset += sizeof(*mach);

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
static kern_return_t
export_macho_header_64(const KXLDKext *kext, u_char *buf, u_int ncmds,
    u_long *header_offset, u_long header_size)
{
    kern_return_t rval = KERN_FAILURE;
    struct mach_header_64 *mach = NULL;

    check(kext);
    check(buf);
    check(header_offset);
    
    require_action(sizeof(*mach) <= header_size - *header_offset, finish,
        rval=KERN_FAILURE);
    mach = (struct mach_header_64 *) (buf + *header_offset);
    
    mach->magic = MH_MAGIC_64;
    mach->cputype = kext->cputype;
    mach->cpusubtype = kext->cpusubtype;
    mach->filetype = kext->filetype;
    mach->ncmds = ncmds;
    mach->sizeofcmds = (uint32_t) (header_size - sizeof(*mach));
    mach->flags = MH_NOUNDEFS;

    *header_offset += sizeof(*mach);

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_kext_resolve(KXLDKext *kext, struct kxld_dict *patched_vtables,
    struct kxld_dict *defined_symbols)
{
    kern_return_t rval = KERN_FAILURE;

    require_action(kext->link_type == KXLD_LINK_PSEUDO_KEXT, finish,
        rval=KERN_FAILURE);

    /* Resolve symbols */
    rval = resolve_symbols(kext, defined_symbols, NULL);
    require_noerr(rval, finish);

    /* Validate symbols */
    rval = validate_symbols(kext);
    require_noerr(rval, finish);

    /* Pseudokexts re-export their dependencies' vtables */
    rval = copy_vtables(kext, patched_vtables);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_kext_relocate(KXLDKext *kext, kxld_addr_t link_address,
    KXLDDict *patched_vtables, KXLDDict *defined_symbols, 
    KXLDDict *obsolete_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    u_int i = 0;

    check(kext);
    check(patched_vtables);
    check(defined_symbols);

    require_action(kext->link_type == KXLD_LINK_KEXT, finish, rval=KERN_FAILURE);

    kext->link_addr = link_address;

    /* Relocate segments (which relocates the sections) */
    for (i = 0; i < kext->segs.nitems; ++i) {
        seg = kxld_array_get_item(&kext->segs, i);
        kxld_seg_relocate(seg, link_address);
    }

    /* Relocate symbols */
    rval = kxld_symtab_relocate(kext->symtab, &kext->sects);
    require_noerr(rval, finish);
 
    /* Populate kmod info structure */
    rval = populate_kmod_info(kext);
    require_noerr(rval, finish);
   
    /* Resolve symbols */
    rval = resolve_symbols(kext, defined_symbols, obsolete_symbols);
    require_noerr(rval, finish);
  
    /* Patch vtables */
    rval = patch_vtables(kext, patched_vtables, defined_symbols);
    require_noerr(rval, finish);
    
    /* Validate symbols */
    rval = validate_symbols(kext);
    require_noerr(rval, finish);

    /* Process relocation entries and populate the global offset table.
     *
     * For final linked images: the relocation entries are contained in a couple
     * of tables hanging off the end of the symbol table.  The GOT has its own
     * section created by the linker; we simply need to fill it.
     *
     * For object files: the relocation entries are bound to each section.
     * The GOT, if it exists for the target architecture, is created by kxld,
     * and we must populate it according to our internal structures.
     */
    if (kext->is_final_image) {
#if KXLD_USER_OR_BUNDLE
        rval = process_symbol_pointers(kext);
        require_noerr(rval, finish);

        rval = process_relocs_from_tables(kext);
        require_noerr(rval, finish);
#else
        require_action(FALSE, finish, rval=KERN_FAILURE);
#endif /* KXLD_USER_OR_BUNDLE */
    } else {
#if KXLD_USER_OR_GOT
        /* Populate GOT */
        rval = populate_got(kext);
        require_noerr(rval, finish);
#endif /* KXLD_USER_OR_GOT */
#if KXLD_USER_OR_OBJECT
        rval = process_relocs_from_sections(kext);
        require_noerr(rval, finish);
#else
        require_action(FALSE, finish, rval=KERN_FAILURE);
#endif /* KXLD_USER_OR_OBJECT */
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
resolve_symbols(KXLDKext *kext, KXLDDict *defined_symbols, 
    KXLDDict *obsolete_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    void *addrp = NULL;
    kxld_addr_t addr = 0;
    const char *name = NULL;
    boolean_t tests_for_weak = FALSE;
    boolean_t error = FALSE;
    boolean_t warning = FALSE;
    char *demangled_name = NULL;
    size_t demangled_length = 0;

    check(kext);
    check(defined_symbols);

    /* Check if the kext tests for weak symbols */
    sym = kxld_symtab_get_symbol_by_name(kext->symtab, KXLD_WEAK_TEST_SYMBOL);
    tests_for_weak = (sym != NULL);

    /* Check for duplicate symbols */
    kxld_symtab_iterator_init(&iter, kext->symtab, kxld_sym_is_exported, FALSE);
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        addrp = kxld_dict_find(defined_symbols, sym->name);
        if (addrp) { 
            /* Convert to a kxld_addr_t */
            if (kxld_kext_is_32_bit(kext)) {
                addr = (kxld_addr_t) (*(uint32_t*)addrp);
            } else {
                addr = (kxld_addr_t) (*(uint64_t*)addrp);
            }

            /* Not a problem if the symbols have the same address */
            if (addr == sym->link_addr) {
                continue;
            }

            if (!error) {
                error = TRUE;
                kxld_log(kKxldLogLinking, kKxldLogErr,
                    "The following symbols were defined more than once:");
            }

            kxld_log(kKxldLogLinking, kKxldLogErr, "\t%s: %p - %p", 
                kxld_demangle(sym->name, &demangled_name, &demangled_length),
                (void *) (uintptr_t) sym->link_addr, 
                (void *) (uintptr_t) addr);
        }
    }
    require_noerr_action(error, finish, rval=KERN_FAILURE);

    /* Resolve undefined and indirect symbols */

    /* Iterate over all unresolved symbols */
    kxld_symtab_iterator_init(&iter, kext->symtab, 
        kxld_sym_is_unresolved, FALSE);
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {

        /* Common symbols are not supported */
        if (kxld_sym_is_common(sym)) {

            if (!error) {
                error = TRUE;
                if (target_supports_common(kext)) {
                    kxld_log(kKxldLogLinking, kKxldLogErr, 
                        "The following common symbols were not resolved:");
                } else {
                    kxld_log(kKxldLogLinking, kKxldLogErr, 
                        "Common symbols are not supported in kernel extensions. " 
                         "Use -fno-common to build your kext. "
                         "The following are common symbols:");
                }
            }
            kxld_log(kKxldLogLinking, kKxldLogErr, "\t%s", 
                kxld_demangle(sym->name, &demangled_name, &demangled_length));

        } else {

            /* Find the address of the defined symbol */
            if (kxld_sym_is_undefined(sym)) {
                name = sym->name;
            } else {
                name = sym->alias;
            }
            addrp = kxld_dict_find(defined_symbols, name);
            
            /* Resolve the symbol.  If a definition cannot be found, then:
             * 1) Psuedokexts log a warning and proceed
             * 2) Actual kexts delay the error until validation in case vtable
             *    patching replaces the undefined symbol.
             */

            if (addrp) {

                /* Convert to a kxld_addr_t */
                if (kxld_kext_is_32_bit(kext)) {
                    addr = (kxld_addr_t) (*(uint32_t*)addrp);
                } else {
                    addr = (kxld_addr_t) (*(uint64_t*)addrp);
                }

                boolean_t is_exported = (kext->link_type == KXLD_LINK_PSEUDO_KEXT);

                rval = kxld_sym_resolve(sym, addr, is_exported);
                require_noerr(rval, finish);

                if (obsolete_symbols && kxld_dict_find(obsolete_symbols, name)) {
                    kxld_log(kKxldLogLinking, kKxldLogWarn, 
                        "This kext uses obsolete symbol %s.", 
                        kxld_demangle(name, &demangled_name, &demangled_length));
                }

            } else if (kext->link_type == KXLD_LINK_PSEUDO_KEXT) {
                /* Pseudokexts ignore undefined symbols, because any actual
                 * kexts that need those symbols will fail to link anyway, so
                 * there's no need to block well-behaved kexts.
                 */
                if (!warning) {
                    kxld_log(kKxldLogLinking, kKxldLogWarn, 
                        "This symbol set has the following unresolved symbols:");
                    warning = TRUE;
                }
                kxld_log(kKxldLogLinking, kKxldLogErr, "\t%s", 
                    kxld_demangle(sym->name, &demangled_name, &demangled_length));
                kxld_sym_delete(sym);

            } else if (kxld_sym_is_weak(sym)) {
                /* Make sure that the kext has referenced gOSKextUnresolved.
                 */
                require_action(tests_for_weak, finish, 
                   rval=KERN_FAILURE;
                   kxld_log(kKxldLogLinking, kKxldLogErr, 
                      "This kext has weak references but does not test for "
                      "them. Test for weak references with "
                      "OSKextIsSymbolResolved()."));

#if KERNEL
                /* Get the address of the default weak address.
                 */
                addr = (kxld_addr_t) &kext_weak_symbol_referenced;
#else  
                /* This is run during symbol generation only, so we only 
                 * need a filler value here.
                 */
                addr = kext->link_addr;
#endif /* KERNEL */

                rval = kxld_sym_resolve(sym, addr, /* exported */ FALSE);
                require_noerr(rval, finish);
            }
        }
    }
    require_noerr_action(error, finish, rval=KERN_FAILURE);

    rval = KERN_SUCCESS;

finish:
    if (demangled_name) kxld_free(demangled_name, demangled_length);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t
target_supports_strict_patching(KXLDKext *kext)
{
    check(kext);

    return (kext->cputype != CPU_TYPE_I386 && 
            kext->cputype != CPU_TYPE_POWERPC);
}

/*******************************************************************************
* We must patch vtables to ensure binary compatibility, and to perform that
* patching, we have to determine the vtables' inheritance relationships.  The
* MetaClass system gives us a way to do that:
*   1) Iterate over all of the super MetaClass pointer symbols.  Every class
*      that inherits from OSObject will have a pointer in its MetaClass that
*      points to the MetaClass's super MetaClass.
*   2) Derive the name of the class from the super MetaClass pointer.
*   3) Derive the name of the class's vtable from the name of the class
*   4) Follow the super MetaClass pointer to get the address of the super
*      MetaClass's symbol
*   5) Look up the super MetaClass symbol by address
*   6) Derive the super class's name from the super MetaClass name
*   7) Derive the super class's vtable from the super class's name
* This procedure will allow us to find all of the OSObject-derived classes and
* their super classes, and thus patch all of the vtables.
*
* We also have to take care to patch up the MetaClass's vtables.  The
* MetaClasses follow a parallel hierarchy to the classes, so once we have the
* class name and super class name, we can also derive the MetaClass name and
* the super MetaClass name, and thus find and patch their vtables as well.
*******************************************************************************/

#define kOSMetaClassVTableName "__ZTV11OSMetaClass"

static kern_return_t
patch_vtables(KXLDKext *kext, KXLDDict *patched_vtables, 
    KXLDDict *defined_symbols)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *metaclass = NULL;
    KXLDSym *super_metaclass_pointer = NULL;
    KXLDSym *final_sym = NULL;
    KXLDVTable *vtable = NULL;
    KXLDVTable *super_vtable = NULL;
    char class_name[KXLD_MAX_NAME_LEN];
    char super_class_name[KXLD_MAX_NAME_LEN];
    char vtable_name[KXLD_MAX_NAME_LEN];
    char super_vtable_name[KXLD_MAX_NAME_LEN];
    char final_sym_name[KXLD_MAX_NAME_LEN];
    char *demangled_name1 = NULL;
    char *demangled_name2 = NULL;
    size_t demangled_length1 = 0;;
    size_t demangled_length2 = 0;
    size_t len = 0;
    u_int nvtables = 0;
    u_int npatched = 0;
    u_int nprogress = 0;
    boolean_t failure = FALSE;

    check(kext);
    check(patched_vtables);

    /* Find each super meta class pointer symbol */

    kxld_symtab_iterator_init(&iter, kext->symtab, 
        kxld_sym_is_super_metaclass_pointer, FALSE);
    nvtables = kxld_symtab_iterator_get_num_remaining(&iter);

    while (npatched < nvtables) {
        npatched = 0;
        nprogress = 0;
        kxld_symtab_iterator_reset(&iter);
        while((super_metaclass_pointer = kxld_symtab_iterator_get_next(&iter))) 
        {
            /* Get the class name from the smc pointer */
            rval = kxld_sym_get_class_name_from_super_metaclass_pointer(
                super_metaclass_pointer, class_name, sizeof(class_name));
            require_noerr(rval, finish);

            /* Get the vtable name from the class name */
            rval = kxld_sym_get_vtable_name_from_class_name(class_name,
                vtable_name, sizeof(vtable_name));
            require_noerr(rval, finish);

            /* Get the vtable and make sure it hasn't been patched */
            vtable = kxld_dict_find(&kext->vtable_index, vtable_name);
            require_action(vtable, finish, rval=KERN_FAILURE;
                kxld_log(kKxldLogPatching, kKxldLogErr, kKxldLogMissingVtable,
                    vtable_name, class_name));

            if (!vtable->is_patched) {

                /* Find the SMCP's meta class symbol */
                rval = get_metaclass_symbol_from_super_meta_class_pointer_symbol(
                    kext, super_metaclass_pointer, &metaclass);
                require_noerr(rval, finish);

                /* Get the super class name from the super metaclass */
                rval = kxld_sym_get_class_name_from_metaclass(metaclass,
                    super_class_name, sizeof(super_class_name));
                require_noerr(rval, finish);

                /* Get the super vtable name from the class name */
                rval = kxld_sym_get_vtable_name_from_class_name(super_class_name,
                    super_vtable_name, sizeof(super_vtable_name));
                require_noerr(rval, finish);

                if (failure) {
                    kxld_log(kKxldLogPatching, kKxldLogErr, 
                        "\t'%s' (super vtable '%s')", 
                        kxld_demangle(vtable_name, &demangled_name1, 
                            &demangled_length1), 
                        kxld_demangle(super_vtable_name, &demangled_name2, 
                            &demangled_length2));
                    continue;
                }

                /* Get the super vtable if it's been patched */
                super_vtable = kxld_dict_find(patched_vtables, super_vtable_name);
                if (!super_vtable) continue;

                /* Get the final symbol's name from the super vtable */
                rval = kxld_sym_get_final_sym_name_from_class_name(super_class_name, 
                    final_sym_name, sizeof(final_sym_name));
                require_noerr(rval, finish);

                /* Verify that the final symbol does not exist.  First check
                 * all the externally defined symbols, then check locally.
                 */
                final_sym = kxld_dict_find(defined_symbols, final_sym_name);
                if (!final_sym) {
                    final_sym = kxld_symtab_get_symbol_by_name(kext->symtab, 
                        final_sym_name);
                }
                require_action(!final_sym, finish, 
                    rval=KERN_FAILURE;
                    kxld_log(kKxldLogPatching, kKxldLogErr, 
                        "Class '%s' is a subclass of final class '%s'.",
                        kxld_demangle(class_name, &demangled_name1, 
                            &demangled_length1), 
                        kxld_demangle(super_class_name, &demangled_name2, 
                            &demangled_length2)));

                /* Patch the class's vtable */
                rval = kxld_vtable_patch(vtable, super_vtable, kext->symtab,
                    target_supports_strict_patching(kext));
                require_noerr(rval, finish);

                /* Add the class's vtable to the set of patched vtables */
                rval = kxld_dict_insert(patched_vtables, vtable->name, vtable);
                require_noerr(rval, finish);

                /* Get the meta vtable name from the class name */
                rval = kxld_sym_get_meta_vtable_name_from_class_name(class_name,
                    vtable_name, sizeof(vtable_name));
                require_noerr(rval, finish);

                /* Get the meta vtable.  Whether or not it should exist has already
                 * been tested in create_vtables(), so if it doesn't exist and we're
                 * still running, we can safely skip it.
                 */
                vtable = kxld_dict_find(&kext->vtable_index, vtable_name);
                if (!vtable) {
                    ++nprogress;
                    ++npatched;
                    continue;
                }
                require_action(!vtable->is_patched, finish, rval=KERN_FAILURE);

                /* There is no way to look up a metaclass vtable at runtime, but
                 * we know that every class's metaclass inherits directly from 
                 * OSMetaClass, so we just hardcode that vtable name here.
                 */
                len = strlcpy(super_vtable_name, kOSMetaClassVTableName,
                    sizeof(super_vtable_name));
                require_action(len == const_strlen(kOSMetaClassVTableName),
                    finish, rval=KERN_FAILURE);
                       
                /* Get the super meta vtable */
                super_vtable = kxld_dict_find(patched_vtables, super_vtable_name);
                require_action(super_vtable && super_vtable->is_patched, 
                    finish, rval=KERN_FAILURE);

                /* Patch the meta class's vtable */
                rval = kxld_vtable_patch(vtable, super_vtable,
                    kext->symtab, target_supports_strict_patching(kext));
                require_noerr(rval, finish);

                /* Add the MetaClass's vtable to the set of patched vtables */
                rval = kxld_dict_insert(patched_vtables, vtable->name, vtable);
                require_noerr(rval, finish);
                
                ++nprogress;
            }

            ++npatched;
        }

        require_action(!failure, finish, rval=KERN_FAILURE);
        if (!nprogress) {
            failure = TRUE;
            kxld_log(kKxldLogPatching, kKxldLogErr, 
                "The following vtables were unpatchable because each one's " 
                "parent vtable either was not found or also was not patchable:");
        }
    }

    rval = KERN_SUCCESS;
finish:
    if (demangled_name1) kxld_free(demangled_name1, demangled_length1);
    if (demangled_name2) kxld_free(demangled_name2, demangled_length2);

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
validate_symbols(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    u_int error = FALSE;
    char *demangled_name = NULL;
    size_t demangled_length = 0;
    
    /* Check for any unresolved symbols */
    kxld_symtab_iterator_init(&iter, kext->symtab, kxld_sym_is_unresolved, FALSE);
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        if (!error) {
            error = TRUE;
            kxld_log(kKxldLogLinking, kKxldLogErr, 
                "The following symbols are unresolved for this kext:");
        }
        kxld_log(kKxldLogLinking, kKxldLogErr, "\t%s", 
            kxld_demangle(sym->name, &demangled_name, &demangled_length));
    }
    require_noerr_action(error, finish, rval=KERN_FAILURE);

    rval = KERN_SUCCESS;

finish:
    if (demangled_name) kxld_free(demangled_name, demangled_length);
    return rval;
}

#if KXLD_USER_OR_GOT || KXLD_USER_OR_COMMON
/*******************************************************************************
*******************************************************************************/
static kern_return_t
add_section(KXLDKext *kext, KXLDSect **sect)
{
    kern_return_t rval = KERN_FAILURE;
    u_int nsects = kext->sects.nitems;

    rval = kxld_array_resize(&kext->sects, nsects + 1);
    require_noerr(rval, finish);

    *sect = kxld_array_get_item(&kext->sects, nsects);

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_GOT || KXLD_USER_OR_COMMON */

#if KXLD_USER_OR_GOT
/*******************************************************************************
*******************************************************************************/
static boolean_t
target_has_got(const KXLDKext *kext)
{
    return FALSE:
}

/*******************************************************************************
* Create and initialize the Global Offset Table
*******************************************************************************/
static kern_return_t
create_got(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    u_int ngots = 0;
    u_int i = 0;

    if (!target_has_got(kext)) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    for (i = 0; i < kext->sects.nitems; ++i) {
        sect = kxld_array_get_item(&kext->sects, i);
        ngots += kxld_sect_get_ngots(sect, &kext->relocator, 
            kext->symtab);
    }

    rval = add_section(kext, &sect);
    require_noerr(rval, finish);

    rval = kxld_sect_init_got(sect, ngots);
    require_noerr(rval, finish);

    kext->got_is_created = TRUE;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
populate_got(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    u_int i = 0;

    if (!target_has_got(kext) || !kext->got_is_created) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    for (i = 0; i < kext->sects.nitems; ++i) {
        sect = kxld_array_get_item(&kext->sects, i);
        if (streq_safe(sect->segname, KXLD_SEG_GOT, sizeof(KXLD_SEG_GOT)) &&
            streq_safe(sect->sectname, KXLD_SECT_GOT, sizeof(KXLD_SECT_GOT)))
        {
            kxld_sect_populate_got(sect, kext->symtab,
                kxld_kext_target_needs_swap(kext));
            break;
        }
    }

    require_action(i < kext->sects.nitems, finish, rval=KXLD_MISSING_GOT);

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_GOT */

/*******************************************************************************
*******************************************************************************/
static boolean_t
target_supports_common(const KXLDKext *kext)
{
    check(kext);
    return (kext->cputype == CPU_TYPE_I386 || 
            kext->cputype == CPU_TYPE_POWERPC);
}

#if KXLD_USER_OR_COMMON
/*******************************************************************************
* If there are common symbols, calculate how much space they'll need
* and create/grow the __DATA __common section to accommodate them.
* Then, resolve them against that section.
*******************************************************************************/
static kern_return_t
resolve_common_symbols(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    KXLDSect *sect = NULL;
    kxld_addr_t base_addr = 0;
    kxld_size_t size = 0;
    kxld_size_t total_size = 0;
    u_int align = 0;
    u_int max_align = 0;
    u_int sectnum = 0;

    if (!target_supports_common(kext)) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    /* Iterate over the common symbols to calculate their total aligned size */
    kxld_symtab_iterator_init(&iter, kext->symtab, kxld_sym_is_common, FALSE);
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        align = kxld_sym_get_common_align(sym);
        size = kxld_sym_get_common_size(sym);

        if (align > max_align) max_align = align;

        total_size = kxld_align_address(total_size, align) + size;
    }

    /* If there are common symbols, grow or create the __DATA __common section
     * to hold them.
     */
    if (total_size) {
        sect = kxld_kext_get_sect_by_name(kext, SEG_DATA, SECT_COMMON);
        if (sect) {
            base_addr = sect->base_addr + sect->size;

            kxld_sect_grow(sect, total_size, max_align);
        } else {
            base_addr = 0;

            rval = add_section(kext, &sect);
            require_noerr(rval, finish);

            kxld_sect_init_zerofill(sect, SEG_DATA, SECT_COMMON, 
                total_size, max_align);
        }

        /* Resolve the common symbols against the new section */
        rval = kxld_array_get_index(&kext->sects, sect, &sectnum);
        require_noerr(rval, finish);

        kxld_symtab_iterator_reset(&iter);
        while ((sym = kxld_symtab_iterator_get_next(&iter))) {
            align = kxld_sym_get_common_align(sym);
            size = kxld_sym_get_common_size(sym);

            base_addr = kxld_align_address(base_addr, align);
            kxld_sym_resolve_common(sym, sectnum, base_addr);

            base_addr += size;
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_COMMON */

/*******************************************************************************
*******************************************************************************/
static kern_return_t
get_metaclass_symbol_from_super_meta_class_pointer_symbol(KXLDKext *kext,
    KXLDSym *super_metaclass_pointer_sym, KXLDSym **metaclass)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    KXLDReloc *reloc = NULL;
    uint32_t offset = 0;
    
    check(kext);
    check(super_metaclass_pointer_sym);
    check(metaclass);
    *metaclass = NULL;

    sect = kxld_array_get_item(&kext->sects, super_metaclass_pointer_sym->sectnum);
    require_action(sect, finish, rval=KERN_FAILURE);

    /* Find the relocation entry for the super metaclass pointer and get the 
     * symbol associated with that relocation entry 
     */

    if (kext->is_final_image) {
        /* The relocation entry could be in either the external or local
         * relocation entries.  kxld_reloc_get_symbol() can handle either
         * type.
         */
        reloc = kxld_reloc_get_reloc_by_offset(&kext->extrelocs, 
            super_metaclass_pointer_sym->base_addr);
        if (!reloc) {
            reloc = kxld_reloc_get_reloc_by_offset(&kext->locrelocs,
                super_metaclass_pointer_sym->base_addr);
        }
        require_action(reloc, finish, rval=KERN_FAILURE);

        *metaclass = kxld_reloc_get_symbol(&kext->relocator, reloc, kext->file,
            kext->symtab);
    } else {
        offset = kxld_sym_get_section_offset(super_metaclass_pointer_sym, sect);

        reloc = kxld_reloc_get_reloc_by_offset(&sect->relocs, offset);
        require_action(reloc, finish, rval=KERN_FAILURE);

        *metaclass = kxld_reloc_get_symbol(&kext->relocator, reloc, sect->data,
            kext->symtab);
    }
    require_action(*metaclass, finish, rval=KERN_FAILURE);

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
copy_vtables(KXLDKext *kext, const KXLDDict *patched_vtables)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSymtabIterator iter;
    KXLDSym *sym = NULL;
    KXLDVTable *vtable = NULL, *src = NULL;
    u_int i = 0;
    u_int nvtables = 0;
    char class_name[KXLD_MAX_NAME_LEN];
    char meta_vtable_name[KXLD_MAX_NAME_LEN];

    kxld_symtab_iterator_init(&iter, kext->symtab, 
        kxld_sym_is_class_vtable, FALSE);
    
    /* The iterator tracks all the class vtables, so we double the number of
     * vtables we're expecting because we use the class vtables to find the
     * MetaClass vtables.
     */
    nvtables = kxld_symtab_iterator_get_num_remaining(&iter) * 2;
    rval = kxld_array_init(&kext->vtables, sizeof(KXLDVTable), nvtables);
    require_noerr(rval, finish);
    
    while ((sym = kxld_symtab_iterator_get_next(&iter))) {
        src = kxld_dict_find(patched_vtables, sym->name);
        require_action(src, finish, rval=KERN_FAILURE);

        vtable = kxld_array_get_item(&kext->vtables, i++);
        rval = kxld_vtable_copy(vtable, src);
        require_noerr(rval, finish);

        rval = kxld_sym_get_class_name_from_vtable(sym, 
            class_name, sizeof(class_name));
        require_noerr(rval, finish);

        rval = kxld_sym_get_meta_vtable_name_from_class_name(class_name,
            meta_vtable_name, sizeof(meta_vtable_name));
        require_noerr(rval, finish);

        /* Some classes don't have a MetaClass, so when we run across one
         * of those, we shrink the vtable array by 1.
         */
        src = kxld_dict_find(patched_vtables, meta_vtable_name);
        if (src) {
            vtable = kxld_array_get_item(&kext->vtables, i++);
            rval = kxld_vtable_copy(vtable, src);
            require_noerr(rval, finish);
        } else {
            kxld_array_resize(&kext->vtables, kext->vtables.nitems - 1);
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#if KXLD_USER_OR_OBJECT
/*******************************************************************************
*******************************************************************************/
static kern_return_t
process_relocs_from_sections(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    u_int i = 0;

    for (i = 0; i < kext->sects.nitems; ++i) {
        sect = kxld_array_get_item(&kext->sects, i);
        rval = kxld_sect_process_relocs(sect, &kext->relocator,
            &kext->sects, kext->symtab);
        require_noerr_action(rval, finish,
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogInvalidSectReloc,
                i, sect->segname, sect->sectname));
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_OBJECT */

#if KXLD_USER_OR_BUNDLE
/*******************************************************************************
*******************************************************************************/
static kern_return_t
process_relocs_from_tables(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    KXLDSeg *seg = NULL;
    u_int i = 0;

    /* Offsets for relocations in relocation tables are based on the vm
     * address of the first segment.
     */
    seg = kxld_array_get_item(&kext->segs, 0);

    /* Process external relocations */
    for (i = 0; i < kext->extrelocs.nitems; ++i) {
        reloc = kxld_array_get_item(&kext->extrelocs, i);

        rval = kxld_relocator_process_table_reloc(&kext->relocator, reloc, seg, 
            kext->file, &kext->sects, kext->symtab);
        require_noerr_action(rval, finish,
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogInvalidExtReloc, i));
    }

    /* Process local relocations */
    for (i = 0; i < kext->locrelocs.nitems; ++i) {
        reloc = kxld_array_get_item(&kext->locrelocs, i);

        rval = kxld_relocator_process_table_reloc(&kext->relocator, reloc, seg, 
            kext->file, &kext->sects, kext->symtab);
        require_noerr_action(rval, finish,
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogInvalidIntReloc, i));
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static void
add_to_ptr(u_char *symptr, kxld_addr_t val, boolean_t is_32_bit)
{
    if (is_32_bit) {
        uint32_t *ptr = (uint32_t *) symptr;
        *ptr += (uint32_t) val;
    } else {
        uint64_t *ptr = (uint64_t *) symptr;
        *ptr += (uint64_t) val;
    }
}

#define SECT_SYM_PTRS "__nl_symbol_ptr"

/*******************************************************************************
* Final linked images create an __nl_symbol_ptr section for the global offset
* table and for symbol pointer lookups in general.  Rather than use relocation
* entries, the linker creates an "indirect symbol table" which stores indexes
* into the symbol table corresponding to the entries of this section.  This
* function populates the section with the relocated addresses of those symbols.
*******************************************************************************/
static kern_return_t
process_symbol_pointers(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    KXLDSym *sym = NULL;
    int32_t *symidx = NULL;
    u_char *symptr = NULL;
    u_long symptrsize = 0;
    u_int nsyms = 0;
    u_int firstsym = 0;
    u_int i = 0;

    check(kext);

    require_action(kext->is_final_image && kext->dysymtab_hdr, 
        finish, rval=KERN_FAILURE);

    /* Get the __DATA,__nl_symbol_ptr section.  If it doesn't exist, we have
     * nothing to do.
     */

    sect = kxld_kext_get_sect_by_name(kext, SEG_DATA, SECT_SYM_PTRS);
    if (!sect) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    require_action(sect->flags & S_NON_LAZY_SYMBOL_POINTERS,
        finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO 
            "Section %s,%s does not have S_NON_LAZY_SYMBOL_POINTERS flag.",
            SEG_DATA, SECT_SYM_PTRS));

    /* Calculate the table offset and number of entries in the section */

    if (kxld_kext_is_32_bit(kext)) {
        symptrsize = sizeof(uint32_t);
    } else {
        symptrsize = sizeof(uint64_t);
    }

    nsyms = (u_int) (sect->size / symptrsize);
    firstsym = sect->reserved1;

    require_action(firstsym + nsyms <= kext->dysymtab_hdr->nindirectsyms,
        finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO));

    /* Iterate through the indirect symbol table and fill in the section of
     * symbol pointers.  There are three cases:
     *   1) A normal symbol - put its value directly in the table
     *   2) An INDIRECT_SYMBOL_LOCAL - symbols that are local and already have
     *      their offset from the start of the file in the section.  Simply
     *      add the file's link address to fill this entry.
     *   3) An INDIRECT_SYMBOL_ABS - prepopulated absolute symbols.  No
     *      action is required.
     */

    symidx = (int32_t *) (kext->file + kext->dysymtab_hdr->indirectsymoff);
    symidx += firstsym;
    symptr = sect->data;
    for (i = 0; i < nsyms; ++i, ++symidx, symptr+=symptrsize) {
        if (*symidx & INDIRECT_SYMBOL_LOCAL) {
            if (*symidx & INDIRECT_SYMBOL_ABS) continue;

            add_to_ptr(symptr, kext->link_addr, kxld_kext_is_32_bit(kext));
        } else {
            sym = kxld_symtab_get_symbol_by_index(kext->symtab, *symidx);
            require_action(sym, finish, rval=KERN_FAILURE);

            add_to_ptr(symptr, sym->link_addr, kxld_kext_is_32_bit(kext));
        }
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}
#endif /* KXLD_USER_OR_BUNDLE */

/*******************************************************************************
*******************************************************************************/
static kern_return_t
populate_kmod_info(KXLDKext *kext)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *kmodsect = NULL;
    KXLDSym *kmodsym = NULL;
    u_long kmod_offset = 0;
    u_long header_size;
    u_long size;

    if (kext->link_type != KXLD_LINK_KEXT) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    kxld_kext_get_vmsize(kext, &header_size, &size);

    kmodsym = kxld_symtab_get_symbol_by_name(kext->symtab, KXLD_KMOD_INFO_SYMBOL);
    require_action(kmodsym, finish, rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogNoKmodInfo));
 
    kmodsect = kxld_array_get_item(&kext->sects, kmodsym->sectnum);
    kmod_offset = (u_long) (kmodsym->base_addr -  kmodsect->base_addr);

    kext->kmod_info = (kmod_info_t *) (kmodsect->data + kmod_offset);
    kext->kmod_link_addr = kmodsym->link_addr;

    if (kxld_kext_is_32_bit(kext)) {
        kmod_info_32_v1_t *kmod = (kmod_info_32_v1_t *) (kext->kmod_info);
        kmod->address = (uint32_t) kext->link_addr;
        kmod->size = (uint32_t) size;
        kmod->hdr_size = (uint32_t) header_size;

#if !KERNEL
        if (kxld_kext_target_needs_swap(kext)) {
            kmod->address = OSSwapInt32(kmod->address);
            kmod->size = OSSwapInt32(kmod->size);
            kmod->hdr_size = OSSwapInt32(kmod->hdr_size);
        }
#endif /* !KERNEL */
    } else {
        kmod_info_64_v1_t *kmod = (kmod_info_64_v1_t *) (kext->kmod_info);
        kmod->address = kext->link_addr;
        kmod->size = size;
        kmod->hdr_size = header_size;

#if !KERNEL
        if (kxld_kext_target_needs_swap(kext)) {
            kmod->address = OSSwapInt64(kmod->address);
            kmod->size = OSSwapInt64(kmod->size);
            kmod->hdr_size = OSSwapInt64(kmod->hdr_size);
        }
#endif /* !KERNEL */
    }


    rval = KERN_SUCCESS;

finish:
    return rval;
}

