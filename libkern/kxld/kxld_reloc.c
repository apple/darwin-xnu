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
#include <mach/boolean.h>
#include <sys/types.h>

#if KERNEL
    #include <libkern/libkern.h>
    #include <mach/machine.h>
#else
    #include <stdlib.h>
    #include <libkern/OSByteOrder.h>

    /* Get machine.h from the kernel source so we can support all platforms
     * that the kernel supports. Otherwise we're at the mercy of the host.
     */
    #include "../../osfmk/mach/machine.h"
#endif

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_array.h"
#include "kxld_demangle.h"
#include "kxld_dict.h"
#include "kxld_reloc.h"
#include "kxld_sect.h"
#include "kxld_seg.h"
#include "kxld_sym.h"
#include "kxld_symtab.h"
#include "kxld_util.h"
#include "kxld_vtable.h"

#if KXLD_PIC_KEXTS
/* This will try to pull in mach/machine.h, so it has to come after the
 * explicit include above.
 */
#include <mach-o/loader.h>
#endif

/* include target-specific relocation prototypes */
#include <mach-o/reloc.h>
#if KXLD_USER_OR_X86_64
#include <mach-o/x86_64/reloc.h>
#endif
#if KXLD_USER_OR_ARM
#include <mach-o/arm/reloc.h>
#endif

#define KXLD_TARGET_NONE        (u_int) 0x0
#define KXLD_TARGET_VALUE       (u_int) 0x1
#define KXLD_TARGET_SECTNUM     (u_int) 0x2
#define KXLD_TARGET_SYMBOLNUM   (u_int) 0x3
#define KXLD_TARGET_LOOKUP      (u_int) 0x4
#define KXLD_TARGET_GOT         (u_int) 0x5

#define ABSOLUTE_VALUE(x) (((x) < 0) ? -(x) : (x))

#define LO16(x) (0x0000FFFF & x)
#define LO16S(x) ((0x0000FFFF & x) << 16)
#define HI16(x) (0xFFFF0000 & x)
#define HI16S(x) ((0xFFFF0000 & x) >> 16)
#define BIT15(x) (0x00008000 & x)
#define BR14I(x) (0xFFFF0003 & x)
#define BR14D(x) (0x0000FFFC & x)
#define BR24I(x) (0xFC000003 & x)
#define BR24D(x) (0x03FFFFFC & x)
#define HADISP 0x00010000
#define BR14_LIMIT 0x00008000
#define BR24_LIMIT 0x02000000
#define IS_COND_BR_INSTR(x) ((x & 0xFC000000) == 0x40000000)
#define IS_NOT_ALWAYS_TAKEN(x) ((x & 0x03E00000) != 0x02800000)
#define FLIP_PREDICT_BIT(x) x ^= 0x00200000

#define SIGN_EXTEND_MASK(n) (1 << ((n) - 1))
#define SIGN_EXTEND(x,n) (((x) ^ SIGN_EXTEND_MASK(n)) - SIGN_EXTEND_MASK(n))
#define BR14_NBITS_DISPLACEMENT 16
#define BR24_NBITS_DISPLACEMENT 26

#define X86_64_RIP_RELATIVE_LIMIT 0x80000000UL

/*******************************************************************************
* Prototypes
*******************************************************************************/
#if KXLD_USER_OR_I386
static boolean_t generic_reloc_has_pair(u_int _type) 
    __attribute__((const));
static u_int generic_reloc_get_pair_type(u_int _prev_type)
    __attribute__((const));
static boolean_t generic_reloc_has_got(u_int _type)
    __attribute__((const));
static kern_return_t generic_process_reloc(const KXLDRelocator *relocator,
    u_char *instruction, u_int length, u_int pcrel, kxld_addr_t base_pc, 
    kxld_addr_t link_pc, kxld_addr_t link_disp, u_int type, kxld_addr_t target, 
    kxld_addr_t pair_target, boolean_t swap);
#endif /* KXLD_USER_OR_I386 */

#if KXLD_USER_OR_X86_64 
static boolean_t x86_64_reloc_has_pair(u_int _type) 
    __attribute__((const));
static u_int x86_64_reloc_get_pair_type(u_int _prev_type) 
    __attribute__((const));
static boolean_t x86_64_reloc_has_got(u_int _type)
    __attribute__((const));
static kern_return_t x86_64_process_reloc(const KXLDRelocator *relocator, 
    u_char *instruction, u_int length, u_int pcrel, kxld_addr_t base_pc, 
    kxld_addr_t link_pc, kxld_addr_t link_disp, u_int type, kxld_addr_t target, 
    kxld_addr_t pair_target, boolean_t swap);
static kern_return_t calculate_displacement_x86_64(uint64_t target, 
    uint64_t adjustment, int32_t *instr32);
#endif /* KXLD_USER_OR_X86_64 */

#if KXLD_USER_OR_ARM
static boolean_t arm_reloc_has_pair(u_int _type) 
    __attribute__((const));
static u_int arm_reloc_get_pair_type(u_int _prev_type) 
    __attribute__((const));
static boolean_t arm_reloc_has_got(u_int _type)
    __attribute__((const));
static kern_return_t arm_process_reloc(const KXLDRelocator *relocator, 
    u_char *instruction, u_int length, u_int pcrel, kxld_addr_t base_pc, 
    kxld_addr_t link_pc, kxld_addr_t link_disp, u_int type, kxld_addr_t target, 
    kxld_addr_t pair_target, boolean_t swap);
#endif /* KXLD_USER_OR_ARM */

#if KXLD_USER_OR_ILP32
static kxld_addr_t get_pointer_at_addr_32(const KXLDRelocator *relocator, 
    const u_char *data, u_long offset)
    __attribute__((pure, nonnull));
#endif /* KXLD_USER_OR_ILP32 */
#if KXLD_USER_OR_LP64
static kxld_addr_t get_pointer_at_addr_64(const KXLDRelocator *relocator, 
    const u_char *data, u_long offset)
    __attribute__((pure, nonnull));
#endif /* KXLD_USER_OR_LP64 */

static u_int count_relocatable_relocs(const KXLDRelocator *relocator, 
    const struct relocation_info *relocs, u_int nrelocs)
    __attribute__((pure));

static kern_return_t calculate_targets(KXLDRelocator *relocator, 
    kxld_addr_t *_target, kxld_addr_t *_pair_target, const KXLDReloc *reloc);

static kxld_addr_t align_raw_function_address(const KXLDRelocator *relocator, 
    kxld_addr_t value);

static kern_return_t get_target_by_address_lookup(kxld_addr_t *target, 
    kxld_addr_t addr, const KXLDArray *sectarray);

static kern_return_t check_for_direct_pure_virtual_call(
    const KXLDRelocator *relocator, u_long offset);

#if KXLD_PIC_KEXTS
static u_long get_macho_data_size_for_array(const KXLDArray *relocs);

static kern_return_t export_macho_for_array(const KXLDRelocator *relocator,
    const KXLDArray *relocs, struct relocation_info **dstp);
#endif /* KXLD_PIC_KEXTS */

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_relocator_init(KXLDRelocator *relocator, u_char *file,
    const KXLDSymtab *symtab, const KXLDArray *sectarray, cpu_type_t cputype, 
    cpu_subtype_t cpusubtype __unused, boolean_t swap)
{
    kern_return_t rval = KERN_FAILURE;

    check(relocator);

    switch(cputype) {
#if KXLD_USER_OR_I386
    case CPU_TYPE_I386:
        relocator->reloc_has_pair = generic_reloc_has_pair;
        relocator->reloc_get_pair_type = generic_reloc_get_pair_type;
        relocator->reloc_has_got = generic_reloc_has_got;
        relocator->process_reloc = generic_process_reloc;
        relocator->function_align = 0;
        relocator->is_32_bit = TRUE;
        relocator->may_scatter = TRUE;
        break;
#endif /* KXLD_USER_OR_I386 */
#if KXLD_USER_OR_X86_64
    case CPU_TYPE_X86_64:
        relocator->reloc_has_pair = x86_64_reloc_has_pair;
        relocator->reloc_get_pair_type = x86_64_reloc_get_pair_type;
        relocator->reloc_has_got = x86_64_reloc_has_got;
        relocator->process_reloc = x86_64_process_reloc;
        relocator->function_align = 0;
        relocator->is_32_bit = FALSE;
        relocator->may_scatter = FALSE;
        break;
#endif /* KXLD_USER_OR_X86_64 */
#if KXLD_USER_OR_ARM
    case CPU_TYPE_ARM:
        relocator->reloc_has_pair = arm_reloc_has_pair;
        relocator->reloc_get_pair_type = arm_reloc_get_pair_type;
        relocator->reloc_has_got = arm_reloc_has_got;
        relocator->process_reloc = arm_process_reloc;
        relocator->function_align = 1;
        relocator->is_32_bit = TRUE;
        relocator->may_scatter = FALSE;
        break;
#endif /* KXLD_USER_OR_ARM */

    default:
        rval = KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr,
            kKxldLogArchNotSupported, cputype);
        goto finish;
    }

    relocator->file = file;
    relocator->symtab = symtab;
    relocator->sectarray = sectarray;
    relocator->is_32_bit = kxld_is_32_bit(cputype);
    relocator->swap = swap;

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_reloc_create_macho(KXLDArray *relocarray, const KXLDRelocator *relocator, 
    const struct relocation_info *srcs, u_int nsrcs)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    u_int nrelocs = 0;
    const struct relocation_info *src = NULL;
    const struct scattered_relocation_info *scatsrc = NULL;
    u_int i = 0;
    u_int reloc_index = 0;

    check(relocarray);
    check(srcs);

    /* If there are no relocation entries, just return */
    if (!nsrcs) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    /* Count the number of non-pair relocs */
    nrelocs = count_relocatable_relocs(relocator, srcs, nsrcs);

    if (nrelocs) {

        /* Allocate the array of relocation entries */

        rval = kxld_array_init(relocarray, sizeof(KXLDReloc), nrelocs);
        require_noerr(rval, finish);

        /* Initialize the relocation entries */
        
        for (i = 0; i < nsrcs; ++i) {
            src = srcs + i;
            scatsrc = (const struct scattered_relocation_info *) src;

            /* A section-based relocation entry can be skipped for absolute 
             * symbols.
             */

            if (!(relocator->may_scatter && (src->r_address & R_SCATTERED)) &&
                !(src->r_extern) && (R_ABS == src->r_symbolnum))
            {
                continue;
            }
            
            /* Pull out the data from the relocation entries.  The target_type
             * depends on the r_extern bit:
             *  Scattered -> Section Lookup by Address
             *  Local (not extern) -> Section by Index
             *  Extern -> Symbolnum by Index
             */
            reloc = kxld_array_get_item(relocarray, reloc_index++);
            if (relocator->may_scatter && (src->r_address & R_SCATTERED)) {
                reloc->address = scatsrc->r_address;
                reloc->pcrel = scatsrc->r_pcrel;
                reloc->length = scatsrc->r_length;
                reloc->reloc_type = scatsrc->r_type;
                reloc->target = scatsrc->r_value;
                reloc->target_type = KXLD_TARGET_LOOKUP;
            } else {
                reloc->address = src->r_address;
                reloc->pcrel = src->r_pcrel;
                reloc->length = src->r_length;
                reloc->reloc_type = src->r_type;
                reloc->target = src->r_symbolnum;

                if (0 == src->r_extern) {
                    reloc->target_type = KXLD_TARGET_SECTNUM;
                    reloc->target -= 1;
                } else {
                    reloc->target_type = KXLD_TARGET_SYMBOLNUM;
                }
            }
            
            /* Find the pair entry if it exists */

            if (relocator->reloc_has_pair(reloc->reloc_type)) {
                ++i;
                require_action(i < nsrcs, finish, rval=KERN_FAILURE);

                src = srcs + i;
                scatsrc = (const struct scattered_relocation_info *) src;
                 
                if (relocator->may_scatter && (src->r_address & R_SCATTERED)) {
                    require_action(relocator->reloc_get_pair_type(
                        reloc->reloc_type) == scatsrc->r_type,
                        finish, rval=KERN_FAILURE);
                    reloc->pair_address= scatsrc->r_address;
                    reloc->pair_target = scatsrc->r_value;
                    reloc->pair_target_type = KXLD_TARGET_LOOKUP;
                } else {
                    require_action(relocator->reloc_get_pair_type(
                        reloc->reloc_type) == scatsrc->r_type,
                        finish, rval=KERN_FAILURE);
                    reloc->pair_address = scatsrc->r_address;
                    if (src->r_extern) {
                        reloc->pair_target = src->r_symbolnum;
                        reloc->pair_target_type = KXLD_TARGET_SYMBOLNUM;
                    } else {
                        reloc->pair_target = src->r_address;
                        reloc->pair_target_type = KXLD_TARGET_VALUE;
                    }
                }
            } else {
                reloc->pair_target = 0;
                if (relocator->reloc_has_got(reloc->reloc_type)) {
                   reloc->pair_target_type = KXLD_TARGET_GOT;
                } else {
                   reloc->pair_target_type = KXLD_TARGET_NONE;
                }
            }
        }
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}


/*******************************************************************************
* Relocatable relocs :
*   1) Are not _PAIR_ relocs
*   2) Don't reference N_ABS symbols
*******************************************************************************/
static u_int
count_relocatable_relocs(const KXLDRelocator *relocator, 
    const struct relocation_info *relocs, u_int nrelocs)
{
    u_int num_nonpair_relocs = 0;
    u_int i = 0;
    const struct relocation_info *reloc = NULL;
    const struct scattered_relocation_info *sreloc = NULL;

    check(relocator);
    check(relocs);

    /* Loop over all of the relocation entries */

    num_nonpair_relocs = 1;
    for (i = 1; i < nrelocs; ++i) {
        reloc = relocs + i;

        if (reloc->r_address & R_SCATTERED) {
            /* A scattered relocation entry is relocatable as long as it's not a
             * pair.
             */
            sreloc = (const struct scattered_relocation_info *) reloc;

            num_nonpair_relocs += 
                !relocator->reloc_has_pair(sreloc->r_type);
        } else {
            /* A normal relocation entry is relocatable if it is not a pair and
             * if it is not a section-based relocation for an absolute symbol.
             */
            num_nonpair_relocs += 
                !(relocator->reloc_has_pair(reloc->r_type)
                 || (0 == reloc->r_extern && R_ABS == reloc->r_symbolnum));
        }

    }
    
    return num_nonpair_relocs;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_relocator_clear(KXLDRelocator *relocator)
{
    bzero(relocator, sizeof(*relocator));
}

/*******************************************************************************
*******************************************************************************/
boolean_t 
kxld_relocator_has_pair(const KXLDRelocator *relocator, u_int r_type)
{
    check(relocator);

    return relocator->reloc_has_pair(r_type);
}

/*******************************************************************************
*******************************************************************************/
u_int 
kxld_relocator_get_pair_type(const KXLDRelocator *relocator,
    u_int prev_r_type)
{
    check(relocator);

    return relocator->reloc_get_pair_type(prev_r_type);
}

/*******************************************************************************
*******************************************************************************/
boolean_t 
kxld_relocator_has_got(const KXLDRelocator *relocator, u_int r_type)
{
    check(relocator);

    return relocator->reloc_has_got(r_type);
}

/*******************************************************************************
*******************************************************************************/
KXLDSym *
kxld_reloc_get_symbol(const KXLDRelocator *relocator, const KXLDReloc *reloc,
    const u_char *data)
{
    KXLDSym *sym = NULL;
    kxld_addr_t value = 0;

    check(reloc);

    switch (reloc->target_type) {
    case KXLD_TARGET_SYMBOLNUM:
        sym = kxld_symtab_get_symbol_by_index(relocator->symtab, reloc->target);
        break;
    case KXLD_TARGET_SECTNUM:
        if (data) { 
            value = kxld_relocator_get_pointer_at_addr(relocator, data, 
                reloc->address);
            sym = kxld_symtab_get_cxx_symbol_by_value(relocator->symtab, value);           
        }
        break;
    default:
        sym = NULL;
        break;
    }

    return sym;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_reloc_get_reloc_index_by_offset(const KXLDArray *relocs, 
    kxld_size_t offset, u_int *idx)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    u_int i = 0;

    for (i = 0; i < relocs->nitems; ++i) {
        reloc = kxld_array_get_item(relocs, i);
        if (reloc->address == offset) break;
    }
    
    if (i >= relocs->nitems) {
        rval = KERN_FAILURE;
        goto finish;
    }

    *idx = i;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
KXLDReloc *
kxld_reloc_get_reloc_by_offset(const KXLDArray *relocs, kxld_addr_t offset)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDReloc *reloc = NULL;
    u_int i = 0;

    rval = kxld_reloc_get_reloc_index_by_offset(relocs, offset, &i);
    if (rval) goto finish;

    reloc = kxld_array_get_item(relocs, i);
    
finish:
    return reloc;
}

#if KXLD_PIC_KEXTS
/*******************************************************************************
*******************************************************************************/
u_long
kxld_reloc_get_macho_header_size()
{
    return sizeof(struct dysymtab_command);
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_reloc_get_macho_data_size(const KXLDArray *locrelocs,
    const KXLDArray *extrelocs)
{
    u_long    rval = 0;

    rval += get_macho_data_size_for_array(locrelocs);
    rval += get_macho_data_size_for_array(extrelocs);

    return (rval);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_reloc_export_macho(const KXLDRelocator *relocator,
    const KXLDArray *locrelocs, const KXLDArray *extrelocs,
    u_char *buf, u_long *header_offset, u_long header_size,
    u_long *data_offset, u_long size)
{
    kern_return_t rval = KERN_FAILURE;
    struct dysymtab_command *dysymtabhdr = NULL;
    struct relocation_info *start = NULL;
    struct relocation_info *dst = NULL;
    u_long count = 0;
    u_long data_size = 0;

    check(locrelocs);
    check(extrelocs);
    check(buf);
    check(header_offset);
    check(data_offset);

    require_action(sizeof(*dysymtabhdr) <= header_size - *header_offset, finish, rval=KERN_FAILURE);
    dysymtabhdr = (struct dysymtab_command *) ((void *) (buf + *header_offset));
    *header_offset += sizeof(*dysymtabhdr);

    data_size = kxld_reloc_get_macho_data_size(locrelocs, extrelocs);
    require_action((*data_offset + data_size) <= size, finish, rval=KERN_FAILURE);
    
    start = dst = (struct relocation_info *) ((void *) (buf + *data_offset));

    rval = export_macho_for_array(relocator, locrelocs, &dst);
    require_noerr(rval, finish);
    
    rval = export_macho_for_array(relocator, extrelocs, &dst);
    require_noerr(rval, finish);

    count = dst - start;

    memset(dysymtabhdr, 0, sizeof(*dysymtabhdr));
    dysymtabhdr->cmd = LC_DYSYMTAB;
    dysymtabhdr->cmdsize = (uint32_t) sizeof(*dysymtabhdr);
    dysymtabhdr->locreloff = (uint32_t) *data_offset;
    dysymtabhdr->nlocrel = (uint32_t) count;
    
    *data_offset += count * sizeof(struct relocation_info);

    rval = KERN_SUCCESS;
finish:
    return rval;
}
#endif /* KXLD_PIC_KEXTS */

/*******************************************************************************
*******************************************************************************/
kxld_addr_t
kxld_relocator_get_pointer_at_addr(const KXLDRelocator *relocator,
    const u_char *data, u_long offset)
{
    kxld_addr_t value;

    KXLD_3264_FUNC(relocator->is_32_bit, value,
        get_pointer_at_addr_32, get_pointer_at_addr_64,
        relocator, data, offset);

    return value;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kxld_addr_t
get_pointer_at_addr_32(const KXLDRelocator *relocator, 
    const u_char *data, u_long offset)
{
    uint32_t addr = 0;
    
    check(relocator);

    addr = *(const uint32_t *) ((void *) (data + offset));
#if !KERNEL
    if (relocator->swap) {
        addr = OSSwapInt32(addr);
    }
#endif

    return align_raw_function_address(relocator, addr);
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
static kxld_addr_t
get_pointer_at_addr_64(const KXLDRelocator *relocator, 
    const u_char *data, u_long offset)
{
    uint64_t addr = 0;
    
    check(relocator);

    addr = *(const uint64_t *) ((void *) (data + offset));
#if !KERNEL
    if (relocator->swap) {
        addr = OSSwapInt64(addr);
    }
#endif

    return align_raw_function_address(relocator, addr);
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
void 
kxld_relocator_set_vtables(KXLDRelocator *relocator, const KXLDDict *vtables)
{
    relocator->vtables = vtables;
}

/*******************************************************************************
* When we're inspecting the raw binary and not the symbol table, value may
* hold a THUMB address (with bit 0 set to 1) but the index will have the real
* address (bit 0 set to 0). So if bit 0 is set here, we clear it. This only
* impacts ARM for now, but it's implemented as a generic function alignment
* mask.
*******************************************************************************/
static kxld_addr_t
align_raw_function_address(const KXLDRelocator *relocator, kxld_addr_t value)
{
    if (relocator->function_align) { 
        value &= ~((1ULL << relocator->function_align) - 1); 
    }

    return value; 
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_relocator_process_sect_reloc(KXLDRelocator *relocator,
    const KXLDReloc *reloc, const KXLDSect *sect)
{
    kern_return_t rval = KERN_FAILURE;
    u_char *instruction = NULL;
    kxld_addr_t target = 0;
    kxld_addr_t pair_target = 0;
    kxld_addr_t base_pc = 0;
    kxld_addr_t link_pc = 0;
    kxld_addr_t link_disp = 0;

    check(relocator);
    check(reloc);
    check(sect);

    /* Find the instruction */

    instruction = sect->data + reloc->address;

    /* Calculate the target */

    rval = calculate_targets(relocator, &target, &pair_target, reloc);
    require_noerr(rval, finish);

    base_pc = reloc->address;
    link_pc = base_pc + sect->link_addr;
    link_disp = sect->link_addr - sect->base_addr;

    /* Relocate */

    rval = relocator->process_reloc(relocator, instruction, reloc->length, 
        reloc->pcrel, base_pc, link_pc, link_disp, reloc->reloc_type, target, 
        pair_target, relocator->swap);
    require_noerr(rval, finish);
    
    /* Return */

    relocator->current_vtable = NULL;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_reloc_update_symindex(KXLDReloc *reloc, u_int symindex)
{
    kern_return_t rval = KERN_FAILURE;

    require_action(reloc->target_type == KXLD_TARGET_SYMBOLNUM, 
        finish, rval = KERN_FAILURE);

    reloc->target = symindex;

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_relocator_process_table_reloc(KXLDRelocator *relocator,
    const KXLDReloc *reloc, const KXLDSeg *seg, kxld_addr_t link_addr)
{
    kern_return_t rval = KERN_FAILURE;
    u_char *instruction = NULL;
    kxld_addr_t target = 0;
    kxld_addr_t pair_target = 0;
    kxld_addr_t base_pc = 0;
    kxld_addr_t link_pc = 0;
    u_long offset = 0;

    check(relocator);
    check(reloc);

    /* Find the instruction */

    offset = (u_long)(seg->fileoff + (reloc->address - seg->base_addr));
    instruction = relocator->file + offset;

    /* Calculate the target */

    rval = calculate_targets(relocator, &target, &pair_target, reloc);
    require_noerr(rval, finish);

    base_pc = reloc->address;
    link_pc = base_pc + link_addr;

    /* Relocate */

    rval = relocator->process_reloc(relocator, instruction, reloc->length, 
        reloc->pcrel, base_pc, link_pc, link_addr, reloc->reloc_type, target,
        pair_target, relocator->swap);
    require_noerr(rval, finish);
    
    /* Return */

    relocator->current_vtable = NULL;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
calculate_targets(KXLDRelocator *relocator, kxld_addr_t *_target, 
    kxld_addr_t *_pair_target, const KXLDReloc *reloc)
{
    kern_return_t rval = KERN_FAILURE;
    const KXLDSect *sect = NULL;
    const KXLDSym *sym = NULL;
    kxld_addr_t target = 0;
    kxld_addr_t pair_target = 0;
    char *demangled_name = NULL;
    size_t demangled_length = 0;

    check(_target);
    check(_pair_target);
    *_target = 0;
    *_pair_target = 0;

    /* Find the target based on the lookup type */

    switch(reloc->target_type) {
    case KXLD_TARGET_LOOKUP:
        require_action(reloc->pair_target_type == KXLD_TARGET_NONE ||
            reloc->pair_target_type == KXLD_TARGET_LOOKUP ||
            reloc->pair_target_type == KXLD_TARGET_VALUE,
            finish, rval=KERN_FAILURE);

        rval = get_target_by_address_lookup(&target, reloc->target, 
            relocator->sectarray);
        require_noerr(rval, finish);

        if (reloc->pair_target_type == KXLD_TARGET_LOOKUP) {
            rval = get_target_by_address_lookup(&pair_target,
                reloc->pair_target, relocator->sectarray);
            require_noerr(rval, finish);
        } else if (reloc->pair_target_type == KXLD_TARGET_VALUE) {
            pair_target = reloc->pair_target;
        }
        break;
    case KXLD_TARGET_SECTNUM:
        require_action(reloc->pair_target_type == KXLD_TARGET_NONE ||
            reloc->pair_target_type == KXLD_TARGET_VALUE, 
            finish, rval=KERN_FAILURE);

        /* Get the target's section by section number */
        sect = kxld_array_get_item(relocator->sectarray, reloc->target);
        require_action(sect, finish, rval=KERN_FAILURE);

        /* target is the change in the section's address */
        target = sect->link_addr - sect->base_addr;

        if (reloc->pair_target_type) {
            pair_target = reloc->pair_target;
        } else {
            /* x86_64 needs to know when we have a non-external relocation,
             * so we hack that information in here.
             */
            pair_target = TRUE;
        }
        break;
    case KXLD_TARGET_SYMBOLNUM:
        require_action(reloc->pair_target_type == KXLD_TARGET_NONE ||
            reloc->pair_target_type == KXLD_TARGET_GOT ||
            reloc->pair_target_type == KXLD_TARGET_SYMBOLNUM ||
            reloc->pair_target_type == KXLD_TARGET_VALUE, finish,
            rval=KERN_FAILURE);

        /* Get the target's symbol by symbol number */
        sym = kxld_symtab_get_symbol_by_index(relocator->symtab, reloc->target);
        require_action(sym, finish, rval=KERN_FAILURE);

        /* If this symbol is a padslot that has already been replaced, then the
         * only way a relocation entry can still reference it is if there is a
         * vtable that has not been patched.  The vtable patcher uses the
         * MetaClass structure to find classes for patching, so an unpatched
         * vtable means that there is an OSObject-dervied class that is missing
         * its OSDeclare/OSDefine macros.
         */
        require_action(!kxld_sym_is_padslot(sym) || !kxld_sym_is_replaced(sym), 
            finish, rval=KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogRelocatingPatchedSym,
                kxld_demangle(sym->name, &demangled_name, &demangled_length)));

        target = sym->link_addr;

        if (kxld_sym_is_vtable(sym)) {
            relocator->current_vtable = kxld_dict_find(relocator->vtables, sym->name);
        }

        /* Some relocation types need the GOT entry address instead of the
         * symbol's actual address.  These types don't have pair relocation
         * entries, so we store the GOT entry address as the pair target.
         */
        if (reloc->pair_target_type == KXLD_TARGET_VALUE) {
            pair_target = reloc->pair_target;
        } else if (reloc->pair_target_type == KXLD_TARGET_SYMBOLNUM ) {
            sym = kxld_symtab_get_symbol_by_index(relocator->symtab, 
                reloc->pair_target);
            require_action(sym, finish, rval=KERN_FAILURE);
            pair_target = sym->link_addr;
        } else if (reloc->pair_target_type == KXLD_TARGET_GOT) {
            pair_target = sym->got_addr;
        }
        break;
    default:
        rval = KERN_FAILURE;
        goto finish;
    }

    *_target = target;
    *_pair_target = pair_target;
    rval = KERN_SUCCESS;

finish:
    if (demangled_name) kxld_free(demangled_name, demangled_length);
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
get_target_by_address_lookup(kxld_addr_t *target, kxld_addr_t addr,
    const KXLDArray *sectarray)
{
    kern_return_t rval = KERN_FAILURE;
    const KXLDSect *sect = NULL;
    kxld_addr_t start = 0;
    kxld_addr_t end = 0;
    u_int i = 0;

    check(target);
    check(sectarray);
    *target = 0;

    for (i = 0; i < sectarray->nitems; ++i) {
        sect = kxld_array_get_item(sectarray, i);
        start = sect->base_addr;
        end = start + sect->size;

        if (start <= addr && addr < end) break;
        
        sect = NULL;
    }
    require_action(sect, finish, rval=KERN_FAILURE);

    *target = sect->link_addr - sect->base_addr;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
check_for_direct_pure_virtual_call(const KXLDRelocator *relocator, u_long offset)
{
    kern_return_t rval = KERN_FAILURE;
    const KXLDVTableEntry *entry = NULL;

    if (relocator->current_vtable) {
        entry = kxld_vtable_get_entry_for_offset(relocator->current_vtable, 
            offset, relocator->is_32_bit);
        require_action(!entry || !entry->patched.name ||
            !kxld_sym_name_is_pure_virtual(entry->patched.name),
            finish, rval=KERN_FAILURE;
            kxld_log(kKxldLogLinking, kKxldLogErr, 
                kKxldLogDirectPureVirtualCall));
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}

#if KXLD_PIC_KEXTS
/*******************************************************************************
*******************************************************************************/
static u_long
get_macho_data_size_for_array(const KXLDArray *relocs)
{
    const KXLDReloc *reloc = NULL;
    u_int i = 0;
    u_long size = 0;

    check(relocs);

    for (i = 0; i < relocs->nitems; ++i) {
        reloc = kxld_array_get_item(relocs, i);
        if (!reloc->pcrel) {
            size += sizeof(struct relocation_info);
            if(reloc->pair_target_type != KXLD_TARGET_NONE) {
                size += sizeof(struct relocation_info);
            }
        }
    }

    return size;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
export_macho_for_array(const KXLDRelocator *relocator,
    const KXLDArray *relocs, struct relocation_info **dstp)
{
    kern_return_t rval = KERN_FAILURE;
    const KXLDReloc *reloc = NULL;
    struct relocation_info *dst = NULL;
    struct scattered_relocation_info *scatdst = NULL;
    u_int i = 0;

    dst = *dstp;

    for (i = 0; i < relocs->nitems; ++i) {
        reloc = kxld_array_get_item(relocs, i);
        scatdst = (struct scattered_relocation_info *) dst;

        if (reloc->pcrel) {
            continue;
        }

        switch (reloc->target_type) {
        case KXLD_TARGET_LOOKUP:
            scatdst->r_address = reloc->address;
            scatdst->r_pcrel = reloc->pcrel;
            scatdst->r_length = reloc->length;
            scatdst->r_type = reloc->reloc_type;
            scatdst->r_value = reloc->target;
            scatdst->r_scattered = 1;
            break;
        case KXLD_TARGET_SECTNUM:
            dst->r_address = reloc->address;
            dst->r_pcrel = reloc->pcrel;
            dst->r_length = reloc->length;
            dst->r_type = reloc->reloc_type;
            dst->r_symbolnum = reloc->target + 1;
            dst->r_extern = 0;
            break;
        case KXLD_TARGET_SYMBOLNUM:
           /* Assume that everything will be slid together; otherwise,
            * there is no sensible value for the section number.
            */
            dst->r_address = reloc->address;
            dst->r_pcrel = reloc->pcrel;
            dst->r_length = reloc->length;
            dst->r_type = reloc->reloc_type;
            dst->r_symbolnum = 1;
            dst->r_extern = 0;
            break;
        default:
            rval = KERN_FAILURE;
            goto finish;
        }

        ++dst;

        if(reloc->pair_target_type != KXLD_TARGET_NONE) {
            ++i;
            require_action(i < relocs->nitems, finish, rval=KERN_FAILURE);
            scatdst = (struct scattered_relocation_info *) dst;
            switch (reloc->pair_target_type) {
            case KXLD_TARGET_LOOKUP:
                scatdst->r_address = reloc->pair_address;
                scatdst->r_pcrel = reloc->pcrel;
                scatdst->r_length = reloc->length;
                scatdst->r_type = relocator->reloc_get_pair_type(reloc->reloc_type);
                scatdst->r_value = reloc->pair_target;
                scatdst->r_scattered = 1;
                break;
            case KXLD_TARGET_SECTNUM:
                dst->r_address = reloc->pair_address;
                dst->r_pcrel = reloc->pcrel;
                dst->r_length = reloc->length;
                dst->r_type = relocator->reloc_get_pair_type(reloc->reloc_type);
                dst->r_symbolnum = reloc->pair_target + 1;
                dst->r_extern = 0;
                break;
            case KXLD_TARGET_SYMBOLNUM:
                dst->r_address = reloc->pair_address;
                dst->r_pcrel = reloc->pcrel;
                dst->r_length = reloc->length;
                dst->r_type = relocator->reloc_get_pair_type(reloc->reloc_type);
                dst->r_symbolnum = 1;
                dst->r_extern = 0;
                break;
            default:
                rval = KERN_FAILURE;
                goto finish;
            }
            ++dst;
        }
    }

    rval = KERN_SUCCESS;
finish:
    *dstp = dst;
    return rval;
}
#endif /* KXLD_PIC_KEXTS */

#if KXLD_USER_OR_I386 
/*******************************************************************************
*******************************************************************************/
static boolean_t
generic_reloc_has_pair(u_int _type)
{
    enum reloc_type_generic type = _type;

    return (type == GENERIC_RELOC_SECTDIFF || 
        type == GENERIC_RELOC_LOCAL_SECTDIFF);
}

/*******************************************************************************
*******************************************************************************/
static u_int 
generic_reloc_get_pair_type(u_int _prev_type __unused)
{
    return GENERIC_RELOC_PAIR;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t generic_reloc_has_got(u_int _type __unused)
{
    return FALSE;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
generic_process_reloc(const KXLDRelocator *relocator, u_char *instruction, 
    u_int length, u_int pcrel, kxld_addr_t _base_pc, kxld_addr_t _link_pc, 
    kxld_addr_t _link_disp __unused, u_int _type, kxld_addr_t _target, 
    kxld_addr_t _pair_target, boolean_t swap __unused)
{
    kern_return_t rval = KERN_FAILURE;
    uint32_t base_pc = (uint32_t) _base_pc;
    uint32_t link_pc = (uint32_t) _link_pc;
    uint32_t *instr_addr = NULL;
    uint32_t instr_data = 0;
    uint32_t target = (uint32_t) _target;
    uint32_t pair_target = (uint32_t) _pair_target;
    enum reloc_type_generic type = _type;

    check(instruction);
    require_action(length == 2, finish, rval=KERN_FAILURE);

    if (pcrel) target = target + base_pc - link_pc;

    instr_addr = (uint32_t *) ((void *) instruction);
    instr_data = *instr_addr;

#if !KERNEL
    if (swap) instr_data = OSSwapInt32(instr_data);
#endif

    rval = check_for_direct_pure_virtual_call(relocator, instr_data);
    require_noerr(rval, finish);

    switch (type) {
    case GENERIC_RELOC_VANILLA:
        instr_data += target;
        break;
    case GENERIC_RELOC_SECTDIFF:
    case GENERIC_RELOC_LOCAL_SECTDIFF:
        instr_data = instr_data + target - pair_target;
        break;
    case GENERIC_RELOC_PB_LA_PTR:
        rval = KERN_FAILURE;
        goto finish;
    case GENERIC_RELOC_PAIR:
    default:
        rval = KERN_FAILURE;
        goto finish;
    }

#if !KERNEL
    if (swap) instr_data = OSSwapInt32(instr_data);
#endif

    *instr_addr = instr_data;

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_I386 */

#if KXLD_USER_OR_X86_64
/*******************************************************************************
*******************************************************************************/
static boolean_t 
x86_64_reloc_has_pair(u_int _type)
{
    enum reloc_type_x86_64 type = _type;

    return (type == X86_64_RELOC_SUBTRACTOR);
}

/*******************************************************************************
*******************************************************************************/
static u_int 
x86_64_reloc_get_pair_type(u_int _prev_type __unused)
{
    return X86_64_RELOC_UNSIGNED;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t 
x86_64_reloc_has_got(u_int _type)
{
    enum reloc_type_x86_64 type = _type;

    return (type == X86_64_RELOC_GOT_LOAD || type == X86_64_RELOC_GOT);
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
x86_64_process_reloc(const KXLDRelocator *relocator __unused, u_char *instruction, 
    u_int length, u_int pcrel, kxld_addr_t _base_pc __unused, 
    kxld_addr_t _link_pc, kxld_addr_t _link_disp, u_int _type, 
    kxld_addr_t _target, kxld_addr_t _pair_target, boolean_t swap __unused)
{
    kern_return_t rval = KERN_FAILURE;
    enum reloc_type_x86_64 type = _type;
    int32_t *instr32p = NULL;
    int32_t instr32 = 0;
    uint64_t *instr64p = NULL;
    uint64_t instr64 = 0;
    uint64_t target = _target;
    uint64_t pair_target = _pair_target;
    uint64_t link_pc = (uint64_t) _link_pc;
    uint64_t link_disp = (uint64_t) _link_disp;
    uint64_t adjustment = 0;

    check(instruction);
    require_action(length == 2 || length == 3, 
        finish, rval=KERN_FAILURE);

    if (length == 2) {
        instr32p = (int32_t *) ((void *) instruction);
        instr32 = *instr32p;

#if !KERNEL
        if (swap) instr32 = OSSwapInt32(instr32);
#endif

        rval = check_for_direct_pure_virtual_call(relocator, instr32);
        require_noerr(rval, finish);

        /* There are a number of different small adjustments for pc-relative
         * relocation entries.  The general case is to subtract the size of the
         * relocation (represented by the length parameter), and it applies to
         * the GOT types and external SIGNED types.  The non-external signed types
         * have a different adjustment corresponding to the specific type.
         */
        switch (type) {
        case X86_64_RELOC_SIGNED:
            if (pair_target) {
                adjustment = 0;    
                break;
            }
            /* Fall through */
        case X86_64_RELOC_SIGNED_1:
            if (pair_target) {
                adjustment = 1;
                break;
            }
            /* Fall through */
        case X86_64_RELOC_SIGNED_2:
            if (pair_target) {
                adjustment = 2;
                break;
            }
            /* Fall through */
        case X86_64_RELOC_SIGNED_4:
            if (pair_target) {
                adjustment = 4;
                break;
            }
            /* Fall through */
        case X86_64_RELOC_BRANCH:
        case X86_64_RELOC_GOT:
        case X86_64_RELOC_GOT_LOAD:
            adjustment = (1 << length);
            break;
        default:
            break;
        }

        /* Perform the actual relocation.  All of the 32-bit relocations are 
         * pc-relative except for SUBTRACTOR, so a good chunk of the logic is
         * stuck in calculate_displacement_x86_64.  The signed relocations are
         * a special case, because when they are non-external, the instruction
         * already contains the pre-relocation displacement, so we only need to
         * find the difference between how far the PC was relocated, and how
         * far the target is relocated.  Since the target variable already
         * contains the difference between the target's base and link
         * addresses, we add the difference between the PC's base and link
         * addresses to the adjustment variable.  This will yield the
         * appropriate displacement in calculate_displacement.
         */
        switch (type) {
        case X86_64_RELOC_BRANCH:
            require_action(pcrel, finish, rval=KERN_FAILURE);
            adjustment += link_pc;
            break;
        case X86_64_RELOC_SIGNED:
        case X86_64_RELOC_SIGNED_1:
        case X86_64_RELOC_SIGNED_2:
        case X86_64_RELOC_SIGNED_4:
            require_action(pcrel, finish, rval=KERN_FAILURE);
            adjustment += (pair_target) ? (link_disp) : (link_pc);
            break;
        case X86_64_RELOC_GOT:
        case X86_64_RELOC_GOT_LOAD:
            require_action(pcrel, finish, rval=KERN_FAILURE);
            adjustment += link_pc;
            target = pair_target;
            break;
        case X86_64_RELOC_SUBTRACTOR:
            require_action(!pcrel, finish, rval=KERN_FAILURE);
            instr32 = (int32_t) (target - pair_target);
            break;
        case X86_64_RELOC_UNSIGNED:
        default:
            rval = KERN_FAILURE;
            goto finish;
        }

        /* Call calculate_displacement for the pc-relative relocations */
        if (pcrel) {
            rval = calculate_displacement_x86_64(target, adjustment, &instr32); 
            require_noerr(rval, finish);
        }

#if !KERNEL
        if (swap) instr32 = OSSwapInt32(instr32);
#endif

        *instr32p = instr32;
    } else {
        instr64p = (uint64_t *) ((void *) instruction);
        instr64 = *instr64p;

#if !KERNEL
        if (swap) instr64 = OSSwapInt64(instr64);
#endif

        rval = check_for_direct_pure_virtual_call(relocator, (u_long) instr64);
        require_noerr(rval, finish);

        switch (type) {
        case X86_64_RELOC_UNSIGNED:
            require_action(!pcrel, finish, rval=KERN_FAILURE);
            
            instr64 += target;
            break;
        case X86_64_RELOC_SUBTRACTOR:
            require_action(!pcrel, finish, rval=KERN_FAILURE);

            instr64 = target - pair_target;
            break;
        case X86_64_RELOC_SIGNED_1:
        case X86_64_RELOC_SIGNED_2:
        case X86_64_RELOC_SIGNED_4:
        case X86_64_RELOC_GOT_LOAD:
        case X86_64_RELOC_BRANCH:
        case X86_64_RELOC_SIGNED:
        case X86_64_RELOC_GOT:
        default:
            rval = KERN_FAILURE;
            goto finish;
        }

#if !KERNEL
        if (swap) instr64 = OSSwapInt64(instr64);
#endif

        *instr64p = instr64;
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
calculate_displacement_x86_64(uint64_t target, uint64_t adjustment, 
    int32_t *instr32)
{
    kern_return_t rval = KERN_FAILURE;
    int64_t displacement;
    uint64_t difference;

    displacement = *instr32 + target - adjustment;
    difference = ABSOLUTE_VALUE(displacement);
    require_action(difference < X86_64_RIP_RELATIVE_LIMIT, finish, 
        rval=KERN_FAILURE;
        kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogRelocationOverflow));

    *instr32 = (int32_t) displacement;
    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_X86_64 */

#if KXLD_USER_OR_ARM
/*******************************************************************************
*******************************************************************************/
static boolean_t 
arm_reloc_has_pair(u_int _type)
{
    enum reloc_type_arm type = _type;

    switch(type) {
    case ARM_RELOC_SECTDIFF:
        return TRUE;
    default:
        return FALSE;
    }
    return FALSE;
}

/*******************************************************************************
*******************************************************************************/
static u_int 
arm_reloc_get_pair_type(u_int _prev_type __unused)
{
    return ARM_RELOC_PAIR;
}

/*******************************************************************************
*******************************************************************************/
static boolean_t 
arm_reloc_has_got(u_int _type __unused)
{
    return FALSE;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t 
arm_process_reloc(const KXLDRelocator *relocator __unused, u_char *instruction, 
    u_int length, u_int pcrel, kxld_addr_t _base_pc __unused, 
    kxld_addr_t _link_pc __unused, kxld_addr_t _link_disp __unused,
    u_int _type __unused, kxld_addr_t _target __unused, 
    kxld_addr_t _pair_target __unused,  boolean_t swap __unused)
{
    kern_return_t rval = KERN_FAILURE;
    uint32_t *instr_addr = NULL;
    uint32_t instr_data = 0;
    uint32_t base_pc = (uint32_t) _base_pc;
    uint32_t link_pc = (uint32_t) _link_pc;
    uint32_t target = (uint32_t) _target;
    int32_t displacement = 0;
    enum reloc_type_arm type = _type;

    check(instruction);
    require_action(length == 2, finish, rval=KERN_FAILURE);

    if (pcrel) displacement = target + base_pc - link_pc;

    instr_addr = (uint32_t *) ((void *) instruction);
    instr_data = *instr_addr;
    
#if !KERNEL
    if (swap) instr_data = OSSwapInt32(instr_data);
#endif

    rval = check_for_direct_pure_virtual_call(relocator, instr_data);
    require_noerr(rval, finish);

    switch (type) {
    case ARM_RELOC_VANILLA:
        instr_data += target;
        break;

    /*
     * If the displacement is 0 (the offset between the pc and the target has
     * not changed), then we don't need to do anything for BR24 and BR22
     * relocs.  As it turns out, because kexts build with -mlong-calls all
     * relocations currently end up being either vanilla (handled above) or 
     * BR22/BR24 with a displacement of 0.
     * We could handle other displacements here but to keep things simple, we
     * won't until it is needed (at which point the kernelcache will fail to
     * link)
     */
    case ARM_RELOC_BR24:
        require_action(pcrel, finish, rval=KERN_FAILURE);
        require_action(displacement == 0, finish, rval=KERN_FAILURE);
        break;
    case ARM_THUMB_RELOC_BR22:
        require_action(pcrel, finish, rval=KERN_FAILURE);
        require_action(displacement == 0, finish, rval=KERN_FAILURE);
        break;

    case ARM_RELOC_SECTDIFF:
    case ARM_RELOC_LOCAL_SECTDIFF:
    case ARM_RELOC_PB_LA_PTR:
        rval = KERN_FAILURE;
        goto finish;

    case ARM_RELOC_PAIR:
    default:
        rval = KERN_FAILURE;
        goto finish;
    }

#if !KERNEL
    if (swap) instr_data = OSSwapInt32(instr_data);
#endif

    *instr_addr = instr_data;

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#endif /* KXLD_USER_OR_ARM */
