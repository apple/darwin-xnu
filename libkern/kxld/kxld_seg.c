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
#include <mach/vm_prot.h>
#include <mach-o/loader.h>
#include <sys/types.h>

#if KERNEL
    #include <mach/vm_param.h>
#else
    #include <mach/mach_init.h>
#endif /* KERNEL */

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_reloc.h"
#include "kxld_sect.h"
#include "kxld_seg.h"
#include "kxld_symtab.h"
#include "kxld_util.h"

#define MAX_SEGS 20

#define TEXT_SEG_PROT (VM_PROT_READ | VM_PROT_EXECUTE)
#define DATA_SEG_PROT (VM_PROT_READ | VM_PROT_WRITE)

extern boolean_t isSplitKext;
extern boolean_t isOldInterface;

#if KXLD_USER_OR_OBJECT
static kern_return_t reorder_sections(KXLDSeg *seg, KXLDArray *section_order);
static void reorder_section(KXLDArray *sects, u_int *sect_reorder_index, 
    KXLDSect **reorder_buffer, u_int reorder_buffer_index);
#endif /* KXLD_USER_OR_OBJECT */

#if 0
static KXLDSeg * get_segment_by_name(KXLDArray *segarray, const char *name);
#endif

#if KXLD_USER_OR_ILP32
static kern_return_t seg_export_macho_header_32(const KXLDSeg *seg, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset);
#endif
#if KXLD_USER_OR_LP64
static kern_return_t seg_export_macho_header_64(const KXLDSeg *seg, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset);
#endif

static KXLDSect * get_sect_by_index(const KXLDSeg *seg, u_int idx);

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_init_from_macho_32(KXLDSeg *seg, struct segment_command *src)
{
    kern_return_t rval = KERN_FAILURE;
    check(seg);
    check(src);

    strlcpy(seg->segname, src->segname, sizeof(seg->segname));
    seg->base_addr = src->vmaddr;
    seg->link_addr = src->vmaddr;
    seg->vmsize = src->vmsize;
    seg->fileoff = src->fileoff;
    seg->maxprot = src->maxprot;
    seg->initprot = src->initprot;
    seg->flags = src->flags;

    rval = kxld_array_init(&seg->sects, sizeof(KXLDSect *), src->nsects);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_init_from_macho_64(KXLDSeg *seg, struct segment_command_64 *src)
{
    kern_return_t rval = KERN_FAILURE;
    check(seg);
    check(src);

    strlcpy(seg->segname, src->segname, sizeof(seg->segname));
    seg->base_addr = src->vmaddr;
    seg->link_addr = src->vmaddr;
    seg->vmsize = src->vmsize;
    
    seg->fileoff = src->fileoff;
    seg->maxprot = src->maxprot;
    seg->initprot = src->initprot;
    seg->flags = src->flags;
    
    rval = kxld_array_init(&seg->sects, sizeof(KXLDSect *), src->nsects);
    require_noerr(rval, finish);

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

#if KXLD_USER_OR_OBJECT
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_create_seg_from_sections(KXLDArray *segarray, KXLDArray *sectarray)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    KXLDSect *sect = NULL;
    KXLDSect **sectp = NULL;
    u_int i = 0;

    /* Initialize the segment array to one segment */

    rval = kxld_array_init(segarray, sizeof(KXLDSeg), 1);
    require_noerr(rval, finish);

    /* Initialize the segment */

    seg = kxld_array_get_item(segarray, 0);
    seg->initprot = VM_PROT_ALL;
    seg->maxprot = VM_PROT_ALL;
    seg->link_addr = 0;

    /* Add the sections to the segment */

    rval = kxld_array_init(&seg->sects, sizeof(KXLDSect *), sectarray->nitems);
    require_noerr(rval, finish);

    for (i = 0; i < sectarray->nitems; ++i) {
        sect = kxld_array_get_item(sectarray, i);
        sectp = kxld_array_get_item(&seg->sects, i);

        *sectp = sect;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_finalize_object_segment(KXLDArray *segarray, KXLDArray *section_order,
    u_long hdrsize)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    KXLDSect *sect = NULL;
    u_long sect_offset = 0;
    u_int i = 0;

    check(segarray);
    check(section_order);
    require_action(segarray->nitems == 1, finish, rval=KERN_FAILURE);

    seg = kxld_array_get_item(segarray, 0);
    
    /* Reorder the sections */
    
    rval = reorder_sections(seg, section_order);
    require_noerr(rval, finish);

    /* Set the initial link address at the end of the header pages */

    seg->link_addr = kxld_round_page_cross_safe(hdrsize);

    /* Fix up all of the section addresses */

    sect_offset = (u_long) seg->link_addr;
    for (i = 0; i < seg->sects.nitems; ++i) {
        sect = *(KXLDSect **)kxld_array_get_item(&seg->sects, i);

        sect->link_addr = kxld_sect_align_address(sect, sect_offset);
        sect_offset = (u_long) (sect->link_addr + sect->size);
    }

    /* Finish initializing the segment */

    seg->vmsize = kxld_round_page_cross_safe(sect_offset) - seg->link_addr;

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
* The legacy section ordering used by kld was based of the order of sections
* in the kernel file.  To achieve the same layout, we save the kernel's
* section ordering as an array of section names when the kernel file itself
* is linked.  Then, when kexts are linked with the KXLD_LEGACY_LAYOUT flag,
* we refer to the kernel's section layout to order the kext's sections.
*
* The algorithm below is as follows.  We iterate through all of the kernel's
* sections grouped by segment name, so that we are processing all of the __TEXT
* sections, then all of the __DATA sections, etc.  We then iterate through the
* kext's sections with a similar grouping, looking for sections that match
* the current kernel's section.  In this way, we order all of the matching
* kext sections in the order in which they appear in the kernel, and then place
* all remaining kext sections at the end of the current segment grouping in
* the order in which they originally appeared.  Sections that only appear in
* the kernel are not created.  segments that only appear in the kext are
* left in their original ordering.
*
* An example:
*
* Kernel sections:
* __TEXT,__text
* __TEXT,__const
* __DATA,__data
*
* Kext sections:
* __TEXT,__const
* __TEXT,__literal4
* __TEXT,__text
* __DATA,__const
* __DATA,__data
*
* Reordered kext sections:
* __TEXT,__text
* __TEXT,__const
* __TEXT,__literal4
* __DATA,__data
* __DATA,__const
*
* In the implementation below, we use a reorder buffer to hold pointers to the
* sections of the current working segment.  We scan this buffer looking for
* matching sections, placing them in the segment's section index as we find them.
* If this function must exit early, the segment's section index is left in an
* unusable state.
*******************************************************************************/
static kern_return_t
reorder_sections(KXLDSeg *seg, KXLDArray *section_order)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    KXLDSect **reorder_buffer = NULL;
    KXLDSectionName *section_name = NULL;
    const char *segname = NULL;
    u_int sect_index = 0, legacy_index = 0, sect_reorder_index = 0;
    u_int i = 0, j = 0;
    u_int sect_start = 0, sect_end = 0, legacy_start = 0, legacy_end = 0;
    u_int nsects = 0;

    check(seg);
    check(section_order);

    /* Allocate the reorder buffer with enough space to hold all of the 
     * sections.
     */

    reorder_buffer = kxld_alloc(
        seg->sects.nitems * sizeof(*reorder_buffer));
    require_action(reorder_buffer, finish, rval=KERN_RESOURCE_SHORTAGE);

    while (legacy_index < section_order->nitems) {

        /* Find the next group of sections with a common segment in the
         * section_order array.
         */

        legacy_start = legacy_index++;
        legacy_end = legacy_index;

        section_name = kxld_array_get_item(section_order, legacy_start);
        segname = section_name->segname;
        while (legacy_index < section_order->nitems) {
            section_name = kxld_array_get_item(section_order, legacy_index);
            if (!streq_safe(segname, section_name->segname, 
                    sizeof(section_name->segname))) 
            {
                break;
            }

            ++legacy_index;
            ++legacy_end;
        }

        /* Find a group of sections in the kext that match the current
         * section_order segment.
         */

        sect_start = sect_index;
        sect_end = sect_index;

        while (sect_index < seg->sects.nitems) {
            sect = *(KXLDSect **) kxld_array_get_item(&seg->sects, sect_index);
            if (!streq_safe(segname, sect->segname, sizeof(sect->segname))) {
                break;
            }

            ++sect_index;
            ++sect_end;
        }
        nsects = sect_end - sect_start;
        
        if (!nsects) continue;

        /* Populate the reorder buffer with the current group of kext sections */

        for (i = sect_start; i < sect_end; ++i) {
            reorder_buffer[i - sect_start] = 
                *(KXLDSect **) kxld_array_get_item(&seg->sects, i);
        }

        /* For each section_order section, scan the reorder buffer for a matching
         * kext section.  If one is found, copy it into the next slot in the
         * segment's section index.
         */

        sect_reorder_index = sect_start;
        for (i = legacy_start; i < legacy_end; ++i) {
            section_name = kxld_array_get_item(section_order, i);
            sect = NULL;

            for (j = 0; j < nsects; ++j) {
                sect = reorder_buffer[j];
                if (!sect) continue;

                if (streq_safe(section_name->sectname, sect->sectname, 
                        sizeof(section_name->sectname))) 
                {
                    break;
                }

                sect = NULL;
            }

            if (sect) { 
                (void) reorder_section(&seg->sects, &sect_reorder_index, 
                    reorder_buffer, j);
            }
        }

        /* If any sections remain in the reorder buffer, they are not specified
         * in the section_order array, so append them to the section index in
         * in the order they are found.
         */

        for (i = 0; i < nsects; ++i) {
            if (!reorder_buffer[i]) continue;
            reorder_section(&seg->sects, &sect_reorder_index, reorder_buffer, i);
        }
    }

    rval = KERN_SUCCESS;

finish:

    if (reorder_buffer) {
        kxld_free(reorder_buffer, seg->sects.nitems * sizeof(*reorder_buffer));
        reorder_buffer = NULL;
    }

    return rval;
}

/*******************************************************************************
*******************************************************************************/
static void
reorder_section(KXLDArray *sects, u_int *sect_reorder_index, 
    KXLDSect **reorder_buffer, u_int reorder_buffer_index)
{
    KXLDSect **tmp = NULL;

    tmp = kxld_array_get_item(sects, *sect_reorder_index);

    *tmp = reorder_buffer[reorder_buffer_index];
    reorder_buffer[reorder_buffer_index]->sectnum = *sect_reorder_index;
    reorder_buffer[reorder_buffer_index] = NULL;

    ++(*sect_reorder_index);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_init_linkedit(KXLDArray *segs)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSeg *seg = NULL;
    KXLDSeg *le = NULL;
    
    rval = kxld_array_resize(segs, 2);
    require_noerr(rval, finish);

    seg = kxld_array_get_item(segs, 0);
    le = kxld_array_get_item(segs, 1);

    strlcpy(le->segname, SEG_LINKEDIT, sizeof(le->segname));
    le->link_addr = kxld_round_page_cross_safe(seg->link_addr + seg->vmsize);
    le->maxprot = VM_PROT_ALL;
    le->initprot = VM_PROT_DEFAULT;

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_OBJECT */

/*******************************************************************************
*******************************************************************************/
void
kxld_seg_clear(KXLDSeg *seg)
{
    check(seg);

    bzero(seg->segname, sizeof(seg->segname));
    seg->base_addr = 0;
    seg->link_addr = 0;
    seg->vmsize = 0;
    seg->flags = 0;
    seg->maxprot = 0;
    seg->initprot = 0;

    /* Don't clear the individual sections here because kxld_kext.c will take
     * care of that.
     */
    kxld_array_clear(&seg->sects);
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_seg_deinit(KXLDSeg *seg)
{
    check(seg);

    kxld_array_deinit(&seg->sects);
    bzero(seg, sizeof(*seg));
}

/*******************************************************************************
*******************************************************************************/
kxld_size_t 
kxld_seg_get_vmsize(const KXLDSeg *seg)
{
    check(seg);
    
    return seg->vmsize;
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_seg_get_macho_header_size(const KXLDSeg *seg, boolean_t is_32_bit)
{
    u_long size = 0;
    
    check(seg);

    if (is_32_bit) {
        size += sizeof(struct segment_command);
    } else {
        size += sizeof(struct segment_command_64);
    }
    size += seg->sects.nitems * kxld_sect_get_macho_header_size(is_32_bit);

    return size;
}

/*******************************************************************************
*******************************************************************************/
/* This is no longer used, but may be useful some day... */
#if 0
u_long
kxld_seg_get_macho_data_size(const KXLDSeg *seg)
{
    u_long size = 0;
    u_int i = 0;
    KXLDSect *sect = NULL;

    check(seg);

    for (i = 0; i < seg->sects.nitems; ++i) {
        sect = get_sect_by_index(seg, i);
        size = (u_long) kxld_sect_align_address(sect, size);
        size += kxld_sect_get_macho_data_size(sect);
    }

    return kxld_round_page_cross_safe(size);
}
#endif

/*******************************************************************************
*******************************************************************************/
static KXLDSect * 
get_sect_by_index(const KXLDSeg *seg, u_int idx)
{
    check(seg);

    return *(KXLDSect **) kxld_array_get_item(&seg->sects, idx);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_export_macho_to_file_buffer(const KXLDSeg *seg, u_char *buf,
    u_long *header_offset, u_long header_size, 
    u_long *data_offset, u_long data_size,
    boolean_t is_32_bit)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect *sect = NULL;
    u_long base_data_offset = *data_offset;
    u_int i = 0;
    struct segment_command *hdr32 = 
        (struct segment_command *) ((void *) (buf + *header_offset));
    struct segment_command_64 *hdr64 = 
        (struct segment_command_64 *) ((void *) (buf + *header_offset));

    check(seg);
    check(buf);
    check(header_offset);
    check(data_offset);

    /* Write out the header */

    KXLD_3264_FUNC(is_32_bit, rval,
        seg_export_macho_header_32, seg_export_macho_header_64,
        seg, buf, header_offset, header_size, *data_offset);
    require_noerr(rval, finish);

    /* Write out each section */

    for (i = 0; i < seg->sects.nitems; ++i) {
        sect = get_sect_by_index(seg, i);

        rval = kxld_sect_export_macho_to_file_buffer(sect, buf, header_offset, 
            header_size, data_offset, data_size, is_32_bit);
        require_noerr(rval, finish);
    }

    /* Update the filesize */

    if (is_32_bit) {
        hdr32->filesize = (uint32_t) (*data_offset - base_data_offset);
    } else {
        hdr64->filesize = (uint64_t) (*data_offset - base_data_offset);
    }

    *data_offset = (u_long)kxld_round_page_cross_safe(*data_offset);

    rval = KERN_SUCCESS;

finish:
    return rval;

}


/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_export_macho_to_vm(const KXLDSeg *seg,
                            u_char *buf,
                            u_long *header_offset,
                            u_long header_size,
                            u_long data_size,
                            kxld_addr_t file_link_addr,
                            boolean_t is_32_bit)
{
    kern_return_t   rval = KERN_FAILURE;
    KXLDSect *      sect = NULL;
    
    // data_offset is used to set fileoff field in segment header
    u_long          data_offset;
    u_int           i = 0;

    check(seg);
    check(buf);
    check(header_offset);
    
    data_offset = (u_long) (seg->link_addr - file_link_addr);

    /* Write out the header */

   KXLD_3264_FUNC(is_32_bit, rval,
                  seg_export_macho_header_32, seg_export_macho_header_64,
                  seg,
                  buf,
                  header_offset, header_size, data_offset);
    require_noerr(rval, finish);

    /* Write out each section */

    for (i = 0; i < seg->sects.nitems; ++i) {
        sect = get_sect_by_index(seg, i);

        rval = kxld_sect_export_macho_to_vm(sect, buf, header_offset,
                                            header_size, file_link_addr, data_size, is_32_bit);
       require_noerr(rval, finish);
    }

    rval = KERN_SUCCESS;

finish:
    return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
seg_export_macho_header_32(const KXLDSeg *seg, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset)
{
    kern_return_t rval = KERN_FAILURE;
    struct segment_command *seghdr = NULL;

    check(seg);
    check(buf);
    check(header_offset);

    require_action(sizeof(*seghdr) <= header_size - *header_offset, finish,
        rval=KERN_FAILURE);
    seghdr = (struct segment_command *) ((void *) (buf + *header_offset));
    *header_offset += sizeof(*seghdr);

    seghdr->cmd = LC_SEGMENT;
    seghdr->cmdsize = (uint32_t) sizeof(*seghdr);
    seghdr->cmdsize += 
        (uint32_t) (seg->sects.nitems * kxld_sect_get_macho_header_size(TRUE));
    strlcpy(seghdr->segname, seg->segname, sizeof(seghdr->segname));
    seghdr->vmaddr = (uint32_t) seg->link_addr;
    seghdr->vmsize = (uint32_t) seg->vmsize;
    seghdr->fileoff = (uint32_t) data_offset;
    seghdr->filesize = (uint32_t) seg->vmsize;
    seghdr->maxprot = seg->maxprot;
    seghdr->initprot = seg->initprot;
    seghdr->nsects = seg->sects.nitems;
    seghdr->flags = 0;

#if SPLIT_KEXTS_DEBUG
    {
        kxld_log(kKxldLogLinking, kKxldLogErr,
                 "segname %s seghdr %p vmaddr %p vmsize 0x%02X %u fileoff 0x%02X %u <%s>",
                 seg->segname[0] ? seg->segname : "none",
                 (void *) seghdr,
                 (void *) ((uint64_t)seghdr->vmaddr),
                 seghdr->vmsize,
                 seghdr->vmsize,
                 seghdr->fileoff,
                 seghdr->fileoff,
                 __func__);
    }
#endif
    
    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64 
/*******************************************************************************
*******************************************************************************/
static kern_return_t
seg_export_macho_header_64(const KXLDSeg *seg, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset)
{
    kern_return_t rval = KERN_FAILURE;
    struct segment_command_64 *seghdr = NULL;

    check(seg);
    check(buf);
    check(header_offset);

    require_action(sizeof(*seghdr) <= header_size - *header_offset, finish,
        rval=KERN_FAILURE);
    
#if SPLIT_KEXTS_DEBUG
    {
        struct mach_header_64 *mach;
        
        mach = (struct mach_header_64 *) ((void *) buf);
        
        if (mach->magic != MH_MAGIC_64) {
            kxld_log(kKxldLogLinking, kKxldLogErr,
                     "bad macho header at %p <%s>",
                     (void *) mach, __func__);
            goto finish;
        }
    }
#endif
  
    seghdr = (struct segment_command_64 *) ((void *) (buf + *header_offset));
    *header_offset += sizeof(*seghdr);

    seghdr->cmd = LC_SEGMENT_64;
    seghdr->cmdsize = (uint32_t) sizeof(*seghdr);
    seghdr->cmdsize += 
        (uint32_t) (seg->sects.nitems * kxld_sect_get_macho_header_size(FALSE));
    strlcpy(seghdr->segname, seg->segname, sizeof(seghdr->segname));
    seghdr->vmaddr = (uint64_t) seg->link_addr;
    seghdr->vmsize = (uint64_t) seg->vmsize;
    seghdr->fileoff = (uint64_t) data_offset;
    seghdr->filesize = (uint64_t) seg->vmsize;
    seghdr->maxprot = seg->maxprot;
    seghdr->initprot = seg->initprot;
    seghdr->nsects = seg->sects.nitems;
    seghdr->flags = 0;

#if SPLIT_KEXTS_DEBUG
    {
        kxld_log(kKxldLogLinking, kKxldLogErr,
                 "%p >>> Start of %s seghdr (size %lu) <%s>",
                 (void *) seghdr,
                 seg->segname[0] ? seg->segname : "none",
                 sizeof(*seghdr),
                 __func__);
        kxld_log(kKxldLogLinking, kKxldLogErr,
                 "%p <<< End of %s seghdr <%s>",
                 (void *) ((u_char *)seghdr + sizeof(*seghdr)),
                 seg->segname[0] ? seg->segname : "none",
                 __func__);
        
        kxld_log(kKxldLogLinking, kKxldLogErr,
                 "%s seghdr, cmdsize %d vmaddr %p vmsize %p %llu fileoff %p %llu <%s>",
                 seg->segname[0] ? seg->segname : "none",
                 seghdr->cmdsize,
                 (void *) seghdr->vmaddr,
                 (void *) seghdr->vmsize,
                 seghdr->vmsize,
                 (void *) seghdr->fileoff,
                 seghdr->fileoff,
                 __func__);
    }
#endif

    rval = KERN_SUCCESS;

finish:
    return rval;
}
#endif /* KXLD_USER_OR_LP64 */

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_add_section(KXLDSeg *seg, KXLDSect *sect)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDSect **sectp = NULL;
    u_int i;

    check(seg);
    check(sect);
    require_action(streq_safe(seg->segname, sect->segname, sizeof(seg->segname)),
        finish, rval=KERN_FAILURE);
    
    /* Add the section into the section index */

    for (i = 0; i < seg->sects.nitems; ++i) {
        sectp = kxld_array_get_item(&seg->sects, i);
        if (NULL == *sectp) {
            *sectp = sect;
            break;
        }
    }
    require_action(i < seg->sects.nitems, finish, rval=KERN_FAILURE);

    rval = KERN_SUCCESS;

finish:

    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_seg_finish_init(KXLDSeg *seg)
{
    kern_return_t rval = KERN_FAILURE;
    u_int i = 0;
    KXLDSect *sect = NULL;
    kxld_addr_t maxaddr = 0;
    kxld_size_t maxsize = 0;

    /* If we already have a size for this segment (e.g. from the mach-o load
     * command) then don't recalculate the segment size. This is safer since 
     * when we recalculate we are making assumptions about page alignment and 
     * padding that the kext mach-o file was built with. Better to trust the 
     * macho-o info, if we have it. If we don't (i.e. vmsize == 0) then add up 
     * the section sizes and take a best guess at page padding.
     */
    if ((seg->vmsize == 0) && (seg->sects.nitems)) {
        for (i = 0; i < seg->sects.nitems; ++i) {
            sect = get_sect_by_index(seg, i);
            require_action(sect, finish, rval=KERN_FAILURE);
            if (sect->base_addr > maxaddr) {
                maxaddr = sect->base_addr;
                maxsize = sect->size;
            }
        }
        seg->vmsize = kxld_round_page_cross_safe(maxaddr +
                                                 maxsize - seg->base_addr);

    }

    rval = KERN_SUCCESS;
    
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_seg_set_vm_protections(KXLDSeg *seg, boolean_t strict_protections)
{
    if (strict_protections) {
        if (!strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname))) {
            seg->initprot = TEXT_SEG_PROT;
            seg->maxprot = TEXT_SEG_PROT;
        } else {
            seg->initprot = DATA_SEG_PROT;
            seg->maxprot = DATA_SEG_PROT;
        }
    } else {
        seg->initprot = VM_PROT_ALL;
        seg->maxprot = VM_PROT_ALL;
    }
}

/*******************************************************************************
*******************************************************************************/
void
kxld_seg_relocate(KXLDSeg *seg, kxld_addr_t link_addr)
{
    KXLDSect *sect = NULL;
    u_int i = 0;
    splitKextLinkInfo * link_info = (splitKextLinkInfo *) link_addr;
    kxld_addr_t         my_link_addr;
   
    if (isOldInterface) {
        seg->link_addr += link_addr;
    }
    else {
        if (isSplitKext) {
            // we have a split kext
            if (kxld_seg_is_text_seg(seg)) {
                // assumes this is the beginning of the kext
                my_link_addr = link_info->vmaddr_TEXT;
                seg->link_addr = my_link_addr;
            }
            else if (kxld_seg_is_text_exec_seg(seg)) {
                my_link_addr = link_info->vmaddr_TEXT_EXEC;
                seg->link_addr = my_link_addr;
                // vmaddr_TEXT_EXEC is the actual vmaddr for this segment so we need
                // to adjust for kxld_sect_relocate assuming the link addr is
                // the address of the kext (macho header in __TEXT)
                my_link_addr -= seg->base_addr;
            }
            else if (kxld_seg_is_data_seg(seg)) {
                my_link_addr = link_info->vmaddr_DATA;
                seg->link_addr = my_link_addr;
                // vmaddr_DATA is the actual vmaddr for this segment so we need
                // to adjust for kxld_sect_relocate assuming the link addr is
                // the address of the kext (macho header in __TEXT)
                my_link_addr -= seg->base_addr;
            }
            else if (kxld_seg_is_data_const_seg(seg)) {
                my_link_addr = link_info->vmaddr_DATA_CONST;
                seg->link_addr = my_link_addr;
                // vmaddr_DATA_CONST is the actual vmaddr for this segment so we need
                // to adjust for kxld_sect_relocate assuming the link addr is
                // the address of the kext (macho header in __TEXT)
                my_link_addr -= seg->base_addr;
            }
            else if (kxld_seg_is_linkedit_seg(seg)) {
                my_link_addr = link_info->vmaddr_LINKEDIT;
                seg->link_addr = my_link_addr;
                // vmaddr_DATA is the actual vmaddr for this segment so we need
                // to adjust for kxld_sect_relocate assuming the link addr is
                // the address of the kext (macho header in __TEXT)
                my_link_addr -= seg->base_addr;
            }
            else {
                kxld_log(kKxldLogLinking, kKxldLogErr,
                         " not expecting this segment %s!!! <%s>",
                         seg->segname[0] ? seg->segname : "none",
                         __func__);
                my_link_addr = link_info->vmaddr_TEXT;
                seg->link_addr += my_link_addr;
            }
        }
        else {
            my_link_addr = link_info->vmaddr_TEXT;
            seg->link_addr += my_link_addr;
        }
    }
    
#if SPLIT_KEXTS_DEBUG
    {
        kxld_log(kKxldLogLinking, kKxldLogErr,
                 "%p >>> Start of %s segment (vmsize %llu) <%s>)",
                 (void *) seg->link_addr,
                 seg->segname[0] ? seg->segname : "none",
                 seg->vmsize,
                 __func__);
        kxld_log(kKxldLogLinking, kKxldLogErr,
                 "%p <<< End of %s segment <%s>",
                 (void *) (seg->link_addr + seg->vmsize),
                 seg->segname[0] ? seg->segname : "none",
                 __func__);
    }
#endif
    
    for (i = 0; i < seg->sects.nitems; ++i) {
        sect = get_sect_by_index(seg, i);
        if (isOldInterface) {
            kxld_sect_relocate(sect, link_addr);
        }
        else {
            kxld_sect_relocate(sect, my_link_addr);
        }
    }
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_seg_populate_linkedit(KXLDSeg *seg, const KXLDSymtab *symtab, boolean_t is_32_bit 
#if KXLD_PIC_KEXTS
    , const KXLDArray *locrelocs
    , const KXLDArray *extrelocs
    , boolean_t target_supports_slideable_kexts
#endif  /* KXLD_PIC_KEXTS */
    , uint32_t splitinfolc_size
   )
{
    u_long size = 0;

    size += kxld_symtab_get_macho_data_size(symtab, is_32_bit);

#if KXLD_PIC_KEXTS
    if (target_supports_slideable_kexts) {
        size += kxld_reloc_get_macho_data_size(locrelocs, extrelocs);
    }
#endif	/* KXLD_PIC_KEXTS */

    // 0 unless this is a split kext
    size += splitinfolc_size;

    seg->vmsize = kxld_round_page_cross_safe(size);
}

/*******************************************************************************
 *******************************************************************************/
boolean_t
kxld_seg_is_split_seg(const KXLDSeg *seg)
{
    boolean_t       result = FALSE;
    
    check(seg);
    if (isSplitKext) {
        if (kxld_seg_is_data_seg(seg) || kxld_seg_is_linkedit_seg(seg) ||
            kxld_seg_is_text_exec_seg(seg) || kxld_seg_is_data_const_seg(seg)) {
            result = TRUE;
        }
    }
    
    return result;
}

boolean_t
kxld_seg_is_text_seg(const KXLDSeg *seg)
{
    boolean_t       result = FALSE;
    
    check(seg);
    result = !strncmp(seg->segname, SEG_TEXT, sizeof(seg->segname));
    
    return result;
}

boolean_t
kxld_seg_is_text_exec_seg(const KXLDSeg *seg)
{
    boolean_t       result = FALSE;
    
    check(seg);
    result = !strncmp(seg->segname, "__TEXT_EXEC", sizeof(seg->segname));
    
    return result;
}

boolean_t
kxld_seg_is_data_seg(const KXLDSeg *seg)
{
    boolean_t       result = FALSE;
    
    check(seg);
    result = !strncmp(seg->segname, SEG_DATA, sizeof(seg->segname));
    
    return result;
}

boolean_t
kxld_seg_is_data_const_seg(const KXLDSeg *seg)
{
    boolean_t       result = FALSE;
    
    check(seg);
    result = !strncmp(seg->segname, "__DATA_CONST", sizeof(seg->segname));
    
    return result;
}

boolean_t
kxld_seg_is_linkedit_seg(const KXLDSeg *seg)
{
    boolean_t       result = FALSE;
    
    check(seg);
    result = !strncmp(seg->segname, SEG_LINKEDIT, sizeof(seg->segname));
    
    return result;
}

