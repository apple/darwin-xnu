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
#include <mach-o/loader.h>
#include <mach-o/reloc.h>
#include <sys/types.h>

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_reloc.h"
#include "kxld_sect.h"
#include "kxld_seg.h"
#include "kxld_symtab.h"
#include "kxld_util.h"

static kern_return_t export_macho(const KXLDSect *sect, u_char *buf, u_long offset,
    u_long bufsize);
#if KXLD_USER_OR_ILP32
static kern_return_t sect_export_macho_header_32(const KXLDSect *sect, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset);
#endif
#if KXLD_USER_OR_LP64
static kern_return_t sect_export_macho_header_64(const KXLDSect *sect, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset);
#endif
extern boolean_t isSplitKext;

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sect_init_from_macho_32(KXLDSect *sect, u_char *macho, u_long *sect_offset,
    u_int sectnum, const KXLDRelocator *relocator)
{
	kern_return_t rval = KERN_FAILURE;
	struct section *src = (struct section *) ((void *) (macho + *sect_offset));
	struct relocation_info *relocs = NULL;

	check(sect);
	check(macho);
	check(src);

	strlcpy(sect->segname, src->segname, sizeof(sect->segname));
	strlcpy(sect->sectname, src->sectname, sizeof(sect->sectname));
	sect->base_addr = src->addr;
	sect->link_addr = src->addr;
	sect->size = src->size;
	sect->sectnum = sectnum;
	sect->flags = src->flags;
	sect->align = src->align;
	sect->reserved1 = src->reserved1;
	sect->reserved2 = src->reserved2;

	if (src->offset) {
		sect->data = macho + src->offset;
	} else {
		sect->data = NULL;
	}

	relocs = (struct relocation_info *) ((void *) (macho + src->reloff));

	rval = kxld_reloc_create_macho(&sect->relocs, relocator,
	    relocs, src->nreloc);
	require_noerr(rval, finish);

	*sect_offset += sizeof(*src);
	rval = KERN_SUCCESS;

finish:
	if (rval) {
		kxld_sect_deinit(sect);
	}

	return rval;
}
#endif /* KXLD_USER_OR_ILP32 */

#if KXLD_USER_OR_LP64
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sect_init_from_macho_64(KXLDSect *sect, u_char *macho, u_long *sect_offset,
    u_int sectnum, const KXLDRelocator *relocator)
{
	kern_return_t rval = KERN_FAILURE;
	struct section_64 *src = (struct section_64 *) ((void *) (macho + *sect_offset));
	struct relocation_info *relocs = NULL;

	check(sect);
	check(macho);
	check(src);

	strlcpy(sect->segname, src->segname, sizeof(sect->segname));
	strlcpy(sect->sectname, src->sectname, sizeof(sect->sectname));
	sect->base_addr = src->addr;
	sect->link_addr = src->addr;
	sect->size = src->size;
	sect->sectnum = sectnum;
	sect->flags = src->flags;
	sect->align = src->align;
	sect->reserved1 = src->reserved1;
	sect->reserved2 = src->reserved2;

	if (src->offset) {
		sect->data = macho + src->offset;
	} else {
		sect->data = NULL;
	}

	relocs = (struct relocation_info *) ((void *) (macho + src->reloff));

	rval = kxld_reloc_create_macho(&sect->relocs, relocator,
	    relocs, src->nreloc);
	require_noerr(rval, finish);

	*sect_offset += sizeof(*src);
	rval = KERN_SUCCESS;

finish:
	if (rval) {
		kxld_sect_deinit(sect);
	}

	return rval;
}
#endif /* KXLD_USER_OR_LP64 */

#if KXLD_USER_OR_GOT
/*******************************************************************************
* Assumes GOT is comprised of kxld_addr_t entries
*******************************************************************************/
kern_return_t
kxld_sect_init_got(KXLDSect *sect, u_int ngots)
{
	kern_return_t rval = KERN_FAILURE;

	check(sect);

	strlcpy(sect->segname, KXLD_SEG_GOT, sizeof(sect->segname));
	strlcpy(sect->sectname, KXLD_SECT_GOT, sizeof(sect->sectname));
	sect->base_addr = 0;
	sect->link_addr = 0;
	sect->flags = 0;
	sect->align = 4;
	sect->reserved1 = 0;
	sect->reserved2 = 0;

	sect->size = ngots * sizeof(kxld_addr_t);
	sect->data = kxld_alloc((u_long) sect->size);
	require_action(sect->data, finish, rval = KERN_RESOURCE_SHORTAGE);

	sect->allocated = TRUE;

	rval = KERN_SUCCESS;

finish:
	return rval;
}
#endif /* KXLD_USER_OR_GOT */

#if KXLD_USER_OR_COMMON
/*******************************************************************************
*******************************************************************************/
void
kxld_sect_init_zerofill(KXLDSect *sect, const char *segname,
    const char *sectname, kxld_size_t size, u_int align)
{
	check(sect);
	check(segname);
	check(sectname);

	strlcpy(sect->segname, segname, sizeof(sect->segname));
	strlcpy(sect->sectname, sectname, sizeof(sect->sectname));
	sect->size = size;
	sect->align = align;
	sect->base_addr = 0;
	sect->link_addr = 0;
	sect->flags = S_ZEROFILL;
}
#endif /* KXLD_USER_OR_COMMON */

/*******************************************************************************
*******************************************************************************/
void
kxld_sect_clear(KXLDSect *sect)
{
	check(sect);

	if (sect->allocated) {
		kxld_free(sect->data, (u_long) sect->size);
		sect->allocated = FALSE;
	}

	bzero(sect->sectname, sizeof(sect->sectname));
	bzero(sect->segname, sizeof(sect->segname));
	sect->data = NULL;
	sect->base_addr = 0;
	sect->link_addr = 0;
	sect->size = 0;
	sect->flags = 0;
	sect->align = 0;
	sect->reserved1 = 0;
	sect->reserved2 = 0;
	kxld_array_clear(&sect->relocs);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_sect_deinit(KXLDSect *sect)
{
	check(sect);

	if (streq_safe(sect->sectname, KXLD_SECT_GOT, sizeof(KXLD_SECT_GOT))) {
		kxld_free(sect->data, (u_long) sect->size);
	}

	kxld_array_deinit(&sect->relocs);
	bzero(sect, sizeof(*sect));
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_sect_get_num_relocs(const KXLDSect *sect)
{
	check(sect);

	return sect->relocs.nitems;
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_sect_get_macho_header_size(boolean_t is_32_bit)
{
	if (is_32_bit) {
		return sizeof(struct section);
	} else {
		return sizeof(struct section_64);
	}
}

/*******************************************************************************
*******************************************************************************/
u_long
kxld_sect_get_macho_data_size(const KXLDSect *sect)
{
	u_long size = 0;

	check(sect);

	if (sect->data) {
		size = (u_long) sect->size;
	}

	return size;
}

#if KXLD_USER_OR_GOT
/*******************************************************************************
*******************************************************************************/
u_int
kxld_sect_get_ngots(const KXLDSect *sect, const KXLDRelocator *relocator,
    const KXLDSymtab *symtab)
{
	const KXLDReloc *reloc = NULL;
	KXLDSym *sym = NULL;
	u_int ngots = 0;
	u_int i = 0;

	for (i = 0; i < sect->relocs.nitems; ++i) {
		reloc = kxld_array_get_item(&sect->relocs, i);

		if (relocator->reloc_has_got(reloc->reloc_type)) {
			/* @TODO This assumes 64-bit symbols (which is valid at the
			 * moment since only x86_64 has a GOT)
			 */
			sym = kxld_reloc_get_symbol(relocator, reloc, sect->data, symtab);
			if (!kxld_sym_is_got(sym)) {
				kxld_sym_set_got(sym);
				++ngots;
			}
		}
	}

	return ngots;
}
#endif /* KXLD_USER_OR_GOT */

/*******************************************************************************
* Each section must be aligned at a certain power of two.  To figure out that
* alignment, we mask for the low bits that may need to be adjusted.  If they are
* non zero, we then subtract them from the target alignment to find the offset,
* and then add that offset to the link address.
*******************************************************************************/
kxld_addr_t
kxld_sect_align_address(const KXLDSect *sect, kxld_addr_t address)
{
	return kxld_align_address(address, sect->align);
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sect_export_macho_to_file_buffer(const KXLDSect *sect, u_char *buf,
    u_long *header_offset, u_long header_size, u_long *data_offset,
    u_long data_size, boolean_t is_32_bit __unused)
{
	kern_return_t rval = KERN_FAILURE;

	check(sect);
	check(buf);
	check(header_offset);
	check(data_offset);

	/* If there is no data to export, we only need to write the header.  We
	 * make it a separate call so that we don't modify data_offset.
	 */
	if (!sect->data) {
		KXLD_3264_FUNC(is_32_bit, rval,
		    sect_export_macho_header_32, sect_export_macho_header_64,
		    sect, buf, header_offset, header_size, /* data_offset */ 0);
		require_noerr(rval, finish);
	} else {
		*data_offset = (u_long) kxld_sect_align_address(sect, *data_offset);

		KXLD_3264_FUNC(is_32_bit, rval,
		    sect_export_macho_header_32, sect_export_macho_header_64,
		    sect, buf, header_offset, header_size, *data_offset);
		require_noerr(rval, finish);

		rval = export_macho(sect, buf, *data_offset, data_size);
		require_noerr(rval, finish);

		*data_offset += (u_long) sect->size;
	}
	rval = KERN_SUCCESS;

finish:
	return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sect_export_macho_to_vm(const KXLDSect *sect,
    u_char *buf,
    u_long *header_offset,
    u_long header_size,
    kxld_addr_t link_addr,
    u_long data_size,
    boolean_t is_32_bit __unused)
{
	kern_return_t rval = KERN_FAILURE;
	u_long data_offset;

	check(sect);
	check(buf);
	check(header_offset);

	data_offset = (u_long) (sect->link_addr - link_addr);

	KXLD_3264_FUNC(is_32_bit, rval,
	    sect_export_macho_header_32, sect_export_macho_header_64,
	    sect, buf, header_offset, header_size, data_offset);
	require_noerr(rval, finish);

	rval = export_macho(sect, buf, data_offset, data_size);
	require_noerr(rval, finish);

	rval = KERN_SUCCESS;

finish:
	return rval;
}

/*******************************************************************************
*******************************************************************************/
static kern_return_t
export_macho(const KXLDSect *sect, u_char *buf, u_long offset, u_long bufsize)
{
	kern_return_t rval = KERN_FAILURE;

	check(sect);
	check(buf);

	if (!sect->data) {
		rval = KERN_SUCCESS;
		goto finish;
	}

	if (!isSplitKext) {
		/* Verify that the section is properly aligned */
		if (kxld_sect_align_address(sect, offset) != offset) {
			kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
			    "Alignment error: %llu != %lu for %s %s <%s>",
			    kxld_sect_align_address(sect, offset), offset,
			    sect->segname, sect->sectname, __func__);
			goto finish;
		}
	}

	/* Verify that we have enough space to copy */
	if (buf + offset + sect->size > buf + bufsize) {
		kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
		    "Overflow: offset %lu + sect->size %llu > bufsize %lu for %s %s",
		    offset, sect->size, bufsize,
		    sect->segname, sect->sectname);
		goto finish;
	}

	/* Copy section data */
	switch (sect->flags & SECTION_TYPE) {
	case S_NON_LAZY_SYMBOL_POINTERS:
	case S_MOD_INIT_FUNC_POINTERS:
	case S_MOD_TERM_FUNC_POINTERS:
	case S_REGULAR:
	case S_CSTRING_LITERALS:
	case S_4BYTE_LITERALS:
	case S_8BYTE_LITERALS:
	case S_LITERAL_POINTERS:
	case S_COALESCED:
	case S_16BYTE_LITERALS:
	case S_SYMBOL_STUBS:
#if SPLIT_KEXTS_DEBUG
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    " sectname %s copy from %p (sect->data) for %llu bytes (sect->size) to %p (buf %p + offset %lu <%s>",
		    sect->sectname[0] ? sect->sectname : "none",
		    (void *) sect->data,
		    sect->size,
		    (void *) (buf + offset),
		    (void *) buf,
		    offset,
		    __func__);

		kxld_log(kKxldLogLinking, kKxldLogErr,
		    " %p >>> Start of %s section data (sect->size %llu) <%s>",
		    (void *) (buf + offset),
		    sect->sectname[0] ? sect->sectname : "none",
		    sect->size,
		    __func__);
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    " %p <<< End of %s section data <%s>",
		    (void *) (buf + offset + sect->size),
		    sect->sectname[0] ? sect->sectname : "none",
		    __func__);
#endif
		memcpy(buf + offset, sect->data, (size_t)sect->size);
		break;
	case S_ZEROFILL: /* sect->data should be NULL, so we'll never get here */
	case S_LAZY_SYMBOL_POINTERS:
	case S_GB_ZEROFILL:
	case S_INTERPOSING:
	case S_DTRACE_DOF:
	default:
		rval = KERN_FAILURE;
		kxld_log(kKxldLogLinking, kKxldLogErr, kKxldLogMalformedMachO
		    "Invalid section type: %u.", sect->flags & SECTION_TYPE);
		goto finish;
	}

	rval = KERN_SUCCESS;

finish:
	return rval;
}

#if KXLD_USER_OR_ILP32
/*******************************************************************************
*******************************************************************************/
static kern_return_t
sect_export_macho_header_32(const KXLDSect *sect, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset)
{
	kern_return_t rval = KERN_FAILURE;
	struct section *secthdr = NULL;

	check(sect);
	check(buf);
	check(header_offset);

	require_action(sizeof(*secthdr) <= header_size - *header_offset, finish,
	    rval = KERN_FAILURE);
	secthdr = (struct section *) ((void *) (buf + *header_offset));
	*header_offset += sizeof(*secthdr);

	/* Initalize header */

	strlcpy(secthdr->sectname, sect->sectname, sizeof(secthdr->sectname));
	strlcpy(secthdr->segname, sect->segname, sizeof(secthdr->segname));
	secthdr->addr = (uint32_t) sect->link_addr;
	secthdr->size = (uint32_t) sect->size;
	secthdr->offset = (uint32_t) ((sect->data) ? data_offset : 0);
	secthdr->align = sect->align;
	secthdr->reloff = 0;
	secthdr->nreloc = 0;
	secthdr->flags = sect->flags;
	secthdr->reserved1 = sect->reserved1;
	secthdr->reserved2 = sect->reserved2;

#if SPLIT_KEXTS_DEBUG
	{
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    "sectname %s secthdr: %p addr %p size %02X %u offset %02X %u <%s>",
		    sect->sectname[0] ? sect->sectname : "none",
		    (void *) secthdr,
		    (void *) ((uint64_t)secthdr->addr),
		    secthdr->size,
		    secthdr->size,
		    secthdr->offset,
		    secthdr->offset,
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
sect_export_macho_header_64(const KXLDSect *sect, u_char *buf,
    u_long *header_offset, u_long header_size, u_long data_offset)
{
	kern_return_t rval = KERN_FAILURE;
	struct section_64 *secthdr = NULL;

	check(sect);
	check(buf);
	check(header_offset);


	require_action(sizeof(*secthdr) <= header_size - *header_offset, finish,
	    rval = KERN_FAILURE);
	secthdr = (struct section_64 *) ((void *) (buf + *header_offset));
	*header_offset += sizeof(*secthdr);

	/* Initalize header */

	strlcpy(secthdr->sectname, sect->sectname, sizeof(secthdr->sectname));
	strlcpy(secthdr->segname, sect->segname, sizeof(secthdr->segname));
	secthdr->addr = (uint64_t) sect->link_addr;
	secthdr->size = (uint64_t) sect->size;
	secthdr->offset = (uint32_t) ((sect->data) ? data_offset : 0);
	secthdr->align = sect->align;
	secthdr->reloff = 0;
	secthdr->nreloc = 0;
	secthdr->flags = sect->flags;
	secthdr->reserved1 = sect->reserved1;
	secthdr->reserved2 = sect->reserved2;

#if SPLIT_KEXTS_DEBUG
	kxld_log(kKxldLogLinking, kKxldLogErr,
	    " %p >>> Start of %s secthdr (size %lu) <%s>",
	    (void *) secthdr,
	    sect->sectname[0] ? sect->sectname : "none",
	    sizeof(*secthdr),
	    __func__);
	kxld_log(kKxldLogLinking, kKxldLogErr,
	    " %p <<< End of %s secthdr <%s>",
	    (void *) ((u_char *)secthdr + sizeof(*secthdr)),
	    sect->sectname[0] ? sect->sectname : "none",
	    __func__);
	kxld_log(kKxldLogLinking, kKxldLogErr,
	    " secthdr: addr %p size %llu offset %u sectname %s <%s>",
	    (void *) secthdr->addr,
	    secthdr->size,
	    secthdr->offset,
	    sect->sectname[0] ? sect->sectname : "none",
	    __func__);
#endif

	rval = KERN_SUCCESS;

finish:
	return rval;
}
#endif /* KXLD_USER_OR_LP64 */

#if KXLD_USER_OR_COMMON
/*******************************************************************************
*******************************************************************************/
kxld_size_t
kxld_sect_grow(KXLDSect *sect, kxld_size_t nbytes, u_int align)
{
	kxld_size_t size = kxld_align_address(sect->size, align);

	if (align > sect->align) {
		sect->align = align;
	}
	sect->size = size + nbytes;

	return size;
}
#endif /* KXLD_USER_OR_COMMON */

/*******************************************************************************
*******************************************************************************/
void
kxld_sect_relocate(KXLDSect *sect, kxld_addr_t link_addr)
{
#if SPLIT_KEXTS_DEBUG
	{
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    "%p >>> Start of %s section (sect->size %llu) <%s>",
		    (void *) (kxld_sect_align_address(sect, sect->link_addr + link_addr)),
		    sect->sectname[0] ? sect->sectname : "none",
		    sect->size,
		    __func__);
		kxld_log(kKxldLogLinking, kKxldLogErr,
		    "%p <<< End of %s section <%s>",
		    (void *) (kxld_sect_align_address(sect, sect->link_addr + link_addr) + sect->size),
		    sect->sectname[0] ? sect->sectname : "none",
		    __func__);
	}
#endif

	sect->link_addr = kxld_sect_align_address(sect,
	    sect->link_addr + link_addr);
}

#if KXLD_USER_OR_GOT
/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sect_populate_got(KXLDSect *sect, KXLDSymtab *symtab,
    boolean_t swap __unused)
{
	kern_return_t rval = KERN_FAILURE;
	KXLDSymtabIterator iter;
	KXLDSym *sym = NULL;
	kxld_addr_t *entry = NULL;
	kxld_addr_t entry_addr = 0;

	check(sect);
	check(symtab);
	require(streq_safe(sect->segname, KXLD_SEG_GOT, sizeof(KXLD_SEG_GOT)),
	    finish);
	require(streq_safe(sect->sectname, KXLD_SECT_GOT, sizeof(KXLD_SECT_GOT)),
	    finish);

	kxld_symtab_iterator_init(&iter, symtab, kxld_sym_is_got, FALSE);

	entry = (kxld_addr_t *) sect->data;
	entry_addr = sect->link_addr;
	while ((sym = kxld_symtab_iterator_get_next(&iter))) {
		*entry = sym->link_addr;
		sym->got_addr = entry_addr;

#if !KERNEL
		if (swap) {
			*entry = OSSwapInt64(*entry);
		}
#endif /* !KERNEL */

		++entry;
		entry_addr += sizeof(*entry);
	}

	rval = KERN_SUCCESS;

finish:
	return rval;
}
#endif /* KXLD_USER_OR_GOT */

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_sect_process_relocs(KXLDSect *sect, KXLDRelocator *relocator)
{
	kern_return_t rval = KERN_FAILURE;
	KXLDReloc *reloc = NULL;
	u_int i = 0;

	for (i = 0; i < sect->relocs.nitems; ++i) {
		reloc = kxld_array_get_item(&sect->relocs, i);
		rval = kxld_relocator_process_sect_reloc(relocator, reloc, sect);
		require_noerr(rval, finish);
	}

	rval = KERN_SUCCESS;
finish:
	return rval;
}
