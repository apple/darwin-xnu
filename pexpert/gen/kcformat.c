/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */

#include <pexpert/pexpert.h>
#include <libkern/section_keywords.h>
#include <libkern/kernel_mach_header.h>

vm_offset_t kc_highest_nonlinkedit_vmaddr = 0;
int vnode_put(void *vp);

// FIXME: should come from mach-o/fixup_chains.h
// Index in basePointers array used by chained rebase in dyld_kernel_fixups.h
typedef enum kc_index {
	primary_kc_index = 0,
	pageable_kc_index = 1,
	auxiliary_kc_index = 3,
} kc_index_t;

#if defined(__x86_64__) || defined(__i386__)
/* FIXME: This should be locked down during early boot */
void *collection_base_pointers[KCNumKinds] = {};
kernel_mach_header_t * collection_mach_headers[KCNumKinds] = {};
uintptr_t collection_slide[KCNumKinds] = {};
void * collection_vp[KCNumKinds] = {};
#else

SECURITY_READ_ONLY_LATE(void *) collection_base_pointers[KCNumKinds];
SECURITY_READ_ONLY_LATE(kernel_mach_header_t *) collection_mach_headers[KCNumKinds];
SECURITY_READ_ONLY_LATE(uintptr_t) collection_slide[KCNumKinds];
SECURITY_READ_ONLY_LATE(void *) collection_vp[KCNumKinds];
#endif //(__x86_64__) || defined(__i386__)

static inline kc_index_t
kc_kind2index(kc_kind_t type)
{
	switch (type) {
	case KCKindPrimary:
		return primary_kc_index;
	case KCKindPageable:
		return pageable_kc_index;
	case KCKindAuxiliary:
		return auxiliary_kc_index;
	default:
		panic("Invalid KC Kind");
		break;
	}
	__builtin_unreachable();
}

void
PE_set_kc_header(kc_kind_t type, kernel_mach_header_t *header, uintptr_t slide)
{
	kc_index_t i = kc_kind2index(type);
	assert(!collection_base_pointers[i]);
	assert(!collection_mach_headers[i]);
	collection_mach_headers[i] = header;
	collection_slide[i] = slide;

	struct load_command *lc;
	struct segment_command_64 *seg;
	uint64_t lowest_vmaddr = ~0ULL;

	lc = (struct load_command *)((uintptr_t)header + sizeof(*header));
	for (uint32_t j = 0; j < header->ncmds; j++,
	    lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
		if (lc->cmd != LC_SEGMENT_64) {
			continue;
		}
		seg = (struct segment_command_64 *)(uintptr_t)lc;
		if (seg->vmaddr < lowest_vmaddr) {
			lowest_vmaddr = seg->vmaddr;
		}
	}

	collection_base_pointers[i] = (void *)(uintptr_t)lowest_vmaddr + slide;
	assert((uint64_t)(uintptr_t)collection_base_pointers[i] != ~0ULL);
}

void
PE_reset_kc_header(kc_kind_t type)
{
	if (type == KCKindPrimary) {
		return;
	}

	kc_index_t i = kc_kind2index(type);
	collection_mach_headers[i] = 0;
	collection_base_pointers[i] = 0;
	collection_slide[i] = 0;
}

void
PE_set_kc_header_and_base(kc_kind_t type, kernel_mach_header_t * header, void *base, uintptr_t slide)
{
	kc_index_t i = kc_kind2index(type);
	assert(!collection_base_pointers[i]);
	assert(!collection_mach_headers[i]);
	collection_mach_headers[i] = header;
	collection_slide[i] = slide;
	collection_base_pointers[i] = base;
}

void *
PE_get_kc_header(kc_kind_t type)
{
	return collection_mach_headers[kc_kind2index(type)];
}

void
PE_set_kc_vp(kc_kind_t type, void *vp)
{
	kc_index_t i = kc_kind2index(type);
	assert(collection_vp[i] == NULL);

	collection_vp[i] = vp;
}

void *
PE_get_kc_vp(kc_kind_t type)
{
	kc_index_t i = kc_kind2index(type);
	return collection_vp[i];
}

void
PE_reset_all_kc_vp(void)
{
	for (int i = 0; i < KCNumKinds; i++) {
		if (collection_vp[i] != NULL) {
			vnode_put(collection_vp[i]);
			collection_vp[i] = NULL;
		}
	}
}

const void * const *
PE_get_kc_base_pointers(void)
{
	return (const void * const*)collection_base_pointers;
}

/*
 * Prelinked kexts in an MH_FILESET start with address 0,
 * the slide for such kexts is calculated from the base
 * address of the first kext mapped in that KC. Return the
 * slide based on the type of the KC.
 *
 * Prelinked kexts booted from a non MH_FILESET KC are
 * marked as KCKindUnknown, for such cases, return
 * the kernel slide.
 */
uintptr_t
PE_get_kc_slide(kc_kind_t type)
{
	if (type == KCKindUnknown) {
		return vm_kernel_slide;
	}
	return collection_slide[kc_kind2index(type)];
}

bool
PE_get_primary_kc_format(kc_format_t *type)
{
	if (type != NULL) {
		kernel_mach_header_t *mh = PE_get_kc_header(KCKindPrimary);
		if (mh && mh->filetype == MH_FILESET) {
			*type = KCFormatFileset;
		} else {
#if defined(__arm__) || defined(__arm64__)
			/* From osfmk/arm/arm_init.c */
			extern bool static_kernelcache;
			if (static_kernelcache) {
				*type = KCFormatStatic;
			} else {
				*type = KCFormatKCGEN;
			}
#else
			*type = KCFormatDynamic;
#endif
		}
	}
	return true;
}

void *
PE_get_kc_baseaddress(kc_kind_t type)
{
	kc_index_t i = kc_kind2index(type);
	switch (type) {
#if defined(__arm__) || defined(__arm64__)
	case KCKindPrimary: {
		extern vm_offset_t segLOWESTTEXT;
		return (void*)segLOWESTTEXT;
	}
#endif
	default:
		return collection_base_pointers[i];
	}
	return NULL;
}
