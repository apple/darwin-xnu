/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
 * This file contains static dyld helper functions for
 * exclusive use in platform startup code.
 */

#include <mach-o/fixup-chains.h>
#include <mach-o/loader.h>

#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#endif /* defined(HAS_APPLE_PAC) */

#ifndef dyldLogFunc
#define dyldLogFunc(msg, ...) kprintf(msg, ## __VA_ARGS__)
#endif

#if 0
#define dyldLogFunc(msg, ...) ({int _wait = 0; do { asm volatile ("yield" : "+r"(_wait) : ); } while(!_wait); })
#endif
#define LogFixups 0

// cannot safely callout out to functions like strcmp before initial fixup
static inline int
strings_are_equal(const char* a, const char* b)
{
	while (*a && *b) {
		if (*a != *b) {
			return 0;
		}
		++a;
		++b;
	}
	return *a == *b;
}

/*
 * Functions from dyld to rebase, fixup and sign the contents of MH_FILESET
 * kernel collections.
 */

union ChainedFixupPointerOnDisk {
	uint64_t raw64;
	struct dyld_chained_ptr_64_kernel_cache_rebase fixup64;
};

static uint64_t __unused
sign_pointer(struct dyld_chained_ptr_64_kernel_cache_rebase pointer __unused,
    void *loc __unused,
    uint64_t target __unused)
{
#if HAS_APPLE_PAC
	uint64_t discriminator = pointer.diversity;
	if (pointer.addrDiv) {
		if (discriminator) {
			discriminator = __builtin_ptrauth_blend_discriminator(loc, discriminator);
		} else {
			discriminator = (uint64_t)(uintptr_t)loc;
		}
	}
	switch (pointer.key) {
	case 0:         // IA
		return (uint64_t)__builtin_ptrauth_sign_unauthenticated((void*)target, 0, discriminator);
	case 1:         // IB
		return (uint64_t)__builtin_ptrauth_sign_unauthenticated((void*)target, 1, discriminator);
	case 2:         // DA
		return (uint64_t)__builtin_ptrauth_sign_unauthenticated((void*)target, 2, discriminator);
	case 3:         // DB
		return (uint64_t)__builtin_ptrauth_sign_unauthenticated((void*)target, 3, discriminator);
	}
#endif
	return target;
}

static inline __attribute__((__always_inline__)) void
fixup_value(union ChainedFixupPointerOnDisk* fixupLoc __unused,
    const struct dyld_chained_starts_in_segment* segInfo,
    uintptr_t slide __unused,
    const void* basePointers[KCNumKinds] __unused,
    int* stop)
{
	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: fixup_value %p\n", fixupLoc);
	}
	switch (segInfo->pointer_format) {
#if __LP64__
	case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
	case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: {
		const void* baseAddress = basePointers[fixupLoc->fixup64.cacheLevel];
		if (baseAddress == 0) {
			dyldLogFunc("Invalid cache level: %d\n", fixupLoc->fixup64.cacheLevel);
			*stop = 1;
			return;
		}
		uintptr_t slidValue = (uintptr_t)baseAddress + fixupLoc->fixup64.target;
		if (LogFixups) {
			dyldLogFunc("[LOG] kernel-fixups: slidValue %p (base=%p, target=%p)\n", (void*)slidValue,
			    (const void *)baseAddress, (void *)(uintptr_t)fixupLoc->fixup64.target);
		}
#if HAS_APPLE_PAC
		if (fixupLoc->fixup64.isAuth) {
			slidValue = sign_pointer(fixupLoc->fixup64, fixupLoc, slidValue);
		}
#else
		if (fixupLoc->fixup64.isAuth) {
			dyldLogFunc("Unexpected authenticated fixup\n");
			*stop = 1;
			return;
		}
#endif // HAS_APPLE_PAC
		fixupLoc->raw64 = slidValue;
		break;
	}
#endif // __LP64__
	default:
		dyldLogFunc("unsupported pointer chain format: 0x%04X", segInfo->pointer_format);
		*stop = 1;
		break;
	}
}

static inline __attribute__((__always_inline__)) int
walk_chain(const struct mach_header_64* mh,
    const struct dyld_chained_starts_in_segment* segInfo,
    uint32_t pageIndex,
    uint16_t offsetInPage,
    uintptr_t slide __unused,
    const void* basePointers[KCNumKinds])
{
	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: walk_chain page[%d]\n", pageIndex);
	}
	int                        stop = 0;
	uintptr_t                   pageContentStart = (uintptr_t)mh + (uintptr_t)segInfo->segment_offset
	    + (pageIndex * segInfo->page_size);
	union ChainedFixupPointerOnDisk* chain = (union ChainedFixupPointerOnDisk*)(pageContentStart + offsetInPage);
	int                       chainEnd = 0;
	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: segInfo->segment_offset 0x%llx\n", segInfo->segment_offset);
		dyldLogFunc("[LOG] kernel-fixups: segInfo->segment_pagesize %d\n", segInfo->page_size);
		dyldLogFunc("[LOG] kernel-fixups: segInfo pointer format %d\n", segInfo->pointer_format);
	}
	while (!stop && !chainEnd) {
		// copy chain content, in case handler modifies location to final value
		if (LogFixups) {
			dyldLogFunc("[LOG] kernel-fixups: value of chain %p", chain);
		}
		union ChainedFixupPointerOnDisk chainContent __unused = *chain;
		fixup_value(chain, segInfo, slide, basePointers, &stop);
		if (!stop) {
			switch (segInfo->pointer_format) {
#if __LP64__
			case DYLD_CHAINED_PTR_64_KERNEL_CACHE:
				if (chainContent.fixup64.next == 0) {
					chainEnd = 1;
				} else {
					if (LogFixups) {
						dyldLogFunc("[LOG] kernel-fixups: chainContent fixup 64.next %d\n", chainContent.fixup64.next);
					}
					chain = (union ChainedFixupPointerOnDisk*)((uintptr_t)chain + chainContent.fixup64.next * 4);
				}
				break;
			case DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE:
				if (chainContent.fixup64.next == 0) {
					chainEnd = 1;
				} else {
					if (LogFixups) {
						dyldLogFunc("[LOG] kernel-fixups: chainContent fixup x86 64.next %d\n", chainContent.fixup64.next);
					}
					chain = (union ChainedFixupPointerOnDisk*)((uintptr_t)chain + chainContent.fixup64.next);
				}
				break;
#endif // __LP64__
			default:
				dyldLogFunc("unknown pointer format 0x%04X", segInfo->pointer_format);
				stop = 1;
			}
		}
	}
	return stop;
}

static inline __attribute__((__always_inline__)) int
kernel_collection_slide(const struct mach_header_64* mh, const void* basePointers[KCNumKinds])
{
	// First find the slide and chained fixups load command
	uint64_t textVMAddr     = 0;
	const struct linkedit_data_command* chainedFixups = 0;
	uint64_t linkeditVMAddr         = 0;
	uint64_t linkeditFileOffset = 0;

	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: parsing load commands\n");
	}

	const struct load_command* startCmds = 0;
	if (mh->magic == MH_MAGIC_64) {
		startCmds = (struct load_command*)((uintptr_t)mh + sizeof(struct mach_header_64));
	} else if (mh->magic == MH_MAGIC) {
		startCmds = (struct load_command*)((uintptr_t)mh + sizeof(struct mach_header));
	} else {
		//const uint32_t* h = (uint32_t*)mh;
		//diag.error("file does not start with MH_MAGIC[_64]: 0x%08X 0x%08X", h[0], h [1]);
		return 1;  // not a mach-o file
	}
	const struct load_command* const cmdsEnd = (struct load_command*)((uintptr_t)startCmds + mh->sizeofcmds);
	const struct load_command* cmd = startCmds;
	for (uint32_t i = 0; i < mh->ncmds; ++i) {
		if (LogFixups) {
			dyldLogFunc("[LOG] kernel-fixups: parsing load command %d with cmd=0x%x\n", i, cmd->cmd);
		}
		const struct load_command* nextCmd = (struct load_command*)((uintptr_t)cmd + cmd->cmdsize);
		if (cmd->cmdsize < 8) {
			//diag.error("malformed load command #%d of %d at %p with mh=%p, size (0x%X) too small", i, this->ncmds, cmd, this, cmd->cmdsize);
			return 1;
		}
		if ((nextCmd > cmdsEnd) || (nextCmd < startCmds)) {
			//diag.error("malformed load command #%d of %d at %p with mh=%p, size (0x%X) is too large, load commands end at %p", i, this->ncmds, cmd, this, cmd->cmdsize, cmdsEnd);
			return 1;
		}
		if (cmd->cmd == LC_DYLD_CHAINED_FIXUPS) {
			chainedFixups = (const struct linkedit_data_command*)cmd;
		} else if (cmd->cmd == LC_SEGMENT_64) {
			const struct segment_command_64* seg = (const struct segment_command_64*)(uintptr_t)cmd;

			if (LogFixups) {
				dyldLogFunc("[LOG] kernel-fixups: segment name vm start and size: %s 0x%llx 0x%llx\n",
				    seg->segname, seg->vmaddr, seg->vmsize);
			}
			if (strings_are_equal(seg->segname, "__TEXT")) {
				textVMAddr = seg->vmaddr;
			} else if (strings_are_equal(seg->segname, "__LINKEDIT")) {
				linkeditVMAddr = seg->vmaddr;
				linkeditFileOffset = seg->fileoff;
			}
		}
		cmd = nextCmd;
	}

	uintptr_t slide = (uintptr_t)mh - (uintptr_t)textVMAddr;

	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: slide %lx\n", slide);
	}

	if (chainedFixups == 0) {
		return 0;
	}

	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: found chained fixups %p\n", chainedFixups);
		dyldLogFunc("[LOG] kernel-fixups: found linkeditVMAddr %p\n", (void*)linkeditVMAddr);
		dyldLogFunc("[LOG] kernel-fixups: found linkeditFileOffset %p\n", (void*)linkeditFileOffset);
	}

	// Now we have the chained fixups, walk it to apply all the rebases
	uint64_t offsetInLinkedit   = chainedFixups->dataoff - linkeditFileOffset;
	uintptr_t linkeditStartAddr = (uintptr_t)linkeditVMAddr + slide;
	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: offsetInLinkedit %llx\n", offsetInLinkedit);
		dyldLogFunc("[LOG] kernel-fixups: linkeditStartAddr %p\n", (void*)linkeditStartAddr);
	}

	const struct dyld_chained_fixups_header* fixupsHeader = (const struct dyld_chained_fixups_header*)(linkeditStartAddr + offsetInLinkedit);
	const struct dyld_chained_starts_in_image* fixupStarts = (const struct dyld_chained_starts_in_image*)((uintptr_t)fixupsHeader + fixupsHeader->starts_offset);
	if (LogFixups) {
		dyldLogFunc("[LOG] kernel-fixups: fixupsHeader %p\n", fixupsHeader);
		dyldLogFunc("[LOG] kernel-fixups: fixupStarts %p\n", fixupStarts);
	}

	int stopped = 0;
	for (uint32_t segIndex = 0; segIndex < fixupStarts->seg_count && !stopped; ++segIndex) {
		if (LogFixups) {
			dyldLogFunc("[LOG] kernel-fixups: segment %d\n", segIndex);
		}
		if (fixupStarts->seg_info_offset[segIndex] == 0) {
			continue;
		}
		const struct dyld_chained_starts_in_segment* segInfo = (const struct dyld_chained_starts_in_segment*)((uintptr_t)fixupStarts + fixupStarts->seg_info_offset[segIndex]);
		for (uint32_t pageIndex = 0; pageIndex < segInfo->page_count && !stopped; ++pageIndex) {
			uint16_t offsetInPage = segInfo->page_start[pageIndex];
			if (offsetInPage == DYLD_CHAINED_PTR_START_NONE) {
				continue;
			}
			if (offsetInPage & DYLD_CHAINED_PTR_START_MULTI) {
				// FIXME: Implement this
				return 1;
			} else {
				// one chain per page
				if (walk_chain(mh, segInfo, pageIndex, offsetInPage, slide, basePointers)) {
					stopped = 1;
				}
			}
		}
	}

	return stopped;
}

/*
 * Utility functions to adjust the load command vmaddrs in constituent MachO's
 * of an MH_FILESET kernel collection.
 */

static void
kernel_collection_adjust_fileset_entry_addrs(struct mach_header_64 *mh, uintptr_t adj)
{
	struct load_command *lc;
	struct segment_command_64 *seg, *linkedit_cmd = NULL;
	struct symtab_command *symtab_cmd = NULL;
	struct section_64 *sec;
	uint32_t i, j;

	lc = (struct load_command *)((uintptr_t)mh + sizeof(*mh));
	for (i = 0; i < mh->ncmds; i++,
	    lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
		if (lc->cmd == LC_SYMTAB) {
			symtab_cmd = (struct symtab_command *)lc;
			continue;
		}
		if (lc->cmd != LC_SEGMENT_64) {
			continue;
		}
		if (strcmp(((struct segment_command_64 *)(uintptr_t)lc)->segname, SEG_LINKEDIT) == 0) {
			linkedit_cmd = ((struct segment_command_64 *)(uintptr_t)lc);
		}

		seg = (struct segment_command_64 *)(uintptr_t)lc;
		seg->vmaddr += adj;
		/* slide/adjust every section in the segment */
		sec = (struct section_64 *)((uintptr_t)seg + sizeof(*seg));
		for (j = 0; j < seg->nsects; j++, sec++) {
			sec->addr += adj;
		}
	}


	if (symtab_cmd != NULL && linkedit_cmd != NULL) {
		struct nlist_64 *sym;
		uint32_t cnt = 0;

		if (LogFixups) {
			dyldLogFunc("[LOG] Symbols:\n");
			dyldLogFunc("[LOG] nsyms: %d, symoff: 0x%x\n", symtab_cmd->nsyms, symtab_cmd->symoff);
		}

		if (symtab_cmd->nsyms == 0) {
			dyldLogFunc("[LOG] No symbols to relocate\n");
		}

		sym = (struct nlist_64 *)(linkedit_cmd->vmaddr + symtab_cmd->symoff - linkedit_cmd->fileoff);

		for (i = 0; i < symtab_cmd->nsyms; i++) {
			if (sym[i].n_type & N_STAB) {
				continue;
			}
			sym[i].n_value += adj;
			cnt++;
		}
		if (LogFixups) {
			dyldLogFunc("[LOG] KASLR: Relocated %d symbols\n", cnt);
		}
	}
}

static void
kernel_collection_adjust_mh_addrs(struct mach_header_64 *kc_mh, uintptr_t adj,
    bool pageable, uintptr_t *kc_lowest_vmaddr, uintptr_t *kc_highest_vmaddr,
    uintptr_t *kc_lowest_ro_vmaddr, uintptr_t *kc_highest_ro_vmaddr,
    uintptr_t *kc_lowest_rx_vmaddr, uintptr_t *kc_highest_rx_vmaddr,
    uintptr_t *kc_highest_nle_vmaddr)
{
	assert(kc_mh->filetype == MH_FILESET);

	struct load_command *lc;
	struct fileset_entry_command *fse;
	struct segment_command_64 *seg;
	struct section_64 *sec;
	struct mach_header_64 *mh;
	uintptr_t lowest_vmaddr = UINTPTR_MAX, highest_vmaddr = 0, highest_nle_vmaddr = 0;
	uintptr_t lowest_ro_vmaddr = UINTPTR_MAX, highest_ro_vmaddr = 0;
	uintptr_t lowest_rx_vmaddr = UINTPTR_MAX, highest_rx_vmaddr = 0;
	uint32_t i, j;
	int is_linkedit = 0;

	/*
	 * Slide (offset/adjust) every segment/section of every kext contained
	 * in this MH_FILESET mach-o.
	 */
	lc = (struct load_command *)((uintptr_t)kc_mh + sizeof(*kc_mh));
	for (i = 0; i < kc_mh->ncmds; i++,
	    lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
		if (lc->cmd == LC_FILESET_ENTRY) {
			fse = (struct fileset_entry_command *)(uintptr_t)lc;
			/*
			 * The fileset_entry contains a pointer to the mach-o
			 * of a kext (or the kernel). Slide/adjust this command, and
			 * then slide/adjust all the sub-commands in the mach-o.
			 */
			if (LogFixups) {
				dyldLogFunc("[MH] sliding %s", (char *)((uintptr_t)fse +
				    (uintptr_t)(fse->entry_id.offset)));
			}
			mh = (struct mach_header_64 *)((uintptr_t)fse->vmaddr + adj);
			if (!pageable) {
				/*
				 * Do not adjust mach headers of entries in pageable KC as that
				 * would pull those pages in prematurely
				 */
				kernel_collection_adjust_fileset_entry_addrs(mh, adj);
			}
			fse->vmaddr += adj;
		} else if (lc->cmd == LC_SEGMENT_64) {
			/*
			 * Slide/adjust all LC_SEGMENT_64 commands in the fileset
			 * (and any sections in those segments)
			 */
			seg = (struct segment_command_64 *)(uintptr_t)lc;
			seg->vmaddr += adj;
			sec = (struct section_64 *)((uintptr_t)seg + sizeof(*seg));
			for (j = 0; j < seg->nsects; j++, sec++) {
				sec->addr += adj;
			}
			if (seg->vmsize == 0) {
				continue;
			}
			/*
			 * Record vmaddr range covered by all non-empty segments in the
			 * kernel collection.
			 */
			if (seg->vmaddr < lowest_vmaddr) {
				lowest_vmaddr = (uintptr_t)seg->vmaddr;
			}

			is_linkedit = strings_are_equal(seg->segname, "__LINKEDIT");

			if (seg->vmaddr + seg->vmsize > highest_vmaddr) {
				highest_vmaddr = (uintptr_t)seg->vmaddr + (uintptr_t)seg->vmsize;
				if (!is_linkedit) {
					highest_nle_vmaddr = highest_vmaddr;
				}
			}

			if ((seg->maxprot & VM_PROT_WRITE) || is_linkedit) {
				continue;
			}
			/*
			 * Record vmaddr range covered by non-empty read-only segments
			 * in the kernel collection (excluding LINKEDIT).
			 */
			if (seg->vmaddr < lowest_ro_vmaddr) {
				lowest_ro_vmaddr = (uintptr_t)seg->vmaddr;
			}
			if (seg->vmaddr + seg->vmsize > highest_ro_vmaddr) {
				highest_ro_vmaddr = (uintptr_t)seg->vmaddr + (uintptr_t)seg->vmsize;
			}

			if (!(seg->maxprot & VM_PROT_EXECUTE)) {
				continue;
			}
			/*
			 * Record vmaddr range covered by contiguous execute segments
			 * in the kernel collection.
			 */
			if (seg->vmaddr < lowest_rx_vmaddr && (lowest_rx_vmaddr <= seg->vmaddr + seg->vmsize || lowest_rx_vmaddr == UINTPTR_MAX)) {
				lowest_rx_vmaddr = (uintptr_t)seg->vmaddr;
			}
			if (seg->vmaddr + seg->vmsize > highest_rx_vmaddr && (highest_rx_vmaddr >= seg->vmaddr || highest_rx_vmaddr == 0)) {
				highest_rx_vmaddr = (uintptr_t)seg->vmaddr + (uintptr_t)seg->vmsize;
			}
		}
	}
	if (kc_lowest_vmaddr) {
		*kc_lowest_vmaddr = lowest_vmaddr;
	}
	if (kc_highest_vmaddr) {
		*kc_highest_vmaddr = highest_vmaddr;
	}
	if (kc_lowest_ro_vmaddr) {
		*kc_lowest_ro_vmaddr = lowest_ro_vmaddr;
	}
	if (kc_highest_ro_vmaddr) {
		*kc_highest_ro_vmaddr = highest_ro_vmaddr;
	}
	if (kc_lowest_rx_vmaddr) {
		*kc_lowest_rx_vmaddr = lowest_rx_vmaddr;
	}
	if (kc_highest_rx_vmaddr) {
		*kc_highest_rx_vmaddr = highest_rx_vmaddr;
	}
	if (kc_highest_nle_vmaddr) {
		*kc_highest_nle_vmaddr = highest_nle_vmaddr;
	}
}

/*
 * Rebaser functions for the traditional arm64e static kernelcache with
 * threaded rebase.
 */

static void
rebase_chain(uintptr_t chainStartAddress, uint64_t stepMultiplier, uintptr_t baseAddress __unused, uint64_t slide)
{
	uint64_t delta = 0;
	uintptr_t address = chainStartAddress;
	do {
		uint64_t value = *(uint64_t*)address;

#if HAS_APPLE_PAC
		uint16_t diversity = (uint16_t)(value >> 32);
		bool hasAddressDiversity = (value & (1ULL << 48)) != 0;
		ptrauth_key key = (ptrauth_key)((value >> 49) & 0x3);
#endif
		bool isAuthenticated = (value & (1ULL << 63)) != 0;
		bool isRebase = (value & (1ULL << 62)) == 0;
		if (isRebase) {
			if (isAuthenticated) {
				// The new value for a rebase is the low 32-bits of the threaded value plus the slide.
				uint64_t newValue = (value & 0xFFFFFFFF) + slide;
				// Add in the offset from the mach_header
				newValue += baseAddress;
#if HAS_APPLE_PAC
				// We have bits to merge in to the discriminator
				uintptr_t discriminator = diversity;
				if (hasAddressDiversity) {
					// First calculate a new discriminator using the address of where we are trying to store the value
					// Only blend if we have a discriminator
					if (discriminator) {
						discriminator = __builtin_ptrauth_blend_discriminator((void*)address, discriminator);
					} else {
						discriminator = address;
					}
				}
				switch (key) {
				case ptrauth_key_asia:
					newValue = (uintptr_t)__builtin_ptrauth_sign_unauthenticated((void*)newValue, ptrauth_key_asia, discriminator);
					break;
				case ptrauth_key_asib:
					newValue = (uintptr_t)__builtin_ptrauth_sign_unauthenticated((void*)newValue, ptrauth_key_asib, discriminator);
					break;
				case ptrauth_key_asda:
					newValue = (uintptr_t)__builtin_ptrauth_sign_unauthenticated((void*)newValue, ptrauth_key_asda, discriminator);
					break;
				case ptrauth_key_asdb:
					newValue = (uintptr_t)__builtin_ptrauth_sign_unauthenticated((void*)newValue, ptrauth_key_asdb, discriminator);
					break;
				}
#endif
				*(uint64_t*)address = newValue;
			} else {
				// Regular pointer which needs to fit in 51-bits of value.
				// C++ RTTI uses the top bit, so we'll allow the whole top-byte
				// and the bottom 43-bits to be fit in to 51-bits.
				uint64_t top8Bits = value & 0x0007F80000000000ULL;
				uint64_t bottom43Bits = value & 0x000007FFFFFFFFFFULL;
				uint64_t targetValue = (top8Bits << 13) | (((intptr_t)(bottom43Bits << 21) >> 21) & 0x00FFFFFFFFFFFFFF);
				targetValue = targetValue + slide;
				*(uint64_t*)address = targetValue;
			}
		}

		// The delta is bits [51..61]
		// And bit 62 is to tell us if we are a rebase (0) or bind (1)
		value &= ~(1ULL << 62);
		delta = (value & 0x3FF8000000000000) >> 51;
		address += delta * stepMultiplier;
	} while (delta != 0);
}

static bool __unused
rebase_threaded_starts(uint32_t *threadArrayStart, uint32_t *threadArrayEnd,
    uintptr_t macho_header_addr, uintptr_t macho_header_vmaddr, size_t slide)
{
	uint32_t threadStartsHeader = *threadArrayStart;
	uint64_t stepMultiplier = (threadStartsHeader & 1) == 1 ? 8 : 4;
	for (uint32_t* threadOffset = threadArrayStart + 1; threadOffset != threadArrayEnd; ++threadOffset) {
		if (*threadOffset == 0xFFFFFFFF) {
			break;
		}
		rebase_chain(macho_header_addr + *threadOffset, stepMultiplier, macho_header_vmaddr, slide);
	}
	return true;
}
