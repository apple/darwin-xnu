/*
 * Copyright (c) 2011-2018 Apple Inc. All rights reserved.
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

#include <arm/pmap.h>

#include <kern/debug.h>
#include <kern/trustcache.h>
#include <kern/misc_protos.h>

#include <libkern/section_keywords.h>

#include <mach/machine/vm_types.h>

#include <pexpert/device_tree.h>

#include <sys/cdefs.h>

// All the external+engineering trust caches (accepting only one on RELEASE).
SECURITY_READ_ONLY_LATE(static struct serialized_trust_caches *)pmap_serialized_trust_caches = NULL;

// Shortcut to the first (= non-engineering, and therefore "static") trust cache.
SECURITY_READ_ONLY_LATE(static struct trust_cache_module1 *)pmap_static_trust_cache = NULL;

#if CONFIG_SECOND_STATIC_TRUST_CACHE
SECURITY_READ_ONLY_LATE(static struct trust_cache_module1 *)pmap_secondary_static_trust_cache = NULL;
#endif

// The EXTRADATA segment is where we find the external trust cache.
extern vm_offset_t   segEXTRADATA;
extern unsigned long segSizeEXTRADATA;

void
trust_cache_init(void)
{
	size_t const len = segSizeEXTRADATA;

	if (len == 0) {
#if XNU_TARGET_OS_OSX
		printf("No external trust cache found (region len is 0).");
#else
		panic("No external trust cache found (region len is 0).");
#endif
		return;
	}

	size_t const locked_down_dt_size = SecureDTIsLockedDown() ? PE_state.deviceTreeSize : 0;

	pmap_serialized_trust_caches = (struct serialized_trust_caches*)(segEXTRADATA +
	    locked_down_dt_size);

	uint8_t const *region_end = (uint8_t*)pmap_serialized_trust_caches + len;

	/* Validate the trust cache region for consistency.
	 *
	 * Technically, this shouldn't be necessary because any problem
	 * here would indicate that iBoot is either broken or compromised,
	 * but we do it anyway to assist in development, and for defense
	 * in depth.
	 */

	if (len < sizeof(struct serialized_trust_caches)) {
		panic("short serialized trust cache region: %zu", len);
	}

	printf("%d external trust cache modules available.\n", pmap_serialized_trust_caches->num_caches);

	if (len < (sizeof(struct serialized_trust_caches) +
	    pmap_serialized_trust_caches->num_caches * sizeof(uint32_t))) {
		panic("serialized trust cache region too short for its %d entries: %zu",
		    pmap_serialized_trust_caches->num_caches, len);
	}

	uint8_t *module_end = (uint8_t*)pmap_serialized_trust_caches;

	for (uint32_t i = 0; i < pmap_serialized_trust_caches->num_caches; i++) {
		struct trust_cache_module1 *module = (struct trust_cache_module1*)
		    ((uint8_t*)pmap_serialized_trust_caches + pmap_serialized_trust_caches->offsets[i]);

		if ((uint8_t*)module < module_end) {
			panic("trust cache module %d overlaps previous module", i);
		}

		module_end = (uint8_t*)(module + 1);

		if (module_end > region_end) {
			panic("trust cache module %d too short for header", i);
		}

		if (module->version != 1) {
			panic("trust cache module %d has unsupported version %d", i, module->version);
		}

		module_end += module->num_entries * sizeof(struct trust_cache_entry1);

		if (module_end > region_end) {
			panic("trust cache module %d too short for its %u entries", i, module->num_entries);
		}

		printf("external trust cache module %d with %d entries\n", i, module->num_entries);

		if (i == 0) {
			pmap_static_trust_cache = module;
		}
#if CONFIG_SECOND_STATIC_TRUST_CACHE
		else if (i == 1) {
			pmap_secondary_static_trust_cache = module;
		}
#endif
	}
}


// Lookup cdhash in a trust cache module.
// Suitable for all kinds of trust caches (but loadable ones are currently different).
bool
lookup_in_trust_cache_module(
	struct trust_cache_module1 const * const module,
	uint8_t const   cdhash[CS_CDHASH_LEN],
	uint8_t * const hash_type,
	uint8_t * const flags)
{
	size_t lim;
	struct trust_cache_entry1 const *base = &module->entries[0];

	struct trust_cache_entry1 const *entry = NULL;

	bool found = false;

	/* Initialization already (redundantly) verified the size of the module for us. */
	for (lim = module->num_entries; lim != 0; lim >>= 1) {
		entry = base + (lim >> 1);
		int cmp = memcmp(cdhash, entry->cdhash, CS_CDHASH_LEN);
		if (cmp == 0) {
			found = true;
			break;
		}
		if (cmp > 0) {  /* key > p: move right */
			base = entry + 1;
			lim--;
		}               /* else move left */
	}

	if (found) {
		*hash_type = entry->hash_type;
		*flags = entry->flags;
		return true;
	}

	return false;
}

MARK_AS_PMAP_TEXT uint32_t
lookup_in_static_trust_cache(const uint8_t cdhash[CS_CDHASH_LEN])
{
	/* We will cram those into a single return value, because output parameters require
	 * some contortion. */
	uint8_t hash_type = 0, flags = 0;
	uint32_t engineering_trust_cache_index = 1;

	if (pmap_static_trust_cache != NULL) {
		// The one real new static trust cache.
		if (lookup_in_trust_cache_module(pmap_static_trust_cache, cdhash, &hash_type, &flags)) {
			return (hash_type << TC_LOOKUP_HASH_TYPE_SHIFT) |
			       (flags << TC_LOOKUP_FLAGS_SHIFT) |
			       (TC_LOOKUP_FOUND << TC_LOOKUP_RESULT_SHIFT);
		}
#if CONFIG_SECOND_STATIC_TRUST_CACHE
		if (pmap_secondary_static_trust_cache != NULL &&
		    lookup_in_trust_cache_module(pmap_secondary_static_trust_cache, cdhash, &hash_type, &flags)) {
			return (hash_type << TC_LOOKUP_HASH_TYPE_SHIFT) |
			       (flags << TC_LOOKUP_FLAGS_SHIFT) |
			       (TC_LOOKUP_FOUND << TC_LOOKUP_RESULT_SHIFT);
		}
		engineering_trust_cache_index = (pmap_secondary_static_trust_cache != NULL) ? 2 : 1;
#endif

		// Engineering Trust Caches.
		if (pmap_serialized_trust_caches->num_caches > engineering_trust_cache_index) {
#if DEVELOPMENT || DEBUG
			for (uint32_t i = engineering_trust_cache_index; i < pmap_serialized_trust_caches->num_caches; i++) {
				struct trust_cache_module1 const *module =
				    (struct trust_cache_module1 const *)(
					(uint8_t*)pmap_serialized_trust_caches + pmap_serialized_trust_caches->offsets[i]);

				if (lookup_in_trust_cache_module(module, cdhash, &hash_type, &flags)) {
					return (hash_type << TC_LOOKUP_HASH_TYPE_SHIFT) |
					       (flags << TC_LOOKUP_FLAGS_SHIFT) |
					       (TC_LOOKUP_FOUND << TC_LOOKUP_RESULT_SHIFT);
				}
			}
#else
			panic("Number of trust caches: %d. How could we let this happen?",
			    pmap_serialized_trust_caches->num_caches);
#endif
		}
	}

	return 0;
}
