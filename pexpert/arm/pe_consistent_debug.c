/*
 * Copyright (C) 2011-2013 Apple Inc. All rights reserved.
 *
 * This document is the property of Apple Inc.
 * It is considered confidential and proprietary.
 *
 * This document may not be reproduced or transmitted in any form,
 * in whole or in part, without the express written permission of
 * Apple Inc.
 */

#include <pexpert/pexpert.h>
#include <pexpert/arm/consistent_debug.h>
#include <pexpert/device_tree.h>
#include <libkern/OSAtomic.h>
#include <machine/machine_routines.h>

static dbg_registry_t * consistent_debug_registry = NULL; 

static dbg_record_header_t* consistent_debug_allocate_entry(void) {
	unsigned int i;

	if (!consistent_debug_registry)
		return NULL;
	for (i = 0; i < consistent_debug_registry->top_level_header.num_records; i++) {
		dbg_record_header_t *record = &consistent_debug_registry->records[i];
		if (OSCompareAndSwap64(kDbgIdUnusedEntry, kDbgIdReservedEntry, &record->record_id)) {
			// Reserved an entry at position i.
			return (dbg_record_header_t*)record;
		}
	}
	return NULL;
}

int PE_consistent_debug_inherit(void)
{
	DTEntry		entryP;
	uintptr_t	*prop_data;
	uintptr_t	root_pointer = 0;
	uint32_t	size;

        if ((DTLookupEntry(NULL, "/chosen", &entryP) == kSuccess))
		if (DTGetProperty(entryP, "consistent-debug-root", (void **)&prop_data, &size) == kSuccess)
			root_pointer = prop_data[0];
	if (root_pointer == 0)
		return -1;
	consistent_debug_registry = (dbg_registry_t *)ml_map_high_window(root_pointer, sizeof(dbg_registry_t));
	return 0;
}

int PE_consistent_debug_register(uint64_t record_id, uint64_t physaddr, uint64_t length)
{
	dbg_record_header_t *allocated_header = consistent_debug_allocate_entry();
	if (allocated_header == NULL)
		return -1;
	allocated_header->length = length;
	allocated_header->physaddr = physaddr;
	// Make sure the hdr/length are visible before the record_id.
	__asm__ volatile("dmb ish" : : : "memory");
	allocated_header->record_id = record_id;
	return 0;
}

int PE_consistent_debug_enabled(void)
{
	return (consistent_debug_registry != NULL);
}

