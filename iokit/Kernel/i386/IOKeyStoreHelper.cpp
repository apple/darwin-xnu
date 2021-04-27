/*
 * Copyright (c) 2010 Apple Inc. All rights reserved.
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

#include <sys/cdefs.h>
#include <stdbool.h>

#include <IOKit/assert.h>
#include <IOKit/system.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOKitDebug.h>

__BEGIN_DECLS

#include <pexpert/pexpert.h>

static volatile UInt32 alreadyFetched = 0;
static IOMemoryDescriptor * newData;

IOMemoryDescriptor *
IOGetBootKeyStoreData(void);
void
IOSetKeyStoreData(IOMemoryDescriptor * data);

// APFS
static volatile UInt32 apfsKeyFetched = 0;
static IOMemoryDescriptor* apfsKeyData = NULL;

IOMemoryDescriptor* IOGetAPFSKeyStoreData();
void IOSetAPFSKeyStoreData(IOMemoryDescriptor* data);

static volatile UInt32 ARVRootHashFetched = 0;
static volatile UInt32 bsARVRootHashFetched = 0;

IOMemoryDescriptor* IOGetARVRootHashData(void);
IOMemoryDescriptor* IOGetBaseSystemARVRootHashData(void);

bool IOBaseSystemARVRootHashAvailable(void);

static volatile UInt32 ARVManifestFetched = 0;
static volatile UInt32 bsARVManifestFetched = 0;

IOMemoryDescriptor* IOGetARVManifestData(void);
IOMemoryDescriptor* IOGetBaseSystemARVManifestData(void);

__END_DECLS

#if 1
#define DEBG(fmt, args...)      { kprintf(fmt, ## args); }
#else
#define DEBG(fmt, args...)      {}
#endif

void
IOSetKeyStoreData(IOMemoryDescriptor * data)
{
	newData = data;
	alreadyFetched = 0;
}

IOMemoryDescriptor *
IOGetBootKeyStoreData(void)
{
	IOMemoryDescriptor *memoryDescriptor;
	boot_args *args = (boot_args *)PE_state.bootArgs;
	IOOptionBits options;
	IOAddressRange ranges;

	if (!OSCompareAndSwap(0, 1, &alreadyFetched)) {
		return NULL;
	}

	if (newData) {
		IOMemoryDescriptor * data = newData;
		newData = NULL;
		return data;
	}

	DEBG("%s: data at address %u size %u\n", __func__,
	    args->keyStoreDataStart,
	    args->keyStoreDataSize);

	if (args->keyStoreDataStart == 0) {
		return NULL;
	}

	ranges.address = args->keyStoreDataStart;
	ranges.length = args->keyStoreDataSize;

	options = kIODirectionInOut | kIOMemoryTypePhysical64 | kIOMemoryMapperNone;

	memoryDescriptor = IOMemoryDescriptor::withOptions(&ranges,
	    1,
	    0,
	    NULL,
	    options);

	DEBG("%s: memory descriptor %p\n", __func__, memoryDescriptor);

	return memoryDescriptor;
}

// APFS volume key fetcher

// Store in-memory key (could be used by IOHibernateDone)
void
IOSetAPFSKeyStoreData(IOMemoryDescriptor* data)
{
	// Do not allow re-fetching of the boot_args key by passing NULL here.
	if (data != NULL) {
		apfsKeyData = data;
		apfsKeyFetched = 0;
	}
}

// Retrieve any key we may have (stored in boot_args or by Hibernate)
IOMemoryDescriptor*
IOGetAPFSKeyStoreData()
{
	// Check if someone got the key before us
	if (!OSCompareAndSwap(0, 1, &apfsKeyFetched)) {
		return NULL;
	}

	// Do we have in-memory key?
	if (apfsKeyData) {
		IOMemoryDescriptor* data = apfsKeyData;
		apfsKeyData = NULL;
		return data;
	}

	// Looks like there was no in-memory key and it's the first call - try boot_args
	boot_args* args = (boot_args*)PE_state.bootArgs;

	DEBG("%s: data at address %u size %u\n", __func__, args->apfsDataStart, args->apfsDataSize);
	if (args->apfsDataStart == 0) {
		return NULL;
	}

	// We have the key in the boot_args, create IOMemoryDescriptor for the blob
	IOAddressRange ranges;
	ranges.address = args->apfsDataStart;
	ranges.length = args->apfsDataSize;

	const IOOptionBits options = kIODirectionInOut | kIOMemoryTypePhysical64 | kIOMemoryMapperNone;

	IOMemoryDescriptor* memoryDescriptor = IOMemoryDescriptor::withOptions(&ranges, 1, 0, NULL, options);
	DEBG("%s: memory descriptor %p\n", __func__, memoryDescriptor);
	return memoryDescriptor;
}

// ARV Root Hash fetcher

// Retrieve any root hash we may have (stored in boot_args)
IOMemoryDescriptor*
IOGetARVRootHashData(void)
{
	// Check if someone got the root hash before us
	if (!OSCompareAndSwap(0, 1, &ARVRootHashFetched)) {
		return NULL;
	}

	boot_args* args = (boot_args*)PE_state.bootArgs;

	DEBG("%s: data at address %llu size %llu\n", __func__, args->arvRootHashStart, args->arvRootHashSize);
	if (args->arvRootHashStart == 0) {
		return NULL;
	}

	// We have the root hash in the boot_args, create IOMemoryDescriptor for the blob
	IOAddressRange ranges;
	ranges.address = args->arvRootHashStart;
	ranges.length = args->arvRootHashSize;

	const IOOptionBits options = kIODirectionInOut | kIOMemoryTypePhysical64 | kIOMemoryMapperNone;

	IOMemoryDescriptor* memoryDescriptor = IOMemoryDescriptor::withOptions(&ranges, 1, 0, NULL, options);
	DEBG("%s: memory descriptor %p\n", __func__, memoryDescriptor);
	return memoryDescriptor;
}

// Base System Analogue

IOMemoryDescriptor*
IOGetBaseSystemARVRootHashData(void)
{
	// Check if someone got the base system root hash before us
	if (!OSCompareAndSwap(0, 1, &bsARVRootHashFetched)) {
		return NULL;
	}

	boot_args* args = (boot_args*)PE_state.bootArgs;

	DEBG("%s: data at address %llu size %llu\n", __func__, args->bsARVRootHashStart, args->bsARVRootHashSize);
	if (args->bsARVRootHashStart == 0) {
		return NULL;
	}

	// We have the base system root hash in the boot_args, create IOMemoryDescriptor for the blob
	IOAddressRange ranges;
	ranges.address = args->bsARVRootHashStart;
	ranges.length = args->bsARVRootHashSize;

	const IOOptionBits options = kIODirectionInOut | kIOMemoryTypePhysical64 | kIOMemoryMapperNone;

	IOMemoryDescriptor* memoryDescriptor = IOMemoryDescriptor::withOptions(&ranges, 1, 0, NULL, options);
	DEBG("%s: memory descriptor %p\n", __func__, memoryDescriptor);
	return memoryDescriptor;
}

bool
IOBaseSystemARVRootHashAvailable(void)
{
	boot_args* args = (boot_args*)PE_state.bootArgs;

	if (args->bsARVRootHashStart == 0 || args->bsARVRootHashSize == 0) {
		return false;
	}

	if (args->bsARVManifestStart == 0 || args->bsARVManifestSize == 0) {
		return false;
	}

	return true;
}

// ARV Manifest fetcher

// Retrieve any manifest we may have (stored in boot_args)
IOMemoryDescriptor*
IOGetARVManifestData(void)
{
	// Check if someone got the manifest before us
	if (!OSCompareAndSwap(0, 1, &ARVManifestFetched)) {
		return NULL;
	}

	boot_args* args = (boot_args*)PE_state.bootArgs;

	DEBG("%s: data at address %llu size %llu\n", __func__, args->arvManifestStart, args->arvManifestSize);
	if (args->arvManifestStart == 0) {
		return NULL;
	}

	// We have the manifest in the boot_args, create IOMemoryDescriptor for the blob
	IOAddressRange ranges;
	ranges.address = args->arvManifestStart;
	ranges.length = args->arvManifestSize;

	const IOOptionBits options = kIODirectionInOut | kIOMemoryTypePhysical64 | kIOMemoryMapperNone;

	IOMemoryDescriptor* memoryDescriptor = IOMemoryDescriptor::withOptions(&ranges, 1, 0, NULL, options);
	DEBG("%s: memory descriptor %p\n", __func__, memoryDescriptor);
	return memoryDescriptor;
}

// Base System Analogue

IOMemoryDescriptor*
IOGetBaseSystemARVManifestData(void)
{
	// Check if someone got the base system manifest before us
	if (!OSCompareAndSwap(0, 1, &bsARVManifestFetched)) {
		return NULL;
	}

	boot_args* args = (boot_args*)PE_state.bootArgs;

	DEBG("%s: data at address %llu size %llu\n", __func__, args->bsARVManifestStart, args->bsARVManifestSize);
	if (args->bsARVManifestStart == 0) {
		return NULL;
	}

	// We have the manifest in the boot_args, create IOMemoryDescriptor for the blob
	IOAddressRange ranges;
	ranges.address = args->bsARVManifestStart;
	ranges.length = args->bsARVManifestSize;

	const IOOptionBits options = kIODirectionInOut | kIOMemoryTypePhysical64 | kIOMemoryMapperNone;

	IOMemoryDescriptor* memoryDescriptor = IOMemoryDescriptor::withOptions(&ranges, 1, 0, NULL, options);
	DEBG("%s: memory descriptor %p\n", __func__, memoryDescriptor);
	return memoryDescriptor;
}
