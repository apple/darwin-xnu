/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <pexpert/protos.h>
#include <pexpert/boot.h>
#include <pexpert/device_tree.h>

#include <mach/mach_types.h>
#include <mach/machine/vm_types.h>
#include <kern/debug.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <libkern/kernel_mach_header.h>
#include <os/overflow.h>

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
extern addr64_t kvtophys(vm_offset_t va);
#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

#include <sys/types.h>

SECURITY_READ_ONLY_LATE(static int) DTInitialized;
SECURITY_READ_ONLY_LATE(RealDTEntry) DTRootNode;
SECURITY_READ_ONLY_LATE(static vm_size_t) DTSize;
SECURITY_READ_ONLY_LATE(static vm_offset_t) DTEnd;

/*
 *
 * Support Routines
 *
 */

static inline void
assert_in_dt_region(vm_offset_t const start, vm_offset_t const end, void const *p)
{
	if ((vm_offset_t)p < start || (vm_offset_t)p > end) {
		panic("Device tree pointer outside of device tree region: pointer %p, DTEnd %lx\n", p, (unsigned long)DTEnd);
	}
}
#define ASSERT_IN_DT(p) assert_in_dt_region((vm_offset_t)DTRootNode, (vm_offset_t)DTEnd, (p))

static inline void
assert_prop_in_dt_region(vm_offset_t const start, vm_offset_t const end, DeviceTreeNodeProperty const *prop)
{
	vm_offset_t prop_end;

	assert_in_dt_region(start, end, prop);
	if (os_add3_overflow((vm_offset_t)prop, sizeof(DeviceTreeNodeProperty), prop->length, &prop_end)) {
		panic("Device tree property overflow: prop %p, length 0x%x\n", prop, prop->length);
	}
	assert_in_dt_region(start, end, (void*)prop_end);
}
#define ASSERT_PROP_IN_DT(prop) assert_prop_in_dt_region((vm_offset_t)DTRootNode, (vm_offset_t)DTEnd, (prop))

#define ASSERT_HEADER_IN_DT_REGION(start, end, p, size) assert_in_dt_region((start), (end), (uint8_t const *)(p) + (size))
#define ASSERT_HEADER_IN_DT(p, size) ASSERT_IN_DT((uint8_t const *)(p) + (size))

/*
 * Since there is no way to know the size of a device tree node
 * without fully walking it, we employ the following principle to make
 * sure that the accessed device tree is fully within its memory
 * region:
 *
 * Internally, we check anything we want to access just before we want
 * to access it (not after creating a pointer).
 *
 * Then, before returning a DTEntry to the caller, we check whether
 * the start address (only!) of the entry is still within the device
 * tree region.
 *
 * Before returning a property value the caller, we check whether the
 * property is fully within the region.
 *
 * "DTEntry"s are opaque to the caller, so only checking their
 * starting address is enough to satisfy existence within the device
 * tree region, while for property values we need to make sure that
 * they are fully within the region.
 */

static inline DeviceTreeNodeProperty const *
next_prop_region(vm_offset_t const start, vm_offset_t end, DeviceTreeNodeProperty const *prop)
{
	uintptr_t next_addr;

	ASSERT_HEADER_IN_DT_REGION(start, end, prop, sizeof(DeviceTreeNode));

	if (os_add3_overflow((uintptr_t)prop, prop->length, sizeof(DeviceTreeNodeProperty) + 3, &next_addr)) {
		panic("Device tree property overflow: prop %p, length 0x%x\n", prop, prop->length);
	}

	next_addr &= ~(3ULL);

	return (DeviceTreeNodeProperty*)next_addr;
}
#define next_prop(prop) next_prop_region((vm_offset_t)DTRootNode, (vm_offset_t)DTEnd, (prop))

static RealDTEntry
skipProperties(RealDTEntry entry)
{
	DeviceTreeNodeProperty const *prop;
	unsigned int k;

	if (entry == NULL) {
		return NULL;
	}

	ASSERT_HEADER_IN_DT(entry, sizeof(DeviceTreeNode));

	if (entry->nProperties == 0) {
		return NULL;
	} else {
		prop = (DeviceTreeNodeProperty const *) (entry + 1);
		for (k = 0; k < entry->nProperties; k++) {
			prop = next_prop(prop);
		}
	}
	ASSERT_IN_DT(prop);
	return (RealDTEntry) prop;
}

static RealDTEntry
skipTree(RealDTEntry root)
{
	RealDTEntry entry;
	unsigned int k;

	ASSERT_HEADER_IN_DT(root, sizeof(DeviceTreeNode));

	entry = skipProperties(root);
	if (entry == NULL) {
		return NULL;
	}
	for (k = 0; k < root->nChildren; k++) {
		entry = skipTree(entry);
	}
	return entry;
}

static RealDTEntry
GetFirstChild(RealDTEntry parent)
{
	return skipProperties(parent);
}

static RealDTEntry
GetNextChild(RealDTEntry sibling)
{
	return skipTree(sibling);
}

static const char *
GetNextComponent(const char *cp, char *bp)
{
	size_t length = 0;
	char *origbp = bp;

	while (*cp != 0) {
		if (*cp == kDTPathNameSeparator) {
			cp++;
			break;
		}
		if (++length > kDTMaxEntryNameLength) {
			*origbp = '\0';
			return cp;
		}
		*bp++ = *cp++;
	}
	*bp = 0;
	return cp;
}

static RealDTEntry
FindChild(RealDTEntry cur, char *buf)
{
	RealDTEntry     child;
	unsigned long   index;
	char const *    str;
	unsigned int    dummy;

	ASSERT_HEADER_IN_DT(cur, sizeof(DeviceTreeNode));

	if (cur->nChildren == 0) {
		return NULL;
	}
	index = 1;
	child = GetFirstChild(cur);
	while (1) {
		if (SecureDTGetProperty(child, "name", (void const **)&str, &dummy) != kSuccess) {
			break;
		}
		if (strcmp(str, buf) == 0) {
			return child;
		}
		if (index >= cur->nChildren) {
			break;
		}
		child = GetNextChild(child);
		index++;
	}
	return NULL;
}

/*
 * External Routines
 */
void
SecureDTInit(void const *base, size_t size)
{
	if ((uintptr_t)base + size < (uintptr_t)base) {
		panic("DeviceTree overflow: %p, size %#zx", base, size);
	}
	DTRootNode = base;
	DTSize = size;
	DTEnd = (vm_offset_t)DTRootNode + DTSize;
	DTInitialized = (DTRootNode != 0);
}

bool
SecureDTIsLockedDown(void)
{
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	/*
	 * We cannot check if the DT is in the CTRR region early on,
	 * because knowledge of the CTRR region is set up later.  But the
	 * DT is used in all kinds of early bootstrapping before that.
	 *
	 * Luckily, we know that the device tree must be in front of the
	 * kernel if set up in EXTRADATA (which means it's covered by
	 * CTRR), and after it otherwise.
	 */
	addr64_t exec_header_phys = kvtophys((vm_offset_t)&_mh_execute_header);

	if (kvtophys((vm_offset_t)DTRootNode) < exec_header_phys) {
		assert(kvtophys(DTEnd) < exec_header_phys);
		return true;
	}

#endif
	return false;
}

int
SecureDTEntryIsEqual(const DTEntry ref1, const DTEntry ref2)
{
	/* equality of pointers */
	return ref1 == ref2;
}

static char const *startingP;         // needed for find_entry
int find_entry(const char *propName, const char *propValue, DTEntry *entryH);

int
SecureDTFindEntry(const char *propName, const char *propValue, DTEntry *entryH)
{
	if (!DTInitialized) {
		return kError;
	}

	startingP = (char const *)DTRootNode;
	return find_entry(propName, propValue, entryH);
}

int
find_entry(const char *propName, const char *propValue, DTEntry *entryH)
{
	DeviceTreeNode const *nodeP = (DeviceTreeNode const *) (void const *) startingP;
	unsigned int k;

	ASSERT_HEADER_IN_DT(nodeP, sizeof(DeviceTreeNode));

	if (nodeP->nProperties == 0) {
		return kError;                        // End of the list of nodes
	}
	startingP = (char const *) (nodeP + 1);

	// Search current entry
	for (k = 0; k < nodeP->nProperties; ++k) {
		DeviceTreeNodeProperty const *propP = (DeviceTreeNodeProperty const *) (void const *) startingP;
		ASSERT_PROP_IN_DT(propP);

		startingP += sizeof(*propP) + ((propP->length + 3) & -4);

		if (strcmp(propP->name, propName) == 0) {
			if (propValue == NULL || strcmp((char const *)(propP + 1), propValue) == 0) {
				*entryH = (DTEntry)nodeP;
				ASSERT_HEADER_IN_DT(*entryH, sizeof(DeviceTreeNode));
				return kSuccess;
			}
		}
	}

	// Search child nodes
	for (k = 0; k < nodeP->nChildren; ++k) {
		if (find_entry(propName, propValue, entryH) == kSuccess) {
			return kSuccess;
		}
	}
	return kError;
}

int
SecureDTLookupEntry(const DTEntry searchPoint, const char *pathName, DTEntry *foundEntry)
{
	DTEntryNameBuf  buf;
	RealDTEntry     cur;
	const char *    cp;

	if (!DTInitialized) {
		return kError;
	}
	if (searchPoint == NULL) {
		cur = DTRootNode;
	} else {
		cur = searchPoint;
	}
	ASSERT_IN_DT(cur);
	cp = pathName;
	if (*cp == kDTPathNameSeparator) {
		cp++;
		if (*cp == 0) {
			*foundEntry = cur;
			return kSuccess;
		}
	}
	do {
		cp = GetNextComponent(cp, buf);

		/* Check for done */
		if (*buf == 0) {
			if (*cp == 0) {
				*foundEntry = cur;
				return kSuccess;
			}
			break;
		}

		cur = FindChild(cur, buf);
	} while (cur != NULL);

	return kError;
}

int
SecureDTInitEntryIterator(const DTEntry startEntry, DTEntryIterator iter)
{
	if (!DTInitialized) {
		return kError;
	}

	if (startEntry != NULL) {
		iter->outerScope = (RealDTEntry) startEntry;
		iter->currentScope = (RealDTEntry) startEntry;
	} else {
		iter->outerScope = DTRootNode;
		iter->currentScope = DTRootNode;
	}
	iter->currentEntry = NULL;
	iter->savedScope = NULL;
	iter->currentIndex = 0;

	return kSuccess;
}

int
SecureDTEnterEntry(DTEntryIterator iter, DTEntry childEntry)
{
	DTSavedScopePtr newScope;

	if (childEntry == NULL) {
		return kError;
	}
	newScope = (DTSavedScopePtr) kalloc(sizeof(struct DTSavedScope));
	newScope->nextScope = iter->savedScope;
	newScope->scope = iter->currentScope;
	newScope->entry = iter->currentEntry;
	newScope->index = iter->currentIndex;

	iter->currentScope = childEntry;
	iter->currentEntry = NULL;
	iter->savedScope = newScope;
	iter->currentIndex = 0;

	return kSuccess;
}

int
SecureDTExitEntry(DTEntryIterator iter, DTEntry *currentPosition)
{
	DTSavedScopePtr newScope;

	newScope = iter->savedScope;
	if (newScope == NULL) {
		return kError;
	}
	iter->savedScope = newScope->nextScope;
	iter->currentScope = newScope->scope;
	iter->currentEntry = newScope->entry;
	iter->currentIndex = newScope->index;
	*currentPosition = iter->currentEntry;

	kfree(newScope, sizeof(struct DTSavedScope));

	return kSuccess;
}

int
SecureDTIterateEntries(DTEntryIterator iter, DTEntry *nextEntry)
{
	if (iter->currentIndex >= iter->currentScope->nChildren) {
		*nextEntry = NULL;
		return kIterationDone;
	} else {
		iter->currentIndex++;
		if (iter->currentIndex == 1) {
			iter->currentEntry = GetFirstChild(iter->currentScope);
		} else {
			iter->currentEntry = GetNextChild(iter->currentEntry);
		}
		ASSERT_IN_DT(iter->currentEntry);
		*nextEntry = iter->currentEntry;
		return kSuccess;
	}
}

int
SecureDTRestartEntryIteration(DTEntryIterator iter)
{
#if 0
	// This commented out code allows a second argument (outer)
	// which (if true) causes restarting at the outer scope
	// rather than the current scope.
	DTSavedScopePtr scope;

	if (outer) {
		while ((scope = iter->savedScope) != NULL) {
			iter->savedScope = scope->nextScope;
			kfree((vm_offset_t) scope, sizeof(struct DTSavedScope));
		}
		iter->currentScope = iter->outerScope;
	}
#endif
	iter->currentEntry = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}

static int
SecureDTGetPropertyInternal(const DTEntry entry, const char *propertyName, void const **propertyValue, unsigned int *propertySize, vm_offset_t const region_start, vm_size_t region_size)
{
	DeviceTreeNodeProperty const *prop;
	unsigned int k;

	if (entry == NULL) {
		return kError;
	}

	ASSERT_HEADER_IN_DT_REGION(region_start, region_start + region_size, entry, sizeof(DeviceTreeNode));

	if (entry->nProperties == 0) {
		return kError;
	} else {
		prop = (DeviceTreeNodeProperty const *) (entry + 1);
		for (k = 0; k < entry->nProperties; k++) {
			assert_prop_in_dt_region(region_start, region_start + region_size, prop);
			if (strcmp(prop->name, propertyName) == 0) {
				*propertyValue = (void const *) (((uintptr_t)prop)
				    + sizeof(DeviceTreeNodeProperty));
				*propertySize = prop->length;
				return kSuccess;
			}
			prop = next_prop_region(region_start, region_start + region_size, prop);
		}
	}
	return kError;
}

int
SecureDTGetProperty(const DTEntry entry, const char *propertyName, void const **propertyValue, unsigned int *propertySize)
{
	return SecureDTGetPropertyInternal(entry, propertyName, propertyValue, propertySize,
	           (vm_offset_t)DTRootNode, (vm_size_t)((uintptr_t)DTEnd - (uintptr_t)DTRootNode));
}

#if defined(__i386__) || defined(__x86_64__)
int
SecureDTGetPropertyRegion(const DTEntry entry, const char *propertyName, void const **propertyValue, unsigned int *propertySize, vm_offset_t const region_start, vm_size_t region_size)
{
	return SecureDTGetPropertyInternal(entry, propertyName, propertyValue, propertySize,
	           region_start, region_size);
}
#endif


int
SecureDTInitPropertyIterator(const DTEntry entry, DTPropertyIterator iter)
{
	iter->entry = entry;
	iter->currentProperty = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}

int
SecureDTIterateProperties(DTPropertyIterator iter, char const **foundProperty)
{
	if (iter->currentIndex >= iter->entry->nProperties) {
		*foundProperty = NULL;
		return kIterationDone;
	} else {
		iter->currentIndex++;
		if (iter->currentIndex == 1) {
			iter->currentProperty = (DeviceTreeNodeProperty const *) (iter->entry + 1);
		} else {
			iter->currentProperty = next_prop(iter->currentProperty);
		}
		ASSERT_PROP_IN_DT(iter->currentProperty);
		*foundProperty = iter->currentProperty->name;
		return kSuccess;
	}
}

int
SecureDTRestartPropertyIteration(DTPropertyIterator iter)
{
	iter->currentProperty = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}
