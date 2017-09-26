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
#include <os/overflow.h>

#include <sys/types.h>

static int DTInitialized;
static RealDTEntry DTRootNode;

/*
 * Support Routines
 */
static inline DeviceTreeNodeProperty*
next_prop(DeviceTreeNodeProperty* prop)
{
	uintptr_t next_addr;
	if (os_add3_overflow((uintptr_t)prop, prop->length, sizeof(DeviceTreeNodeProperty) + 3, &next_addr))
		panic("Device tree property overflow: prop %p, length 0x%x\n", prop, prop->length);
	next_addr &= ~(3ULL);
	return (DeviceTreeNodeProperty*)next_addr;
}

static RealDTEntry
skipProperties(RealDTEntry entry)
{
	DeviceTreeNodeProperty *prop;
	unsigned int k;

	if (entry == NULL || entry->nProperties == 0) {
		return NULL;
	} else {
		prop = (DeviceTreeNodeProperty *) (entry + 1);
		for (k = 0; k < entry->nProperties; k++) {
			prop = next_prop(prop);
		}
	}
	return ((RealDTEntry) prop);
}

static RealDTEntry
skipTree(RealDTEntry root)
{
	RealDTEntry entry;
	unsigned int k;

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
	RealDTEntry	child;
	unsigned long	index;
	char *			str;
	unsigned int	dummy;

	if (cur->nChildren == 0) {
		return NULL;
	}
	index = 1;
	child = GetFirstChild(cur);
	while (1) {
		if (DTGetProperty(child, "name", (void **)&str, &dummy) != kSuccess) {
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
DTInit(void *base)
{
	DTRootNode = (RealDTEntry) base;
	DTInitialized = (DTRootNode != 0);
}

int
DTEntryIsEqual(const DTEntry ref1, const DTEntry ref2)
{
	/* equality of pointers */
	return (ref1 == ref2);
}

static char *startingP;		// needed for find_entry
int find_entry(const char *propName, const char *propValue, DTEntry *entryH);

int DTFindEntry(const char *propName, const char *propValue, DTEntry *entryH)
{
	if (!DTInitialized) {
		return kError;
	}

	startingP = (char *)DTRootNode;
	return(find_entry(propName, propValue, entryH));
}

int find_entry(const char *propName, const char *propValue, DTEntry *entryH)
{
	DeviceTreeNode *nodeP = (DeviceTreeNode *) (void *) startingP;
	unsigned int k;

	if (nodeP->nProperties == 0) return(kError);	// End of the list of nodes
	startingP = (char *) (nodeP + 1);

	// Search current entry
	for (k = 0; k < nodeP->nProperties; ++k) {
		DeviceTreeNodeProperty *propP = (DeviceTreeNodeProperty *) (void *) startingP;

		startingP += sizeof (*propP) + ((propP->length + 3) & -4);

		if (strcmp (propP->name, propName) == 0) {
			if (propValue == NULL || strcmp( (char *)(propP + 1), propValue) == 0)
			{
				*entryH = (DTEntry)nodeP;
				return(kSuccess);
			}
		}
	}

	// Search child nodes
	for (k = 0; k < nodeP->nChildren; ++k)
	{
		if (find_entry(propName, propValue, entryH) == kSuccess)
			return(kSuccess);
	}
	return(kError);
}

int
DTLookupEntry(const DTEntry searchPoint, const char *pathName, DTEntry *foundEntry)
{
	DTEntryNameBuf	buf;
	RealDTEntry	cur;
	const char *	cp;

	if (!DTInitialized) {
		return kError;
	}
	if (searchPoint == NULL) {
		cur = DTRootNode;
	} else {
		cur = searchPoint;
	}
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
DTInitEntryIterator(const DTEntry startEntry, DTEntryIterator iter)
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
DTEnterEntry(DTEntryIterator iter, DTEntry childEntry)
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
DTExitEntry(DTEntryIterator iter, DTEntry *currentPosition)
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
DTIterateEntries(DTEntryIterator iter, DTEntry *nextEntry)
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
		*nextEntry = iter->currentEntry;
		return kSuccess;
	}
}

int
DTRestartEntryIteration(DTEntryIterator iter)
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

int
DTGetProperty(const DTEntry entry, const char *propertyName, void **propertyValue, unsigned int *propertySize)
{
	DeviceTreeNodeProperty *prop;
	unsigned int k;

	if (entry == NULL || entry->nProperties == 0) {
		return kError;
	} else {
		prop = (DeviceTreeNodeProperty *) (entry + 1);
		for (k = 0; k < entry->nProperties; k++) {
			if (strcmp(prop->name, propertyName) == 0) {
				*propertyValue = (void *) (((uintptr_t)prop)
						+ sizeof(DeviceTreeNodeProperty));
				*propertySize = prop->length;
				return kSuccess;
			}
			prop = next_prop(prop);
		}
	}
	return kError;
}

int
DTInitPropertyIterator(const DTEntry entry, DTPropertyIterator iter)
{

	iter->entry = entry;
	iter->currentProperty = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}

int
DTIterateProperties(DTPropertyIterator iter, char **foundProperty)
{
	if (iter->currentIndex >= iter->entry->nProperties) {
		*foundProperty = NULL;
		return kIterationDone;
	} else {
		iter->currentIndex++;
		if (iter->currentIndex == 1) {
			iter->currentProperty = (DeviceTreeNodeProperty *) (iter->entry + 1);
		} else {
			iter->currentProperty = next_prop(iter->currentProperty);
		}
		*foundProperty = iter->currentProperty->name;
		return kSuccess;
	}
}

int
DTRestartPropertyIteration(DTPropertyIterator iter)
{
	iter->currentProperty = NULL;
	iter->currentIndex = 0;
	return kSuccess;
}

