/*
 * Copyright (c) 2010 Apple Computer, Inc. All rights reserved.
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

#include <sys/sysctl.h>
#include <kern/host.h>

#include <IOKit/system.h>
#include <libkern/c++/OSKext.h>
#include <libkern/OSAtomic.h>

#include <IOKit/IOStatisticsPrivate.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOEventSource.h>
#include <IOKit/IOKitDebug.h>

#if IOKITSTATS
bool IOStatistics::enabled = false;

uint32_t IOStatistics::sequenceID = 0;

uint32_t IOStatistics::lastClassIndex = 0;
uint32_t IOStatistics::lastKextIndex = 0;

uint32_t IOStatistics::loadedKexts = 0;
uint32_t IOStatistics::registeredClasses = 0;
uint32_t IOStatistics::registeredCounters = 0;
uint32_t IOStatistics::registeredWorkloops = 0;

uint32_t IOStatistics::attachedEventSources = 0;

IOWorkLoopDependency *IOStatistics::nextWorkLoopDependency = NULL;

/* Logging */

#define LOG_LEVEL 0

#define LOG(level, format, ...) \
do { \
	if (level <= LOG_LEVEL) \
		printf(format, ##__VA_ARGS__); \
} while (0)

/* Locks */

IORWLock *IOStatistics::lock = NULL;

/* Kext tree */

KextNode *IOStatistics::kextHint = NULL;

IOStatistics::KextTreeHead IOStatistics::kextHead = RB_INITIALIZER(&IOStatistics::kextHead);

int IOStatistics::kextNodeCompare(KextNode *e1, KextNode *e2) 
{
    if (e1->kext < e2->kext)
        return -1;
    else if (e1->kext > e2->kext)
        return 1;
    else
        return 0;
}

RB_GENERATE(IOStatistics::KextTree, KextNode, link, kextNodeCompare);

/* Kext tree ordered by address */

IOStatistics::KextAddressTreeHead IOStatistics::kextAddressHead = RB_INITIALIZER(&IOStatistics::kextAddressHead);

int IOStatistics::kextAddressNodeCompare(KextNode *e1, KextNode *e2) 
{
    if (e1->address < e2->address)
        return -1;
    else if (e1->address > e2->address)
        return 1; 
    else
        return 0;
}

RB_GENERATE(IOStatistics::KextAddressTree, KextNode, addressLink, kextAddressNodeCompare);

/* Class tree */

IOStatistics::ClassTreeHead IOStatistics::classHead = RB_INITIALIZER(&IOStatistics::classHead);

int IOStatistics::classNodeCompare(ClassNode *e1, ClassNode *e2) {
    if (e1->metaClass < e2->metaClass)
        return -1;
    else if (e1->metaClass > e2->metaClass)
        return 1;
    else
        return 0;
}

RB_GENERATE(IOStatistics::ClassTree, ClassNode, tLink, classNodeCompare);

/* Workloop dependencies */

int IOWorkLoopCounter::loadTagCompare(IOWorkLoopDependency *e1, IOWorkLoopDependency *e2) {
    if (e1->loadTag < e2->loadTag)
        return -1;
    else if (e1->loadTag > e2->loadTag)
        return 1;
    else
        return 0;
}

RB_GENERATE(IOWorkLoopCounter::DependencyTree, IOWorkLoopDependency, link, IOWorkLoopCounter::loadTagCompare);

/* sysctl stuff */

static int 
oid_sysctl(__unused struct sysctl_oid *oidp, __unused void *arg1, int arg2, struct sysctl_req *req)
{
	int error = EINVAL;
	uint32_t request = arg2;

	switch (request)
	{
		case kIOStatisticsGeneral:
			error = IOStatistics::getStatistics(req);
			break;
		case kIOStatisticsWorkLoop:
			error = IOStatistics::getWorkLoopStatistics(req);
			break;
		case kIOStatisticsUserClient:
			error = IOStatistics::getUserClientStatistics(req);
			break;		
		default:
			break;
	}

	return error;
}
 
SYSCTL_NODE(_debug, OID_AUTO, iokit_statistics, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IOStatistics");

static SYSCTL_PROC(_debug_iokit_statistics, OID_AUTO, general,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    0, kIOStatisticsGeneral, oid_sysctl, "S", "");

static SYSCTL_PROC(_debug_iokit_statistics, OID_AUTO, workloop,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    0, kIOStatisticsWorkLoop, oid_sysctl, "S", "");

static SYSCTL_PROC(_debug_iokit_statistics, OID_AUTO, userclient,
	    CTLTYPE_STRUCT | CTLFLAG_RW | CTLFLAG_NOAUTO | CTLFLAG_KERN | CTLFLAG_LOCKED,
	    0, kIOStatisticsUserClient, oid_sysctl, "S", "");

void IOStatistics::initialize()
{
	if (enabled) {
		return;
	}

	/* Only enabled if the boot argument is set. */
	if (!(kIOStatistics & gIOKitDebug)) {
		return;
	}
	
	sysctl_register_oid(&sysctl__debug_iokit_statistics_general);
	sysctl_register_oid(&sysctl__debug_iokit_statistics_workloop);
	sysctl_register_oid(&sysctl__debug_iokit_statistics_userclient);
	
	lock = IORWLockAlloc();
	if (!lock) {
		return;
	}
	
	nextWorkLoopDependency = (IOWorkLoopDependency*)kalloc(sizeof(IOWorkLoopDependency));
	if (!nextWorkLoopDependency) {
		return;
	}
	
	enabled = true;
}

void IOStatistics::onKextLoad(OSKext *kext, kmod_info_t *kmod_info) 
{
	KextNode *ke;

	assert(kext && kmod_info);

	if (!enabled) {
		return;
	}

	LOG(1, "IOStatistics::onKextLoad: %s, tag %d, address 0x%llx, address end 0x%llx\n",
		kext->getIdentifierCString(), kmod_info->id, (uint64_t)kmod_info->address, (uint64_t)(kmod_info->address + kmod_info->size));

	ke = (KextNode *)kalloc(sizeof(KextNode));
	if (!ke) {
		return;
	}

	memset(ke, 0, sizeof(KextNode));
	
	ke->kext = kext;
	ke->loadTag = kmod_info->id;
	ke->address = kmod_info->address;
	ke->address_end = kmod_info->address + kmod_info->size;

	SLIST_INIT(&ke->classList);
	TAILQ_INIT(&ke->userClientCallList);

	IORWLockWrite(lock);

	RB_INSERT(KextTree, &kextHead, ke);
	RB_INSERT(KextAddressTree, &kextAddressHead, ke);
	
	sequenceID++;
	loadedKexts++;
	lastKextIndex++;
	
	IORWLockUnlock(lock);
}

void IOStatistics::onKextUnload(OSKext *kext) 
{
	KextNode sought, *found;
	
	assert(kext);
	
	if (!enabled) {
		return;
	}

	LOG(1, "IOStatistics::onKextUnload: %s\n", kext->getIdentifierCString());
	
	IORWLockWrite(lock);

	sought.kext = kext;
	found = RB_FIND(KextTree, &kextHead, &sought);
	if (found) {
		IOWorkLoopCounter *wlc;
		IOUserClientProcessEntry *uce;

		/* Free up the list of counters */
		while ((wlc = SLIST_FIRST(&found->workLoopList))) {
			SLIST_REMOVE_HEAD(&found->workLoopList, link);
			kfree(wlc, sizeof(IOWorkLoopCounter));
		}

		/* Free up the user client list */
		while ((uce = TAILQ_FIRST(&found->userClientCallList))) {
			TAILQ_REMOVE(&found->userClientCallList, uce, link);
			kfree(uce, sizeof(IOUserClientProcessEntry));
		}

		/* Remove from kext trees */
		RB_REMOVE(KextTree, &kextHead, found);
		RB_REMOVE(KextAddressTree, &kextAddressHead, found);

		/*
		 * Clear a matching kextHint to avoid use after free in
		 * onClassAdded() for a class add after a KEXT unload.
		 */
		if (found == kextHint) {
			kextHint = NULL;
		}
		
		/* Finally, free the class node */
		kfree(found, sizeof(KextNode));
		
		sequenceID++;
		loadedKexts--;
	}
	else {
		panic("IOStatistics::onKextUnload: cannot find kext: %s", kext->getIdentifierCString());
	}

	IORWLockUnlock(lock);
}

void IOStatistics::onClassAdded(OSKext *parentKext, OSMetaClass *metaClass) 
{
	ClassNode *ce;
	KextNode soughtKext, *foundKext = NULL;

	assert(parentKext && metaClass);

	if (!enabled) {
		return;
	}

	LOG(1, "IOStatistics::onClassAdded: %s\n", metaClass->getClassName());

	ce = (ClassNode *)kalloc(sizeof(ClassNode));
	if (!ce) {
		return;	
	}

	memset(ce, 0, sizeof(ClassNode));

	IORWLockWrite(lock);

	/* Hinted? */
	if (kextHint && kextHint->kext == parentKext) {
		foundKext = kextHint;
	}
	else {
		soughtKext.kext = parentKext;
		foundKext = RB_FIND(KextTree, &kextHead, &soughtKext);
	}

	if (foundKext) {
		ClassNode soughtClass, *foundClass = NULL;
		const OSMetaClass *superClass;

		ce->metaClass = metaClass;
		ce->classID = lastClassIndex++;
		ce->parentKext = foundKext;
		
		/* Has superclass? */
	 	superClass = ce->metaClass->getSuperClass();
		if (superClass) {
			soughtClass.metaClass = superClass;
			foundClass = RB_FIND(ClassTree, &classHead, &soughtClass);
		}
		ce->superClassID = foundClass ? foundClass->classID : (uint32_t)(-1);

		SLIST_INIT(&ce->counterList);
		SLIST_INIT(&ce->userClientList);
		
		RB_INSERT(ClassTree, &classHead, ce);
		SLIST_INSERT_HEAD(&foundKext->classList, ce, lLink);
		
		foundKext->classes++;
		
		kextHint = foundKext;
		
		sequenceID++;	
		registeredClasses++;
	}
	else {
		panic("IOStatistics::onClassAdded: cannot find parent kext: %s", parentKext->getIdentifierCString());
	}
	
	IORWLockUnlock(lock);
}

void IOStatistics::onClassRemoved(OSKext *parentKext, OSMetaClass *metaClass) 
{
	ClassNode sought, *found;

	assert(parentKext && metaClass);

	if (!enabled) {
		return;
	}

	LOG(1, "IOStatistics::onClassRemoved: %s\n", metaClass->getClassName());

	IORWLockWrite(lock);

	sought.metaClass = metaClass;
	found = RB_FIND(ClassTree, &classHead, &sought);
	if (found) {
		IOEventSourceCounter *esc;
		IOUserClientCounter *ucc;
		
		/* Free up the list of counters */
		while ((esc = SLIST_FIRST(&found->counterList))) {
			SLIST_REMOVE_HEAD(&found->counterList, link);
			kfree(esc, sizeof(IOEventSourceCounter));
		}

		/* Free up the user client list */
		while ((ucc = SLIST_FIRST(&found->userClientList))) {
			SLIST_REMOVE_HEAD(&found->userClientList, link);
			kfree(ucc, sizeof(IOUserClientCounter));
		}

		/* Remove from class tree */
		RB_REMOVE(ClassTree, &classHead, found);
		
		/* Remove from parent */
		SLIST_REMOVE(&found->parentKext->classList, found, ClassNode, lLink);
		
		/* Finally, free the class node */
		kfree(found, sizeof(ClassNode));
		
		sequenceID++;
		registeredClasses--;
	}
	else {
		panic("IOStatistics::onClassRemoved: cannot find class: %s", metaClass->getClassName());
	}

	IORWLockUnlock(lock);
}

IOEventSourceCounter *IOStatistics::registerEventSource(OSObject *inOwner)
{
	IOEventSourceCounter *counter = NULL;
	ClassNode sought, *found = NULL;
	boolean_t createDummyCounter = FALSE;
	
	assert(inOwner);

	if (!enabled) {
		return NULL;
	}

	counter = (IOEventSourceCounter*)kalloc(sizeof(IOEventSourceCounter));
	if (!counter) {
		return NULL;
	}
	
	memset(counter, 0, sizeof(IOEventSourceCounter));

	IORWLockWrite(lock);

	/* Workaround for <rdar://problem/7158117> - create a dummy counter when inOwner is bad.
	 * We use retainCount here as our best indication that the pointer is awry.
	 */
	if (inOwner->retainCount > 0xFFFFFF) {
		kprintf("IOStatistics::registerEventSource - bad metaclass %p\n", inOwner);
		createDummyCounter = TRUE;
	}
	else {
		sought.metaClass = inOwner->getMetaClass();
		found = RB_FIND(ClassTree, &classHead, &sought);
	}

	if (found) {
		counter->parentClass = found;
		SLIST_INSERT_HEAD(&found->counterList, counter, link);
		registeredCounters++;
	}

	if (!(createDummyCounter || found)) {
		panic("IOStatistics::registerEventSource: cannot find parent class: %s", inOwner->getMetaClass()->getClassName());
	}
	
	IORWLockUnlock(lock);
	
	return counter;
}

void IOStatistics::unregisterEventSource(IOEventSourceCounter *counter)
{
	if (!counter) {
		return;
	}

	IORWLockWrite(lock);

	if (counter->parentClass) {
		SLIST_REMOVE(&counter->parentClass->counterList, counter, IOEventSourceCounter, link);
		registeredCounters--;
	}
	kfree(counter, sizeof(IOEventSourceCounter));
	
	IORWLockUnlock(lock);
}

IOWorkLoopCounter* IOStatistics::registerWorkLoop(IOWorkLoop *workLoop)
{
	IOWorkLoopCounter *counter = NULL;
	KextNode *found;

	assert(workLoop);

	if (!enabled) {
		return NULL;
	}

	counter = (IOWorkLoopCounter*)kalloc(sizeof(IOWorkLoopCounter));
	if (!counter) {
		return NULL;
	}
    
	memset(counter, 0, sizeof(IOWorkLoopCounter));

	found = getKextNodeFromBacktrace(TRUE);
	if (!found) {
		panic("IOStatistics::registerWorkLoop: cannot find parent kext");
	}

	counter->parentKext = found;
	counter->workLoop = workLoop;
	RB_INIT(&counter->dependencyHead);
	SLIST_INSERT_HEAD(&found->workLoopList, counter, link);
	registeredWorkloops++;

	releaseKextNode(found);

	return counter;
}

void IOStatistics::unregisterWorkLoop(IOWorkLoopCounter *counter)
{
	if (!counter) {
		return;
	}
	
	IORWLockWrite(lock);

	SLIST_REMOVE(&counter->parentKext->workLoopList, counter, IOWorkLoopCounter, link);
	kfree(counter, sizeof(IOWorkLoopCounter));
	registeredWorkloops--;
	
	IORWLockUnlock(lock);
}

IOUserClientCounter *IOStatistics::registerUserClient(IOUserClient *userClient)
{
	ClassNode sought, *found;
	IOUserClientCounter *counter = NULL;

	assert(userClient);

	if (!enabled) {
		return NULL;
	}

	counter = (IOUserClientCounter*)kalloc(sizeof(IOUserClientCounter));
	if (!counter) {
		return NULL;
	}
	
	memset(counter, 0, sizeof(IOUserClientCounter));

	IORWLockWrite(lock);

	sought.metaClass = userClient->getMetaClass();

	found = RB_FIND(ClassTree, &classHead, &sought);
	if (found) {
		counter->parentClass = found;
		SLIST_INSERT_HEAD(&found->userClientList, counter, link);
	}
	else {
		panic("IOStatistics::registerUserClient: cannot find parent class: %s", sought.metaClass->getClassName());
	}

	IORWLockUnlock(lock);

	return counter;
}

void IOStatistics::unregisterUserClient(IOUserClientCounter *counter)
{
	if (!counter) {
		return;
	}
	
	IORWLockWrite(lock);
	
	SLIST_REMOVE(&counter->parentClass->userClientList, counter, IOUserClientCounter, link);
	kfree(counter, sizeof(IOUserClientCounter));

	IORWLockUnlock(lock);
}

void IOStatistics::attachWorkLoopEventSource(IOWorkLoopCounter *wlc, IOEventSourceCounter *esc) 
{
	if (!wlc) {
        return;
	}
    
	IORWLockWrite(lock);
	
	if (!nextWorkLoopDependency) {
		return;
	}
	
	attachedEventSources++;
	wlc->attachedEventSources++;
	
	/* Track the kext dependency */
	nextWorkLoopDependency->loadTag = esc->parentClass->parentKext->loadTag;
	if (NULL == RB_INSERT(IOWorkLoopCounter::DependencyTree, &wlc->dependencyHead, nextWorkLoopDependency)) {
		nextWorkLoopDependency = (IOWorkLoopDependency*)kalloc(sizeof(IOWorkLoopDependency));
	}
    
	IORWLockUnlock(lock);
}

void IOStatistics::detachWorkLoopEventSource(IOWorkLoopCounter *wlc, IOEventSourceCounter *esc) 
{
	IOWorkLoopDependency sought, *found;
    
	if (!wlc) {
		return;
	}
    
	IORWLockWrite(lock);

	attachedEventSources--;
	wlc->attachedEventSources--;
	
	sought.loadTag = esc->parentClass->parentKext->loadTag;

	found = RB_FIND(IOWorkLoopCounter::DependencyTree, &wlc->dependencyHead, &sought);
	if (found) {
		RB_REMOVE(IOWorkLoopCounter::DependencyTree, &wlc->dependencyHead, found);
		kfree(found, sizeof(IOWorkLoopDependency));
	}

	IORWLockUnlock(lock);
}

int IOStatistics::getStatistics(sysctl_req *req)
{
	int error;
	uint32_t calculatedSize, size;
	char *buffer, *ptr;
	IOStatisticsHeader *header;

	assert(IOStatistics::enabled && req);
    
	IORWLockRead(IOStatistics::lock);

	/* Work out how much we need to allocate. IOStatisticsKext is of variable size. */
	calculatedSize = sizeof(IOStatisticsHeader) + 
					 sizeof(IOStatisticsGlobal) +
					(sizeof(IOStatisticsKext) * loadedKexts) + (sizeof(uint32_t) * registeredClasses) + 
					(sizeof(IOStatisticsMemory) * loadedKexts) +
					(sizeof(IOStatisticsClass) * registeredClasses) +
					(sizeof(IOStatisticsCounter) * registeredClasses) +
					(sizeof(IOStatisticsKextIdentifier) * loadedKexts) +
					(sizeof(IOStatisticsClassName) * registeredClasses);

	/* Size request? */
	if (req->oldptr == USER_ADDR_NULL) {
		error = SYSCTL_OUT(req, NULL, calculatedSize);
		goto exit;
	}
	
	/* Read only */
	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto exit;
	}

	buffer = (char*)kalloc(calculatedSize);
	if (!buffer) {
		error = ENOMEM;
		goto exit;
	}

	memset(buffer, 0, calculatedSize);
	
	ptr = buffer;
	
	header = (IOStatisticsHeader*)((void*)ptr);

	header->sig = IOSTATISTICS_SIG;
	header->ver = IOSTATISTICS_VER;

	header->seq = sequenceID;

	ptr += sizeof(IOStatisticsHeader);

	/* Global data - seq, timers, interrupts, etc) */
	header->globalStatsOffset = sizeof(IOStatisticsHeader);
	size = copyGlobalStatistics((IOStatisticsGlobal*)((void*)ptr));
	ptr += size;

	/* Kext statistics */
	header->kextStatsOffset = header->globalStatsOffset + size;
	size = copyKextStatistics((IOStatisticsKext*)((void*)ptr));
	ptr += size;

	/* Memory allocation info */
	header->memoryStatsOffset = header->kextStatsOffset + size;
	size = copyMemoryStatistics((IOStatisticsMemory*)((void*)ptr));
	ptr += size;
	
	/* Class statistics */
	header->classStatsOffset = header->memoryStatsOffset + size;
	size = copyClassStatistics((IOStatisticsClass*)((void*)ptr));
	ptr += size;
	
	/* Dynamic class counter data */
	header->counterStatsOffset = header->classStatsOffset + size;
	size = copyCounterStatistics((IOStatisticsCounter*)((void*)ptr));
	ptr += size;
	
	/* Kext identifiers */
	header->kextIdentifiersOffset = header->counterStatsOffset + size;
	size = copyKextIdentifiers((IOStatisticsKextIdentifier*)((void*)ptr));
	ptr += size;

	/* Class names */
	header->classNamesOffset = header->kextIdentifiersOffset + size;
	size = copyClassNames((IOStatisticsClassName*)ptr);
	ptr += size;
	
	LOG(2, "IOStatistics::getStatistics - calculatedSize 0x%x, kexts 0x%x, classes 0x%x.\n",
	 	calculatedSize, loadedKexts, registeredClasses);

	assert( (uint32_t)(ptr - buffer) == calculatedSize );

	error = SYSCTL_OUT(req, buffer, calculatedSize);

	kfree(buffer, calculatedSize);

exit:
	IORWLockUnlock(IOStatistics::lock);
	return error;
}

int IOStatistics::getWorkLoopStatistics(sysctl_req *req)
{
	int error;
	uint32_t calculatedSize, size;
	char *buffer;
	IOStatisticsWorkLoopHeader *header;

	assert(IOStatistics::enabled && req);

	IORWLockRead(IOStatistics::lock);

	/* Approximate how much we need to allocate (worse case estimate) */
	calculatedSize = sizeof(IOStatisticsWorkLoop) * registeredWorkloops +
					 sizeof(uint32_t) * attachedEventSources;

	/* Size request? */
	if (req->oldptr == USER_ADDR_NULL) {
		error = SYSCTL_OUT(req, NULL, calculatedSize);
		goto exit;
	}
	
	/* Read only */
	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto exit;
	}

	buffer = (char*)kalloc(calculatedSize);
	if (!buffer) {
		error = ENOMEM;
		goto exit;
	}

	header = (IOStatisticsWorkLoopHeader*)((void*)buffer);
	
	header->sig = IOSTATISTICS_SIG_WORKLOOP;
	header->ver = IOSTATISTICS_VER;

	header->seq = sequenceID;
	
	header->workloopCount = registeredWorkloops;

	size = copyWorkLoopStatistics(&header->workLoopStats);

	LOG(2, "IOStatistics::getWorkLoopStatistics: calculatedSize %d, size %d\n", calculatedSize, size);

	assert( size <= calculatedSize );

	error = SYSCTL_OUT(req, buffer, size);

	kfree(buffer, calculatedSize);

exit:
	IORWLockUnlock(IOStatistics::lock);
	return error;
}

int IOStatistics::getUserClientStatistics(sysctl_req *req)
{	
	int error;
	uint32_t calculatedSize, size;
	char *buffer;
	uint32_t requestedLoadTag = 0;
	IOStatisticsUserClientHeader *header;

	assert(IOStatistics::enabled && req);

	IORWLockRead(IOStatistics::lock);

	/* Work out how much we need to allocate */
	calculatedSize = sizeof(IOStatisticsUserClientHeader) + 
					 sizeof(IOStatisticsUserClientCall) * IOKIT_STATISTICS_RECORDED_USERCLIENT_PROCS * loadedKexts;
	
	/* Size request? */
	if (req->oldptr == USER_ADDR_NULL) {
		error = SYSCTL_OUT(req, NULL, calculatedSize);
		goto exit;
	}

	/* Kext request (potentially) valid? */
	if (!req->newptr || req->newlen < sizeof(requestedLoadTag)) {
		error = EINVAL;
		goto exit;
	}

	SYSCTL_IN(req, &requestedLoadTag, sizeof(requestedLoadTag));
	
	LOG(2, "IOStatistics::getUserClientStatistics - requesting kext w/load tag: %d\n", requestedLoadTag);

	buffer = (char*)kalloc(calculatedSize);
	if (!buffer) {
		error = ENOMEM;
		goto exit;
	}

	header = (IOStatisticsUserClientHeader*)((void*)buffer);

	header->sig = IOSTATISTICS_SIG_USERCLIENT;
	header->ver = IOSTATISTICS_VER;
	
	header->seq = sequenceID;

	header->processes = 0;

	size = copyUserClientStatistics(header, requestedLoadTag);
	
	assert((sizeof(IOStatisticsUserClientHeader) + size) <= calculatedSize);
	
	if (size) {
		error = SYSCTL_OUT(req, buffer, sizeof(IOStatisticsUserClientHeader) + size);
	}
	else {
		error = EINVAL;
	}

	kfree(buffer, calculatedSize);

exit:
	IORWLockUnlock(IOStatistics::lock);
	return error;
}

uint32_t IOStatistics::copyGlobalStatistics(IOStatisticsGlobal *stats)
{
	stats->kextCount = loadedKexts;
	stats->classCount = registeredClasses;
	stats->workloops = registeredWorkloops;
	
	return sizeof(IOStatisticsGlobal);
}

uint32_t IOStatistics::copyKextStatistics(IOStatisticsKext *stats)
{
	KextNode *ke;
	ClassNode *ce;
	uint32_t index = 0;

	RB_FOREACH(ke, KextTree, &kextHead) {
		stats->loadTag = ke->loadTag;
		ke->kext->getSizeInfo(&stats->loadSize, &stats->wiredSize);

		stats->classes = ke->classes;

		/* Append indices of owned classes */
		SLIST_FOREACH(ce, &ke->classList, lLink) {
			stats->classIndexes[index++] = ce->classID;
		}
		
		stats = (IOStatisticsKext *)((void*)((char*)stats + sizeof(IOStatisticsKext) + (ke->classes * sizeof(uint32_t))));
	}

	return (sizeof(IOStatisticsKext) * loadedKexts + sizeof(uint32_t) * registeredClasses);
}

uint32_t IOStatistics::copyMemoryStatistics(IOStatisticsMemory *stats)
{
	KextNode *ke;

	RB_FOREACH(ke, KextTree, &kextHead) {
		stats->allocatedSize = ke->memoryCounters[kIOStatisticsMalloc];
		stats->freedSize = ke->memoryCounters[kIOStatisticsFree]; 
		stats->allocatedAlignedSize = ke->memoryCounters[kIOStatisticsMallocAligned];
		stats->freedAlignedSize = ke->memoryCounters[kIOStatisticsFreeAligned];
		stats->allocatedContiguousSize = ke->memoryCounters[kIOStatisticsMallocContiguous];
		stats->freedContiguousSize = ke->memoryCounters[kIOStatisticsFreeContiguous];
		stats->allocatedPageableSize = ke->memoryCounters[kIOStatisticsMallocPageable];
		stats->freedPageableSize = ke->memoryCounters[kIOStatisticsFreePageable];
		stats++;
	}
	
	return (sizeof(IOStatisticsMemory) * loadedKexts);
}

uint32_t IOStatistics::copyClassStatistics(IOStatisticsClass *stats)
{
	KextNode *ke;
	ClassNode *ce;

	RB_FOREACH(ke, KextTree, &kextHead) {
		SLIST_FOREACH(ce, &ke->classList, lLink) {
			stats->classID = ce->classID;
			stats->superClassID = ce->superClassID;		
			stats->classSize = ce->metaClass->getClassSize();

			stats++;
		}
	}

	return sizeof(IOStatisticsClass) * registeredClasses;
}

uint32_t IOStatistics::copyCounterStatistics(IOStatisticsCounter *stats)
{
	KextNode *ke;
	ClassNode *ce;

	RB_FOREACH(ke, KextTree, &kextHead) {
		SLIST_FOREACH(ce, &ke->classList, lLink) {
			IOUserClientCounter *userClientCounter;
			IOEventSourceCounter *counter;

			stats->classID = ce->classID;
			stats->classInstanceCount = ce->metaClass->getInstanceCount();

			IOStatisticsUserClients *uc = &stats->userClientStatistics;

			/* User client counters */
			SLIST_FOREACH(userClientCounter, &ce->userClientList, link) {
				uc->clientCalls += userClientCounter->clientCalls;
				uc->created++;
			}

			IOStatisticsInterruptEventSources *iec = &stats->interruptEventSourceStatistics;
			IOStatisticsInterruptEventSources *fiec = &stats->filterInterruptEventSourceStatistics;
			IOStatisticsTimerEventSources *tec = &stats->timerEventSourceStatistics;
			IOStatisticsCommandGates *cgc = &stats->commandGateStatistics;
			IOStatisticsCommandQueues *cqc = &stats->commandQueueStatistics;
			IOStatisticsDerivedEventSources *dec = &stats->derivedEventSourceStatistics;

			/* Event source counters */
			SLIST_FOREACH(counter, &ce->counterList, link) {
				switch (counter->type) {	
					case kIOStatisticsInterruptEventSourceCounter:
						iec->created++;
						iec->produced += counter->u.interrupt.produced;
						iec->checksForWork += counter->u.interrupt.checksForWork;
						break;
					case kIOStatisticsFilterInterruptEventSourceCounter:
						fiec->created++;
						fiec->produced += counter->u.filter.produced;
						fiec->checksForWork += counter->u.filter.checksForWork;
						break;
					case kIOStatisticsTimerEventSourceCounter:
						tec->created++;
						tec->timeouts += counter->u.timer.timeouts;
						tec->checksForWork += counter->u.timer.checksForWork;
						tec->timeOnGate += counter->timeOnGate;
						tec->closeGateCalls += counter->closeGateCalls;
						tec->openGateCalls += counter->openGateCalls;
						break;
					case kIOStatisticsCommandGateCounter:
						cgc->created++;
						cgc->timeOnGate += counter->timeOnGate;
						cgc->actionCalls += counter->u.commandGate.actionCalls;
						break;
					case kIOStatisticsCommandQueueCounter:
						cqc->created++;
						cqc->actionCalls += counter->u.commandQueue.actionCalls;
						break;
					case kIOStatisticsDerivedEventSourceCounter:
						dec->created++;
						dec->timeOnGate += counter->timeOnGate;
						dec->closeGateCalls += counter->closeGateCalls;
						dec->openGateCalls += counter->openGateCalls;
						break;
					default:
						break;
				}
			}
		
			stats++;
		}
	}

	return sizeof(IOStatisticsCounter) * registeredClasses;
}

uint32_t IOStatistics::copyKextIdentifiers(IOStatisticsKextIdentifier *kextIDs)
{
	KextNode *ke;

	RB_FOREACH(ke, KextTree, &kextHead) {
		strncpy(kextIDs->identifier, ke->kext->getIdentifierCString(), kIOStatisticsDriverNameLength);
		kextIDs++;
	}

	return (sizeof(IOStatisticsKextIdentifier) * loadedKexts);
}

uint32_t IOStatistics::copyClassNames(IOStatisticsClassName *classNames)
{
	KextNode *ke;
	ClassNode *ce;

	RB_FOREACH(ke, KextTree, &kextHead) {
		SLIST_FOREACH(ce, &ke->classList, lLink) {
			strncpy(classNames->name, ce->metaClass->getClassName(), kIOStatisticsClassNameLength);
			classNames++;
		}
	}
		
	return (sizeof(IOStatisticsClassName) * registeredClasses);
}

uint32_t IOStatistics::copyWorkLoopStatistics(IOStatisticsWorkLoop *stats) 
{
	KextNode *ke;
	IOWorkLoopCounter *wlc;
	IOWorkLoopDependency *dependentNode;
	uint32_t size, accumulatedSize = 0;

	RB_FOREACH(ke, KextTree, &kextHead) {
		SLIST_FOREACH(wlc, &ke->workLoopList, link) {
			stats->kextLoadTag = ke->loadTag;
			stats->attachedEventSources = wlc->attachedEventSources;
			stats->timeOnGate = wlc->timeOnGate;
			stats->dependentKexts = 0;
			RB_FOREACH(dependentNode, IOWorkLoopCounter::DependencyTree, &wlc->dependencyHead) {
				stats->dependentKextLoadTags[stats->dependentKexts] = dependentNode->loadTag;
				stats->dependentKexts++;
			}
			
			size = sizeof(IOStatisticsWorkLoop) + (sizeof(uint32_t) * stats->dependentKexts);
			
			accumulatedSize += size;
			stats = (IOStatisticsWorkLoop*)((void*)((char*)stats + size));
		}
	}

	return accumulatedSize;
}

uint32_t IOStatistics::copyUserClientStatistics(IOStatisticsUserClientHeader *stats, uint32_t loadTag) 
{
	KextNode *sought, *found = NULL;
	uint32_t procs = 0;
	IOUserClientProcessEntry *processEntry;

	RB_FOREACH(sought, KextTree, &kextHead) {
		if (sought->loadTag == loadTag) {
			found = sought;
			break;
		}
	}
	
	if (!found) {
		return 0;
	}

	TAILQ_FOREACH(processEntry, &found->userClientCallList, link) {
		strncpy(stats->userClientCalls[procs].processName, processEntry->processName, kIOStatisticsProcessNameLength);
		stats->userClientCalls[procs].pid = processEntry->pid;
		stats->userClientCalls[procs].calls = processEntry->calls;
		stats->processes++;
		procs++;
	}

	return sizeof(IOStatisticsUserClientCall) * stats->processes;
}

void IOStatistics::storeUserClientCallInfo(IOUserClient *userClient, IOUserClientCounter *counter)
{	
	OSString *ossUserClientCreator = NULL;
	int32_t pid = -1;
	KextNode *parentKext;
	IOUserClientProcessEntry *entry, *nextEntry, *prevEntry = NULL;
	uint32_t count = 0;
	const char *ptr = NULL;
	OSObject *obj;
	
	/* TODO: see if this can be more efficient */
	obj = userClient->copyProperty("IOUserClientCreator",
					gIOServicePlane,
					kIORegistryIterateRecursively | kIORegistryIterateParents);

	if (!obj)
		goto err_nounlock;

	ossUserClientCreator = OSDynamicCast(OSString, obj);

	if (ossUserClientCreator) {
		uint32_t len, lenIter = 0; 
		
		ptr = ossUserClientCreator->getCStringNoCopy();
		len = ossUserClientCreator->getLength();
		
		while ((*ptr != ' ') && (lenIter < len)) {
			ptr++;
			lenIter++;
		}
		
		if (lenIter < len) {
			ptr++; // Skip the space
			lenIter++;
			pid = 0;
			while ( (*ptr != ',') && (lenIter < len)) {
				pid = pid*10 + (*ptr - '0');
				ptr++;
				lenIter++;
			}
			
			if(lenIter == len) {
				pid = -1;
			} else {
				ptr += 2;
			}
		}
	}
	
	if (-1 == pid)
		goto err_nounlock;
	
	IORWLockWrite(lock);

	parentKext = counter->parentClass->parentKext;

	TAILQ_FOREACH(entry, &parentKext->userClientCallList, link) {
		if (entry->pid == pid) {
			/* Found, so increment count and move to the head */
			entry->calls++;
			if (count) {
				TAILQ_REMOVE(&parentKext->userClientCallList, entry, link);
				break;
			}
			else {
				/* At the head already, so increment and return */
				goto err_unlock;
			}
		}
		
		count++;
	}

	if (!entry) {
		if (count == IOKIT_STATISTICS_RECORDED_USERCLIENT_PROCS) {
			/* Max elements hit, so reuse the last */
			entry = TAILQ_LAST(&parentKext->userClientCallList, ProcessEntryList);
			TAILQ_REMOVE(&parentKext->userClientCallList, entry, link);
		}
		else {
			/* Otherwise, allocate a new entry */
			entry = (IOUserClientProcessEntry*)kalloc(sizeof(IOUserClientProcessEntry));
			if (!entry) {
			    IORWLockUnlock(lock);
				return;
			}
		}

		strncpy(entry->processName, ptr, kIOStatisticsProcessNameLength);
		entry->pid = pid;
		entry->calls = 1;
	}
	
	TAILQ_FOREACH(nextEntry, &parentKext->userClientCallList, link) {
		if (nextEntry->calls <= entry->calls)
			break;
			
		prevEntry = nextEntry;
	}
	
	if (!prevEntry)
		TAILQ_INSERT_HEAD(&parentKext->userClientCallList, entry, link);
	else
		TAILQ_INSERT_AFTER(&parentKext->userClientCallList, prevEntry, entry, link);
	
err_unlock:
	IORWLockUnlock(lock);
        
err_nounlock:
	if (obj)
		obj->release();
}

void IOStatistics::countUserClientCall(IOUserClient *client) {
	IOUserClient::ExpansionData *data;
	IOUserClientCounter *counter;
    
	/* Guard against an uninitialized client object - <rdar://problem/8577946> */
	if (!(data = client->reserved)) {
		return;
	}
    
	if ((counter = data->counter)) {
		storeUserClientCallInfo(client, counter);
		OSIncrementAtomic(&counter->clientCalls);
	}
}

KextNode *IOStatistics::getKextNodeFromBacktrace(boolean_t write) {
	const uint32_t btMin = 3;

	void *bt[16];
	unsigned btCount = sizeof(bt) / sizeof(bt[0]);
	vm_offset_t *scanAddr = NULL;
	uint32_t i;
	KextNode *found = NULL, *ke = NULL;
    
	btCount = OSBacktrace(bt, btCount);

	if (write) {
		IORWLockWrite(lock);
	} else {
		IORWLockRead(lock);
	}

	/* Ignore first levels */
	scanAddr = (vm_offset_t *)&bt[btMin - 1];

	for (i = btMin - 1; i < btCount; i++, scanAddr++) {
		ke = RB_ROOT(&kextAddressHead);
		while (ke) {
			if (*scanAddr < ke->address) {
				ke = RB_LEFT(ke, addressLink);
			}
			else {
				if ((*scanAddr < ke->address_end) && (*scanAddr >= ke->address)) {
 					if (!ke->kext->isKernelComponent()) {
 						return ke;
					} else {
						found = ke;
					}
				}
				ke = RB_RIGHT(ke, addressLink);
			}
		}
	}

	if (!found) {
		IORWLockUnlock(lock);
	}
  
	return found;
}
  
void IOStatistics::releaseKextNode(KextNode *node) {
#pragma unused(node)
	IORWLockUnlock(lock);
}

/* IOLib allocations */
void IOStatistics::countAlloc(uint32_t index, vm_size_t size) {
	KextNode *ke;
  
	if (!enabled) {
		return;
	}

	ke = getKextNodeFromBacktrace(FALSE);
	if (ke) {
		OSAddAtomic(size, &ke->memoryCounters[index]);
		releaseKextNode(ke);
	}
}

#endif /* IOKITSTATS */
