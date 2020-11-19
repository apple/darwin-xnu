/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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

extern "C" {
#include <kern/queue.h>
#include <kern/sched_prim.h>
#include <machine/machine_routines.h>
}

#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOPlatformActions.h>
#include "IOKitKernelInternal.h"

static IOLock *gIOPlatformActionsLock;

typedef kern_return_t (*iocpu_platform_action_t)(void * refcon0, void * refcon1, uint32_t priority,
    void * param1, void * param2, void * param3,
    const char * name);

struct iocpu_platform_action_entry {
	queue_chain_t                     link;
	iocpu_platform_action_t           action;
	int32_t                           priority;
	const char *                      name;
	void *                            refcon0;
	void *                            refcon1;
	boolean_t                         callout_in_progress;
	struct iocpu_platform_action_entry * alloc_list;
};
typedef struct iocpu_platform_action_entry iocpu_platform_action_entry_t;

enum {
	kQueueSleep       = 0,
	kQueueWake        = 1,
	kQueueQuiesce     = 2,
	kQueueActive      = 3,
	kQueueHaltRestart = 4,
	kQueuePanic       = 5,
	kQueueCount       = 6
};

const OSSymbol *                gIOPlatformSleepActionKey;
const OSSymbol *                gIOPlatformWakeActionKey;
const OSSymbol *                gIOPlatformQuiesceActionKey;
const OSSymbol *                gIOPlatformActiveActionKey;
const OSSymbol *                gIOPlatformHaltRestartActionKey;
const OSSymbol *                gIOPlatformPanicActionKey;

static queue_head_t             gActionQueues[kQueueCount];
static const OSSymbol *         gActionSymbols[kQueueCount];

static bool
IOInstallServicePlatformAction(IOService * service, uint32_t qidx);

static void
iocpu_add_platform_action(queue_head_t * queue, iocpu_platform_action_entry_t * entry)
{
	iocpu_platform_action_entry_t * next;

	queue_iterate(queue, next, iocpu_platform_action_entry_t *, link)
	{
		if (next->priority > entry->priority) {
			queue_insert_before(queue, entry, next, iocpu_platform_action_entry_t *, link);
			return;
		}
	}
	queue_enter(queue, entry, iocpu_platform_action_entry_t *, link); // at tail
}

static void
iocpu_remove_platform_action(iocpu_platform_action_entry_t * entry)
{
	remque(&entry->link);
}

static kern_return_t
iocpu_run_platform_actions(queue_head_t * queue, uint32_t first_priority, uint32_t last_priority,
    void * param1, void * param2, void * param3, boolean_t allow_nested_callouts)
{
	kern_return_t                ret = KERN_SUCCESS;
	kern_return_t                result = KERN_SUCCESS;
	iocpu_platform_action_entry_t * next;

	queue_iterate(queue, next, iocpu_platform_action_entry_t *, link)
	{
		uint32_t pri = (next->priority < 0) ? -next->priority : next->priority;
		if ((pri >= first_priority) && (pri <= last_priority)) {
			//kprintf("[%p]", next->action);
			if (!allow_nested_callouts && !next->callout_in_progress) {
				next->callout_in_progress = TRUE;
				ret = (*next->action)(next->refcon0, next->refcon1, pri, param1, param2, param3, next->name);
				next->callout_in_progress = FALSE;
			} else if (allow_nested_callouts) {
				ret = (*next->action)(next->refcon0, next->refcon1, pri, param1, param2, param3, next->name);
			}
		}
		if (KERN_SUCCESS == result) {
			result = ret;
		}
	}
	return result;
}

extern "C" kern_return_t
IOCPURunPlatformQuiesceActions(void)
{
	assert(preemption_enabled() == false);
	return iocpu_run_platform_actions(&gActionQueues[kQueueQuiesce], 0, 0U - 1,
	           NULL, NULL, NULL, TRUE);
}

extern "C" kern_return_t
IOCPURunPlatformActiveActions(void)
{
	assert(preemption_enabled() == false);
	ml_hibernate_active_pre();
	kern_return_t result = iocpu_run_platform_actions(&gActionQueues[kQueueActive], 0, 0U - 1,
	    NULL, NULL, NULL, TRUE);
	ml_hibernate_active_post();
	return result;
}

extern "C" kern_return_t
IOCPURunPlatformHaltRestartActions(uint32_t message)
{
	if (!gActionQueues[kQueueHaltRestart].next) {
		return kIOReturnNotReady;
	}
	return iocpu_run_platform_actions(&gActionQueues[kQueueHaltRestart], 0, 0U - 1,
	           (void *)(uintptr_t) message, NULL, NULL, TRUE);
}

extern "C" kern_return_t
IOCPURunPlatformPanicActions(uint32_t message, uint32_t details)
{
	// Don't allow nested calls of panic actions
	if (!gActionQueues[kQueuePanic].next) {
		return kIOReturnNotReady;
	}
	return iocpu_run_platform_actions(&gActionQueues[kQueuePanic], 0, 0U - 1,
	           (void *)(uintptr_t) message, (void *)(uintptr_t) details, NULL, FALSE);
}

extern "C" kern_return_t
IOCPURunPlatformPanicSyncAction(void *addr, uint32_t offset, uint32_t len)
{
	PE_panic_save_context_t context = {
		.psc_buffer = addr,
		.psc_offset = offset,
		.psc_length = len
	};

	// Don't allow nested calls of panic actions
	if (!gActionQueues[kQueuePanic].next) {
		return kIOReturnNotReady;
	}
	return iocpu_run_platform_actions(&gActionQueues[kQueuePanic], 0, 0U - 1,
	           (void *)(uintptr_t)(kPEPanicSync), &context, NULL, FALSE);
}

void
IOPlatformActionsPreSleep(void)
{
	iocpu_run_platform_actions(&gActionQueues[kQueueSleep], 0, 0U - 1,
	    NULL, NULL, NULL, TRUE);
}

void
IOPlatformActionsPostResume(void)
{
	iocpu_run_platform_actions(&gActionQueues[kQueueWake], 0, 0U - 1,
	    NULL, NULL, NULL, TRUE);
}

void
IOPlatformActionsInitialize(void)
{
	gIOPlatformActionsLock = IOLockAlloc();

	for (uint32_t qidx = kQueueSleep; qidx < kQueueCount; qidx++) {
		queue_init(&gActionQueues[qidx]);
	}

	gIOPlatformSleepActionKey        = gActionSymbols[kQueueSleep]
	            = OSSymbol::withCStringNoCopy(kIOPlatformSleepActionKey);
	gIOPlatformWakeActionKey         = gActionSymbols[kQueueWake]
	            = OSSymbol::withCStringNoCopy(kIOPlatformWakeActionKey);
	gIOPlatformQuiesceActionKey      = gActionSymbols[kQueueQuiesce]
	            = OSSymbol::withCStringNoCopy(kIOPlatformQuiesceActionKey);
	gIOPlatformActiveActionKey       = gActionSymbols[kQueueActive]
	            = OSSymbol::withCStringNoCopy(kIOPlatformActiveActionKey);
	gIOPlatformHaltRestartActionKey  = gActionSymbols[kQueueHaltRestart]
	            = OSSymbol::withCStringNoCopy(kIOPlatformHaltRestartActionKey);
	gIOPlatformPanicActionKey = gActionSymbols[kQueuePanic]
	            = OSSymbol::withCStringNoCopy(kIOPlatformPanicActionKey);
}

static kern_return_t
IOServicePlatformAction(void * refcon0, void * refcon1, uint32_t priority,
    void * param1, void * param2, void * param3,
    const char * service_name)
{
	IOReturn         ret;
	IOService *      service  = (IOService *)      refcon0;
	const OSSymbol * function = (const OSSymbol *) refcon1;

	IOLog("%s -> %s\n", function->getCStringNoCopy(), service_name);

	ret = service->callPlatformFunction(function, false,
	    (void *)(uintptr_t) priority, param1, param2, param3);

	return ret;
}

static bool
IOInstallServicePlatformAction(IOService * service, uint32_t qidx)
{
	iocpu_platform_action_entry_t * entry;
	OSNumber *       num;
	uint32_t         priority;
	const OSSymbol * key = gActionSymbols[qidx];
	queue_head_t *   queue = &gActionQueues[qidx];
	bool             reverse;

	num = OSDynamicCast(OSNumber, service->getProperty(key));
	if (!num) {
		return true;
	}

	reverse = false;
	switch (qidx) {
	case kQueueWake:
	case kQueueActive:
		reverse = true;
		break;
	}
	queue_iterate(queue, entry, iocpu_platform_action_entry_t *, link)
	{
		if (service == entry->refcon0) {
			return true;
		}
	}

	entry = IONew(iocpu_platform_action_entry_t, 1);
	entry->action = &IOServicePlatformAction;
	entry->name = service->getName();
	priority = num->unsigned32BitValue();
	if (reverse) {
		entry->priority = -priority;
	} else {
		entry->priority = priority;
	}
	entry->refcon0 = service;
	entry->refcon1 = (void *) key;
	entry->callout_in_progress = FALSE;

	iocpu_add_platform_action(queue, entry);
	return false;
}


IOReturn
IOInstallServicePlatformActions(IOService * service)
{
	IOLockLock(gIOPlatformActionsLock);

	IOInstallServicePlatformAction(service, kQueueHaltRestart);
	IOInstallServicePlatformAction(service, kQueuePanic);

	IOLockUnlock(gIOPlatformActionsLock);

	return kIOReturnSuccess;
}

IOReturn
IOInstallServiceSleepPlatformActions(IOService * service)
{
	IOLockLock(gIOPlatformActionsLock);

	for (uint32_t qidx = kQueueSleep; qidx <= kQueueActive; qidx++) {
		IOInstallServicePlatformAction(service, qidx);
	}

	IOLockUnlock(gIOPlatformActionsLock);

	return kIOReturnSuccess;
}

IOReturn
IORemoveServicePlatformActions(IOService * service)
{
	iocpu_platform_action_entry_t * entry;
	iocpu_platform_action_entry_t * next;

	IOLockLock(gIOPlatformActionsLock);

	for (uint32_t qidx = kQueueSleep; qidx < kQueueCount; qidx++) {
		next = (typeof(entry))queue_first(&gActionQueues[qidx]);
		while (!queue_end(&gActionQueues[qidx], &next->link)) {
			entry = next;
			next = (typeof(entry))queue_next(&entry->link);
			if (service == entry->refcon0) {
				iocpu_remove_platform_action(entry);
				IODelete(entry, iocpu_platform_action_entry_t, 1);
			}
		}
	}

	IOLockUnlock(gIOPlatformActionsLock);

	return kIOReturnSuccess;
}
