/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
 */

#include <IOKit/perfcontrol/IOPerfControl.h>

#include <stdatomic.h>

#include <kern/thread_group.h>

#undef super
#define super OSObject
OSDefineMetaClassAndStructors(IOPerfControlClient, OSObject);

bool
IOPerfControlClient::init(IOService *driver, uint64_t maxWorkCapacity)
{
	if (!super::init()) {
		return false;
	}

	interface = PerfControllerInterface{
		.version = 0,
		.registerDevice =
		    [](IOService *device) {
			    return kIOReturnSuccess;
		    },
		.unregisterDevice =
		    [](IOService *device) {
			    return kIOReturnSuccess;
		    },
		.workCanSubmit =
		    [](IOService *device, PerfControllerInterface::WorkState *state, WorkSubmitArgs *args) {
			    return false;
		    },
		.workSubmit =
		    [](IOService *device, uint64_t token, PerfControllerInterface::WorkState *state, WorkSubmitArgs *args) {
		    },
		.workBegin =
		    [](IOService *device, uint64_t token, PerfControllerInterface::WorkState *state, WorkBeginArgs *args) {
		    },
		.workEnd =
		    [](IOService *device, uint64_t token, PerfControllerInterface::WorkState *state, WorkEndArgs *args, bool done) {
		    },
	};

	interfaceLock = IOLockAlloc();
	if (!interfaceLock) {
		goto error;
	}

	deviceRegistrationList = OSSet::withCapacity(4);
	if (!deviceRegistrationList) {
		goto error;
	}

	bzero(workTable, sizeof(workTable));
	memset(&workTable[kIOPerfControlClientWorkUntracked], ~0, sizeof(WorkTableEntry));
	workTableNextIndex = kIOPerfControlClientWorkUntracked + 1;

	workTableLock = IOSimpleLockAlloc();
	if (!workTableLock) {
		goto error;
	}

	// TODO: check sum(maxWorkCapacities) < table size

	return true;

error:
	if (interfaceLock) {
		IOLockFree(interfaceLock);
	}
	if (deviceRegistrationList) {
		deviceRegistrationList->release();
	}
	if (workTableLock) {
		IOSimpleLockFree(workTableLock);
	}
	return false;
}

IOPerfControlClient *_Atomic gSharedClient = nullptr;

IOPerfControlClient *
IOPerfControlClient::copyClient(IOService *driver, uint64_t maxWorkCapacity)
{
	IOPerfControlClient *client = atomic_load_explicit(&gSharedClient, memory_order_acquire);
	if (client == nullptr) {
		IOPerfControlClient *expected = client;
		client = new IOPerfControlClient;
		if (!client || !client->init(driver, maxWorkCapacity)) {
			panic("could not create IOPerfControlClient");
		}
		if (!atomic_compare_exchange_strong_explicit(&gSharedClient, &expected, client, memory_order_acq_rel,
		    memory_order_acquire)) {
			client->release();
			client = expected;
		}
	}
	// TODO: add maxWorkCapacity to existing client
	client->retain();
	return client;
}

uint64_t
IOPerfControlClient::allocateToken(thread_group *thread_group)
{
	uint64_t token = kIOPerfControlClientWorkUntracked;


	return token;
}

void
IOPerfControlClient::deallocateToken(uint64_t token)
{
}

bool
IOPerfControlClient::getEntryForToken(uint64_t token, IOPerfControlClient::WorkTableEntry &entry)
{
	if (token == kIOPerfControlClientWorkUntracked) {
		return false;
	}

	if (token >= kWorkTableNumEntries) {
		panic("Invalid work token (%llu): index out of bounds.", token);
	}

	entry = workTable[token];
	auto *thread_group = entry.thread_group;
	assertf(thread_group, "Invalid work token: %llu", token);
	return thread_group != nullptr;
}

void
IOPerfControlClient::markEntryStarted(uint64_t token, bool started)
{
	if (token == kIOPerfControlClientWorkUntracked) {
		return;
	}

	if (token >= kWorkTableNumEntries) {
		panic("Invalid work token (%llu): index out of bounds.", token);
	}

	workTable[token].started = started;
}

IOReturn
IOPerfControlClient::registerDevice(__unused IOService *driver, IOService *device)
{
	IOReturn ret = kIOReturnSuccess;

	IOLockLock(interfaceLock);

	if (interface.version > 0) {
		ret = interface.registerDevice(device);
	} else {
		deviceRegistrationList->setObject(device);
	}

	IOLockUnlock(interfaceLock);

	return ret;
}

void
IOPerfControlClient::unregisterDevice(__unused IOService *driver, IOService *device)
{
	IOLockLock(interfaceLock);

	if (interface.version > 0) {
		interface.unregisterDevice(device);
	} else {
		deviceRegistrationList->removeObject(device);
	}

	IOLockUnlock(interfaceLock);
}

uint64_t
IOPerfControlClient::workSubmit(IOService *device, WorkSubmitArgs *args)
{
	return kIOPerfControlClientWorkUntracked;
}

uint64_t
IOPerfControlClient::workSubmitAndBegin(IOService *device, WorkSubmitArgs *submitArgs, WorkBeginArgs *beginArgs)
{
	return kIOPerfControlClientWorkUntracked;
}

void
IOPerfControlClient::workBegin(IOService *device, uint64_t token, WorkBeginArgs *args)
{
}

void
IOPerfControlClient::workEnd(IOService *device, uint64_t token, WorkEndArgs *args, bool done)
{
}

IOReturn
IOPerfControlClient::registerPerformanceController(PerfControllerInterface pci)
{
	IOReturn result = kIOReturnError;

	IOLockLock(interfaceLock);

	if (interface.version == 0 && pci.version > 0) {
		assert(pci.registerDevice && pci.unregisterDevice && pci.workCanSubmit && pci.workSubmit && pci.workBegin && pci.workEnd);
		result = kIOReturnSuccess;

		OSObject *obj;
		while ((obj = deviceRegistrationList->getAnyObject())) {
			IOService *device = OSDynamicCast(IOService, obj);
			if (device) {
				pci.registerDevice(device);
			}
			deviceRegistrationList->removeObject(obj);
		}

		interface = pci;
	}

	IOLockUnlock(interfaceLock);

	return result;
}
