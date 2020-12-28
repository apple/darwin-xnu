/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
 */

#include <IOKit/perfcontrol/IOPerfControl.h>

#include <stdatomic.h>

#include <kern/thread_group.h>

#undef super
#define super OSObject
OSDefineMetaClassAndStructors(IOPerfControlClient, OSObject);

static IOPerfControlClient::IOPerfControlClientShared *_Atomic gIOPerfControlClientShared;

bool
IOPerfControlClient::init(IOService *driver, uint64_t maxWorkCapacity)
{
	// TODO: Remove this limit and implement dynamic table growth if workloads are found that exceed this
	if (maxWorkCapacity > kMaxWorkTableNumEntries) {
		maxWorkCapacity = kMaxWorkTableNumEntries;
	}

	if (!super::init()) {
		return false;
	}

	shared = atomic_load_explicit(&gIOPerfControlClientShared, memory_order_acquire);
	if (shared == nullptr) {
		IOPerfControlClient::IOPerfControlClientShared *expected = shared;
		shared = reinterpret_cast<IOPerfControlClient::IOPerfControlClientShared*>(kalloc(sizeof(IOPerfControlClientShared)));
		if (!shared) {
			return false;
		}

		atomic_init(&shared->maxDriverIndex, 0);

		shared->interface = PerfControllerInterface{
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

		shared->interfaceLock = IOLockAlloc();
		if (!shared->interfaceLock) {
			goto shared_init_error;
		}

		shared->deviceRegistrationList = OSSet::withCapacity(4);
		if (!shared->deviceRegistrationList) {
			goto shared_init_error;
		}

		if (!atomic_compare_exchange_strong_explicit(&gIOPerfControlClientShared, &expected, shared, memory_order_acq_rel,
		    memory_order_acquire)) {
			IOLockFree(shared->interfaceLock);
			shared->deviceRegistrationList->release();
			kfree(shared, sizeof(*shared));
			shared = expected;
		}
	}

	driverIndex = atomic_fetch_add_explicit(&shared->maxDriverIndex, 1, memory_order_relaxed) + 1;
	assertf(driverIndex != 0, "Overflow in driverIndex. Too many IOPerfControlClients created.\n");

	// + 1 since index 0 is unused for kIOPerfControlClientWorkUntracked
	workTableLength = maxWorkCapacity + 1;
	assertf(workTableLength <= kWorkTableMaxSize, "%zu exceeds max allowed capacity of %zu", workTableLength, kWorkTableMaxSize);
	if (maxWorkCapacity > 0) {
		workTable = reinterpret_cast<WorkTableEntry*>(kalloc(workTableLength * sizeof(WorkTableEntry)));
		if (!workTable) {
			goto error;
		}
		bzero(workTable, workTableLength * sizeof(WorkTableEntry));
		workTableNextIndex = 1;

		workTableLock = IOSimpleLockAlloc();
		if (!workTableLock) {
			goto error;
		}
	}

	return true;

error:
	if (workTable) {
		kfree(workTable, maxWorkCapacity * sizeof(WorkTableEntry));
	}
	if (workTableLock) {
		IOSimpleLockFree(workTableLock);
	}
	return false;
shared_init_error:
	if (shared) {
		if (shared->interfaceLock) {
			IOLockFree(shared->interfaceLock);
		}
		if (shared->deviceRegistrationList) {
			shared->deviceRegistrationList->release();
		}
		kfree(shared, sizeof(*shared));
		shared = nullptr;
	}
	return false;
}

IOPerfControlClient *
IOPerfControlClient::copyClient(IOService *driver, uint64_t maxWorkCapacity)
{
	IOPerfControlClient *client = new IOPerfControlClient;
	if (!client || !client->init(driver, maxWorkCapacity)) {
		panic("could not create IOPerfControlClient");
	}
	return client;
}

/* Convert the per driver token into a globally unique token for the performance
 * controller's consumption. This is achieved by setting the driver's unique
 * index onto the high order bits. The performance controller is shared between
 * all drivers and must track all instances separately, while each driver has
 * its own token table, so this step is needed to avoid token collisions between
 * drivers.
 */
inline uint64_t
IOPerfControlClient::tokenToGlobalUniqueToken(uint64_t token)
{
	return token | (static_cast<uint64_t>(driverIndex) << kWorkTableIndexBits);
}

/* With this implementation, tokens returned to the driver differ from tokens
 * passed to the performance controller. This implementation has the nice
 * property that tokens returns to the driver will aways be between 1 and
 * the value of maxWorkCapacity passed by the driver to copyClient. The tokens
 * the performance controller sees will match on the lower order bits and have
 * the driver index set on the high order bits.
 */
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

	if (token >= workTableLength) {
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

	if (token >= workTableLength) {
		panic("Invalid work token (%llu): index out of bounds.", token);
	}

	workTable[token].started = started;
}

IOReturn
IOPerfControlClient::registerDevice(__unused IOService *driver, IOService *device)
{
	IOReturn ret = kIOReturnSuccess;

	IOLockLock(shared->interfaceLock);

	if (shared->interface.version > 0) {
		ret = shared->interface.registerDevice(device);
	} else {
		shared->deviceRegistrationList->setObject(device);
	}

	IOLockUnlock(shared->interfaceLock);

	return ret;
}

void
IOPerfControlClient::unregisterDevice(__unused IOService *driver, IOService *device)
{
	IOLockLock(shared->interfaceLock);

	if (shared->interface.version > 0) {
		shared->interface.unregisterDevice(device);
	} else {
		shared->deviceRegistrationList->removeObject(device);
	}

	IOLockUnlock(shared->interfaceLock);
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

	IOLockLock(shared->interfaceLock);

	if (shared->interface.version == 0 && pci.version > 0) {
		assert(pci.registerDevice && pci.unregisterDevice && pci.workCanSubmit && pci.workSubmit && pci.workBegin && pci.workEnd);
		result = kIOReturnSuccess;

		OSObject *obj;
		while ((obj = shared->deviceRegistrationList->getAnyObject())) {
			IOService *device = OSDynamicCast(IOService, obj);
			if (device) {
				pci.registerDevice(device);
			}
			shared->deviceRegistrationList->removeObject(obj);
		}

		shared->interface = pci;
	}

	IOLockUnlock(shared->interfaceLock);

	return result;
}
