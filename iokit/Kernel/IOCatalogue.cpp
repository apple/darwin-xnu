/*
 * Copyright (c) 1998-2012 Apple Inc. All rights reserved.
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
 * Copyright (c) 1998 Apple Inc.  All rights reserved.
 *
 * HISTORY
 *
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#define IOKIT_ENABLE_SHARED_PTR

extern "C" {
#include <machine/machine_routines.h>
#include <libkern/kernel_mach_header.h>
#include <kern/host.h>
#include <security/mac_data.h>
};

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSUnserialize.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSSharedPtr.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/OSDebug.h>

#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOService.h>
#include <IOKit/IOCatalogue.h>

#include <IOKit/IOLib.h>
#include <IOKit/assert.h>
#include <IOKit/IOKitKeysPrivate.h>

#if PRAGMA_MARK
#pragma mark Internal Declarations
#endif
/*********************************************************************
*********************************************************************/

OSSharedPtr<IOCatalogue> gIOCatalogue;
OSSharedPtr<const OSSymbol> gIOClassKey;
OSSharedPtr<const OSSymbol> gIOProbeScoreKey;
OSSharedPtr<const OSSymbol> gIOModuleIdentifierKey;
OSSharedPtr<const OSSymbol> gIOModuleIdentifierKernelKey;
IORWLock       * gIOCatalogLock;

#if PRAGMA_MARK
#pragma mark Utility functions
#endif

#if PRAGMA_MARK
#pragma mark IOCatalogue class implementation
#endif
/*********************************************************************
*********************************************************************/

#define super OSObject
OSDefineMetaClassAndStructors(IOCatalogue, OSObject)

static bool isModuleLoadedNoOSKextLock(OSDictionary *theKexts,
    OSDictionary *theModuleDict);


/*********************************************************************
*********************************************************************/
void
IOCatalogue::initialize(void)
{
	OSSharedPtr<OSArray> array;
	OSSharedPtr<OSString> errorString;
	bool                   rc;

	extern const char * gIOKernelConfigTables;

	array = OSDynamicPtrCast<OSArray>(OSUnserialize(gIOKernelConfigTables, errorString));
	if (!array && errorString) {
		IOLog("KernelConfigTables syntax error: %s\n",
		    errorString->getCStringNoCopy());
	}

	gIOClassKey                  = OSSymbol::withCStringNoCopy( kIOClassKey );
	gIOProbeScoreKey             = OSSymbol::withCStringNoCopy( kIOProbeScoreKey );
	gIOModuleIdentifierKey       = OSSymbol::withCStringNoCopy( kCFBundleIdentifierKey );
	gIOModuleIdentifierKernelKey = OSSymbol::withCStringNoCopy( kCFBundleIdentifierKernelKey );


	assert( array && gIOClassKey && gIOProbeScoreKey
	    && gIOModuleIdentifierKey);

	gIOCatalogue = OSMakeShared<IOCatalogue>();
	assert(gIOCatalogue);
	rc = gIOCatalogue->init(array.get());
	assert(rc);
}

/*********************************************************************
* Initialize the IOCatalog object.
*********************************************************************/
OSArray *
IOCatalogue::arrayForPersonality(OSDictionary * dict)
{
	const OSSymbol * sym;

	sym = OSDynamicCast(OSSymbol, dict->getObject(gIOProviderClassKey));
	if (!sym) {
		return NULL;
	}

	return (OSArray *) personalities->getObject(sym);
}

void
IOCatalogue::addPersonality(OSDictionary * dict)
{
	const OSSymbol * sym;
	OSArray * arr;

	sym = OSDynamicCast(OSSymbol, dict->getObject(gIOProviderClassKey));
	if (!sym) {
		return;
	}
	arr = (OSArray *) personalities->getObject(sym);
	if (arr) {
		arr->setObject(dict);
	} else {
		OSSharedPtr<OSArray> sharedArr = OSArray::withObjects((const OSObject **)&dict, 1, 2);
		personalities->setObject(sym, sharedArr.get());
	}
}

/*********************************************************************
* Initialize the IOCatalog object.
*********************************************************************/
bool
IOCatalogue::init(OSArray * initArray)
{
	OSDictionary         * dict;
	OSObject * obj;

	if (!super::init()) {
		return false;
	}

	generation = 1;

	personalities = OSDictionary::withCapacity(32);
	personalities->setOptions(OSCollection::kSort, OSCollection::kSort);
	for (unsigned int idx = 0; (obj = initArray->getObject(idx)); idx++) {
		dict = OSDynamicCast(OSDictionary, obj);
		if (!dict) {
			continue;
		}
		OSKext::uniquePersonalityProperties(dict);
		if (NULL == dict->getObject( gIOClassKey.get())) {
			IOLog("Missing or bad \"%s\" key\n",
			    gIOClassKey->getCStringNoCopy());
			continue;
		}
		dict->setObject("KernelConfigTable", kOSBooleanTrue);
		addPersonality(dict);
	}

	gIOCatalogLock = IORWLockAlloc();
	lock = gIOCatalogLock;

	return true;
}

/*********************************************************************
* Release all resources used by IOCatalogue and deallocate.
* This will probably never be called.
*********************************************************************/
void
IOCatalogue::free( void )
{
	panic("");
}

/*********************************************************************
*********************************************************************/
OSPtr<OSOrderedSet>
IOCatalogue::findDrivers(
	IOService * service,
	SInt32 * generationCount)
{
	OSDictionary         * nextTable;
	OSSharedPtr<OSOrderedSet> set;
	OSArray              * array;
	const OSMetaClass    * meta;
	unsigned int           idx;

	set = OSOrderedSet::withCapacity( 1, IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!set) {
		return NULL;
	}

	IORWLockRead(lock);

	meta = service->getMetaClass();
	while (meta) {
		array = (OSArray *) personalities->getObject(meta->getClassNameSymbol());
		if (array) {
			for (idx = 0; (nextTable = (OSDictionary *) array->getObject(idx)); idx++) {
				set->setObject(nextTable);
			}
		}
		if (meta == &IOService::gMetaClass) {
			break;
		}
		meta = meta->getSuperClass();
	}

	*generationCount = getGenerationCount();

	IORWLockUnlock(lock);

	return set;
}

/*********************************************************************
* Is personality already in the catalog?
*********************************************************************/
OSPtr<OSOrderedSet>
IOCatalogue::findDrivers(
	OSDictionary * matching,
	SInt32 * generationCount)
{
	OSSharedPtr<OSCollectionIterator> iter;
	OSDictionary         * dict;
	OSSharedPtr<OSOrderedSet> set;
	OSArray              * array;
	const OSSymbol       * key;
	unsigned int           idx;

	OSKext::uniquePersonalityProperties(matching);

	set = OSOrderedSet::withCapacity( 1, IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!set) {
		return NULL;
	}
	iter = OSCollectionIterator::withCollection(personalities.get());
	if (!iter) {
		return nullptr;
	}

	IORWLockRead(lock);
	while ((key = (const OSSymbol *) iter->getNextObject())) {
		array = (OSArray *) personalities->getObject(key);
		if (array) {
			for (idx = 0; (dict = (OSDictionary *) array->getObject(idx)); idx++) {
				/* This comparison must be done with only the keys in the
				 * "matching" dict to enable general searches.
				 */
				if (dict->isEqualTo(matching, matching)) {
					set->setObject(dict);
				}
			}
		}
	}
	*generationCount = getGenerationCount();
	IORWLockUnlock(lock);

	return set;
}

/*********************************************************************
* Add driver config tables to catalog and start matching process.
*
* Important that existing personalities are kept (not replaced)
* if duplicates found. Personalities can come from OSKext objects
* or from userland kext library. We want to minimize distinct
* copies between OSKext & IOCatalogue.
*
* xxx - userlib used to refuse to send personalities with IOKitDebug
* xxx - during safe boot. That would be better implemented here.
*********************************************************************/

bool
IOCatalogue::addDrivers(
	OSArray * drivers,
	bool doNubMatching)
{
	bool                   result = false;
	OSSharedPtr<OSOrderedSet> set;
	OSSharedPtr<OSCollectionIterator> iter;
	OSObject             * object = NULL;   // do not release
	OSArray              * persons = NULL;// do not release

	persons = OSDynamicCast(OSArray, drivers);
	if (!persons) {
		goto finish;
	}

	set = OSOrderedSet::withCapacity( 10, IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!set) {
		goto finish;
	}

	iter = OSCollectionIterator::withCollection(persons);
	if (!iter) {
		goto finish;
	}

	/* Start with success; clear it on an error.
	 */
	result = true;

	IORWLockWrite(lock);
	while ((object = iter->getNextObject())) {
		// xxx Deleted OSBundleModuleDemand check; will handle in other ways for SL

		OSDictionary * personality = OSDynamicCast(OSDictionary, object);

		SInt count;

		if (!personality) {
			IOLog("IOCatalogue::addDrivers() encountered non-dictionary; bailing.\n");
			result = false;
			break;
		}

		OSKext::uniquePersonalityProperties(personality);

		// Add driver personality to catalogue.

		OSArray * array = arrayForPersonality(personality);
		if (!array) {
			addPersonality(personality);
		} else {
			count = array->getCount();
			while (count--) {
				OSDictionary * driver;

				// Be sure not to double up on personalities.
				driver = (OSDictionary *)array->getObject(count);

				/* Unlike in other functions, this comparison must be exact!
				 * The catalogue must be able to contain personalities that
				 * are proper supersets of others.
				 * Do not compare just the properties present in one driver
				 * personality or the other.
				 */
				if (personality->isEqualTo(driver)) {
					break;
				}
			}
			if (count >= 0) {
				// its a dup
				continue;
			}
			result = array->setObject(personality);
			if (!result) {
				break;
			}
		}

		set->setObject(personality);
	}
	// Start device matching.
	if (result && doNubMatching && (set->getCount() > 0)) {
		IOService::catalogNewDrivers(set.get());
		generation++;
	}
	IORWLockUnlock(lock);

finish:

	return result;
}

bool
IOCatalogue::removeDrivers(bool doNubMatching, bool (^shouldRemove)(OSDictionary *personality))
{
	OSSharedPtr<OSOrderedSet> set;
	OSSharedPtr<OSCollectionIterator> iter;
	OSDictionary         * dict;
	OSArray              * array;
	const OSSymbol       * key;
	unsigned int           idx;

	set = OSOrderedSet::withCapacity(10,
	    IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!set) {
		return false;
	}
	iter = OSCollectionIterator::withCollection(personalities.get());
	if (!iter) {
		return false;
	}

	IORWLockWrite(lock);
	while ((key = (const OSSymbol *) iter->getNextObject())) {
		array = (OSArray *) personalities->getObject(key);
		if (array) {
			for (idx = 0; (dict = (OSDictionary *) array->getObject(idx)); idx++) {
				if (shouldRemove(dict)) {
					set->setObject(dict);
					array->removeObject(idx);
					idx--;
				}
			}
		}
		// Start device matching.
		if (doNubMatching && (set->getCount() > 0)) {
			IOService::catalogNewDrivers(set.get());
			generation++;
		}
	}
	IORWLockUnlock(lock);

	return true;
}

/*********************************************************************
* Remove drivers from the catalog which match the
* properties in the matching dictionary.
*********************************************************************/
bool
IOCatalogue::removeDrivers(
	OSDictionary * matching,
	bool doNubMatching)
{
	if (!matching) {
		return false;
	}
	return removeDrivers(doNubMatching, ^(OSDictionary *dict) {
		/* This comparison must be done with only the keys in the
		 * "matching" dict to enable general searches.
		 */
		return dict->isEqualTo(matching, matching);
	});
}

// Return the generation count.
SInt32
IOCatalogue::getGenerationCount(void) const
{
	return generation;
}

// Check to see if kernel module has been loaded already, and request its load.
bool
IOCatalogue::isModuleLoaded(OSDictionary * driver, OSObject ** kextRef) const
{
	OSString * moduleName = NULL;
	OSString * publisherName = NULL;
	OSReturn   ret;

	if (kextRef) {
		*kextRef = NULL;
	}
	if (!driver) {
		return false;
	}

	/* The personalities of codeless kexts often contain the bundle ID of the
	 * kext they reference, and not the bundle ID of the codeless kext itself.
	 * The prelinked kernel needs to know the bundle ID of the codeless kext
	 * so it can include these personalities, so OSKext stores that bundle ID
	 * in the IOPersonalityPublisher key, and we record it as requested here.
	 */
	publisherName = OSDynamicCast(OSString,
	    driver->getObject(kIOPersonalityPublisherKey));
	OSKext::recordIdentifierRequest(publisherName);

	moduleName = OSDynamicCast(OSString, driver->getObject(gIOModuleIdentifierKernelKey.get()));
	if (moduleName) {
		ret = OSKext::loadKextWithIdentifier(moduleName, kextRef);
		if (kOSKextReturnDeferred == ret) {
			// a request has been queued but the module isn't necessarily
			// loaded yet, so stall.
			return false;
		}
		OSString *moduleDextName = OSDynamicCast(OSString, driver->getObject(gIOModuleIdentifierKey.get()));
		if (moduleDextName && !(moduleName->isEqualTo(moduleDextName))) {
			OSSharedPtr<OSObject> dextRef;
			ret = OSKext::loadKextWithIdentifier(moduleDextName, dextRef);
		}
		// module is present or never will be
		return true;
	}

	/* If a personality doesn't hold the "CFBundleIdentifier" or "CFBundleIdentifierKernel" key
	 * it is assumed to be an "in-kernel" driver.
	 */
	return true;
}

bool
IOCatalogue::isModuleLoaded(OSDictionary * driver, OSSharedPtr<OSObject>& kextRef) const
{
	OSObject* kextRefRaw = NULL;
	bool result = isModuleLoaded(driver, &kextRefRaw);
	kextRef.reset(kextRefRaw, OSNoRetain);
	return result;
}

/* This function is called after a module has been loaded.
 * Is invoked from user client call, ultimately from IOKitLib's
 * IOCatalogueModuleLoaded(). Sent from kextd.
 */
void
IOCatalogue::moduleHasLoaded(const OSSymbol * moduleName)
{
	startMatching(moduleName);

	(void) OSKext::setDeferredLoadSucceeded();
	(void) OSKext::considerRebuildOfPrelinkedKernel();
}

void
IOCatalogue::moduleHasLoaded(const char * moduleName)
{
	OSSharedPtr<const OSSymbol> name;

	name = OSSymbol::withCString(moduleName);
	moduleHasLoaded(name.get());
}

// xxx - return is really OSReturn/kern_return_t
IOReturn
IOCatalogue::unloadModule(OSString * moduleName) const
{
	return OSKext::removeKextWithIdentifier(moduleName->getCStringNoCopy());
}

IOReturn
IOCatalogue::terminateDrivers(OSDictionary * matching, io_name_t className)
{
	OSDictionary         * dict;
	OSSharedPtr<OSIterator> iter;
	IOService            * service;
	IOReturn               ret;

	ret = kIOReturnSuccess;
	dict = NULL;
	iter = IORegistryIterator::iterateOver(gIOServicePlane,
	    kIORegistryIterateRecursively);
	if (!iter) {
		return kIOReturnNoMemory;
	}

	if (matching) {
		OSKext::uniquePersonalityProperties( matching, false );
	}

	// terminate instances.
	do {
		iter->reset();
		while ((service = (IOService *)iter->getNextObject())) {
			if (className && !service->metaCast(className)) {
				continue;
			}
			if (matching) {
				/* Terminate only for personalities that match the matching dictionary.
				 * This comparison must be done with only the keys in the
				 * "matching" dict to enable general matching.
				 */
				dict = service->getPropertyTable();
				if (!dict) {
					continue;
				}
				if (!dict->isEqualTo(matching, matching)) {
					continue;
				}
			}

			OSKext     * kext;
			OSSharedPtr<OSString> dextBundleID;
			const char * bundleIDStr;
			OSObject   * prop;
			bool         okToTerminate;
			bool         isDext = service->hasUserServer();
			for (okToTerminate = true;;) {
				if (isDext) {
					dextBundleID = OSDynamicPtrCast<OSString>(service->copyProperty(gIOModuleIdentifierKey.get()));
					if (!dextBundleID) {
						break;
					}
					bundleIDStr = dextBundleID->getCStringNoCopy();
				} else {
					kext = service->getMetaClass()->getKext();
					if (!kext) {
						break;
					}
					bundleIDStr = kext->getIdentifierCString();
					prop = kext->getPropertyForHostArch(kOSBundleAllowUserTerminateKey);
					if (prop) {
						okToTerminate = (kOSBooleanTrue == prop);
						break;
					}
				}
				if (!bundleIDStr) {
					break;
				}
				if (!strcmp(kOSKextKernelIdentifier, bundleIDStr)) {
					okToTerminate = false;
					break;
				}
				if (!strncmp("com.apple.", bundleIDStr, strlen("com.apple."))) {
					okToTerminate = false;
					break;
				}
				break;
			}
			if (!okToTerminate) {
#if DEVELOPMENT || DEBUG
				okToTerminate = true;
#endif /* DEVELOPMENT || DEBUG */
				IOLog("%sallowing kextunload terminate for bundleID %s\n",
				    okToTerminate ? "" : "dis", bundleIDStr ? bundleIDStr : "?");
				if (!okToTerminate) {
					ret = kIOReturnUnsupported;
					break;
				}
			}
			IOOptionBits terminateOptions = kIOServiceRequired | kIOServiceSynchronous;
			if (isDext) {
				terminateOptions |= kIOServiceTerminateNeedWillTerminate;
			}
			if (!service->terminate(terminateOptions)) {
				ret = kIOReturnUnsupported;
				break;
			}
		}
	} while (!service && !iter->isValid());

	return ret;
}

IOReturn
IOCatalogue::_removeDrivers(OSDictionary * matching)
{
	IOReturn               ret = kIOReturnSuccess;
	OSSharedPtr<OSCollectionIterator> iter;
	OSDictionary         * dict;
	OSArray              * array;
	const OSSymbol       * key;
	unsigned int           idx;

	// remove configs from catalog.

	iter = OSCollectionIterator::withCollection(personalities.get());
	if (!iter) {
		return kIOReturnNoMemory;
	}

	while ((key = (const OSSymbol *) iter->getNextObject())) {
		array = (OSArray *) personalities->getObject(key);
		if (array) {
			for (idx = 0; (dict = (OSDictionary *) array->getObject(idx)); idx++) {
				/* Remove from the catalogue's array any personalities
				 * that match the matching dictionary.
				 * This comparison must be done with only the keys in the
				 * "matching" dict to enable general matching.
				 */
				if (dict->isEqualTo(matching, matching)) {
					array->removeObject(idx);
					idx--;
				}
			}
		}
	}

	return ret;
}

IOReturn
IOCatalogue::terminateDrivers(OSDictionary * matching)
{
	IOReturn ret;

	if (!matching) {
		return kIOReturnBadArgument;
	}
	ret = terminateDrivers(matching, NULL);
	IORWLockWrite(lock);
	if (kIOReturnSuccess == ret) {
		ret = _removeDrivers(matching);
	}
	IORWLockUnlock(lock);

	return ret;
}

IOReturn
IOCatalogue::terminateDriversForUserspaceReboot()
{
	IOReturn                ret = kIOReturnSuccess;

#if !NO_KEXTD
	OSSharedPtr<OSIterator> iter;
	IOService             * service;
	bool                    isDeferredMatch;
	bool                    isDext;
	IOOptionBits            terminateOptions;

	iter = IORegistryIterator::iterateOver(gIOServicePlane,
	    kIORegistryIterateRecursively);
	if (!iter) {
		return kIOReturnNoMemory;
	}

	do {
		iter->reset();
		while ((service = (IOService *)iter->getNextObject())) {
			isDeferredMatch = service->propertyHasValue(gIOMatchDeferKey, kOSBooleanTrue);
			isDext = service->hasUserServer();
			if (isDeferredMatch || isDext) {
				if (isDext) {
					OSSharedPtr<OSString> name = OSDynamicPtrCast<OSString>(service->copyProperty(gIOUserServerNameKey));
					const char *userServerName = NULL;
					if (name) {
						userServerName = name->getCStringNoCopy();
					}
					IOLog("terminating service %s-0x%llx [dext %s]\n", service->getName(), service->getRegistryEntryID(), userServerName ? userServerName : "(null)");
				} else {
					OSKext *kext = service->getMetaClass()->getKext();
					const char *bundleID = NULL;
					if (kext) {
						bundleID = kext->getIdentifierCString();
					}
					IOLog("terminating service %s-0x%llx [kext %s]\n", service->getName(), service->getRegistryEntryID(), bundleID ? bundleID : "(null)");
				}
				terminateOptions = kIOServiceRequired | kIOServiceSynchronous;
				if (isDext) {
					terminateOptions |= kIOServiceTerminateNeedWillTerminate;
				}
				if (!service->terminate(terminateOptions)) {
					IOLog("failed to terminate service %s-0x%llx\n", service->getName(), service->getRegistryEntryID());
					ret = kIOReturnUnsupported;
					break;
				}
			}
		}
	} while (!service && !iter->isValid());
#endif

	return ret;
}

IOReturn
IOCatalogue::resetAfterUserspaceReboot(void)
{
	OSSharedPtr<OSIterator> iter;
	IOService             * service;

	iter = IORegistryIterator::iterateOver(gIOServicePlane,
	    kIORegistryIterateRecursively);
	if (!iter) {
		return kIOReturnNoMemory;
	}

	do {
		iter->reset();
		while ((service = (IOService *)iter->getNextObject())) {
			service->resetRematchProperties();
		}
	} while (!service && !iter->isValid());

	/* Remove all dext personalities */
	removeDrivers(false, ^(OSDictionary *dict) {
		return dict->getObject(gIOUserServerNameKey) != NULL;
	});

	return kIOReturnSuccess;
}

IOReturn
IOCatalogue::terminateDriversForModule(
	OSString * moduleName,
	bool unload)
{
	IOReturn ret;
	OSSharedPtr<OSDictionary> dict;
	bool isLoaded = false;

	/* Check first if the kext currently has any linkage dependents;
	 * in such a case the unload would fail so let's not terminate any
	 * IOServices (since doing so typically results in a panic when there
	 * are loaded dependencies). Note that we aren't locking the kext here
	 * so it might lose or gain dependents by the time we call unloadModule();
	 * I think that's ok, our unload can fail if a kext comes in on top of
	 * this one even after we've torn down IOService objects. Conversely,
	 * if we fail the unload here and then lose a library, the autounload
	 * thread will get us in short order.
	 */
	if (OSKext::isKextWithIdentifierLoaded(moduleName->getCStringNoCopy())) {
		isLoaded = true;

		if (!OSKext::canUnloadKextWithIdentifier(moduleName,
		    /* checkClasses */ false)) {
			ret = kOSKextReturnInUse;
			goto finish;
		}
	}
	dict = OSDictionary::withCapacity(1);
	if (!dict) {
		ret = kIOReturnNoMemory;
		goto finish;
	}

	dict->setObject(gIOModuleIdentifierKey.get(), moduleName);

	ret = terminateDrivers(dict.get(), NULL);

	/* No goto between IOLock calls!
	 */
	IORWLockWrite(lock);
	if (kIOReturnSuccess == ret) {
		ret = _removeDrivers(dict.get());
	}

	// Unload the module itself.
	if (unload && isLoaded && ret == kIOReturnSuccess) {
		ret = unloadModule(moduleName);
	}

	IORWLockUnlock(lock);

finish:
	return ret;
}

IOReturn
IOCatalogue::terminateDriversForModule(
	const char * moduleName,
	bool unload)
{
	OSSharedPtr<OSString> name;
	IOReturn ret;

	name = OSString::withCString(moduleName);
	if (!name) {
		return kIOReturnNoMemory;
	}

	ret = terminateDriversForModule(name.get(), unload);

	return ret;
}

#if defined(__i386__) || defined(__x86_64__)
bool
IOCatalogue::startMatching( OSDictionary * matching )
{
	OSSharedPtr<OSOrderedSet> set;

	if (!matching) {
		return false;
	}

	set = OSOrderedSet::withCapacity(10, IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!set) {
		return false;
	}

	IORWLockRead(lock);

	personalities->iterateObjects(^bool (const OSSymbol * key, OSObject * value) {
		OSArray      * array;
		OSDictionary * dict;
		unsigned int   idx;

		array = (OSArray *) value;
		for (idx = 0; (dict = (OSDictionary *) array->getObject(idx)); idx++) {
		        /* This comparison must be done with only the keys in the
		         * "matching" dict to enable general matching.
		         */
		        if (dict->isEqualTo(matching, matching)) {
		                set->setObject(dict);
			}
		}
		return false;
	});

	// Start device matching.
	if (set->getCount() > 0) {
		IOService::catalogNewDrivers(set.get());
		generation++;
	}

	IORWLockUnlock(lock);

	return true;
}
#endif /* defined(__i386__) || defined(__x86_64__) */

bool
IOCatalogue::startMatching( const OSSymbol * moduleName )
{
	OSSharedPtr<OSOrderedSet> set;

	if (!moduleName) {
		return false;
	}

	set = OSOrderedSet::withCapacity(10, IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!set) {
		return false;
	}

	IORWLockRead(lock);

	personalities->iterateObjects(^bool (const OSSymbol * key, OSObject * value) {
		OSArray      * array;
		OSDictionary * dict;
		OSObject     * moduleIdentifierKernel;
		OSObject     * moduleIdentifier;
		unsigned int   idx;

		array = (OSArray *) value;
		for (idx = 0; (dict = (OSDictionary *) array->getObject(idx)); idx++) {
		        moduleIdentifierKernel = dict->getObject(gIOModuleIdentifierKernelKey.get());
		        moduleIdentifier = dict->getObject(gIOModuleIdentifierKey.get());
		        if ((moduleIdentifierKernel && moduleName->isEqualTo(moduleIdentifierKernel)) ||
		        (moduleIdentifier && moduleName->isEqualTo(moduleIdentifier))) {
		                set->setObject(dict);
			}
		}
		return false;
	});

	// Start device matching.
	if (set->getCount() > 0) {
		IOService::catalogNewDrivers(set.get());
		generation++;
	}

	IORWLockUnlock(lock);

	return true;
}

void
IOCatalogue::reset(void)
{
	IOCatalogue::resetAndAddDrivers(/* no drivers; true reset */ NULL,
	    /* doMatching */ false);
	return;
}

bool
IOCatalogue::resetAndAddDrivers(OSArray * drivers, bool doNubMatching)
{
	bool                   result              = false;
	OSArray              * newPersonalities    = NULL;// do not release
	const OSSymbol       * key;
	OSArray              * array;
	OSDictionary         * thisNewPersonality   = NULL;// do not release
	OSDictionary         * thisOldPersonality   = NULL;// do not release
	OSSharedPtr<OSDictionary> myKexts;
	OSSharedPtr<OSCollectionIterator> iter;
	OSSharedPtr<OSOrderedSet> matchSet;
	signed int             idx, newIdx;

	if (drivers) {
		newPersonalities = OSDynamicCast(OSArray, drivers);
		if (!newPersonalities) {
			goto finish;
		}
	}
	matchSet = OSOrderedSet::withCapacity(10, IOServiceOrdering,
	    (void *)(gIOProbeScoreKey.get()));
	if (!matchSet) {
		goto finish;
	}
	iter = OSCollectionIterator::withCollection(personalities.get());
	if (!iter) {
		goto finish;
	}

	/* need copy of loaded kexts so we can check if for loaded modules without
	 * taking the OSKext lock.  There is a potential of deadlocking if we get
	 * an OSKext via the normal path.  See 14672140.
	 */
	myKexts = OSKext::copyKexts();

	result = true;

	IOLog("Resetting IOCatalogue.\n");

	/* No goto finish from here to unlock.
	 */
	IORWLockWrite(lock);

	while ((key = (const OSSymbol *) iter->getNextObject())) {
		array = (OSArray *) personalities->getObject(key);
		if (!array) {
			continue;
		}

		for (idx = 0;
		    (thisOldPersonality = (OSDictionary *) array->getObject(idx));
		    idx++) {
			if (thisOldPersonality->getObject("KernelConfigTable")) {
				continue;
			}
			thisNewPersonality = NULL;

			if (newPersonalities) {
				for (newIdx = 0;
				    (thisNewPersonality = (OSDictionary *) newPersonalities->getObject(newIdx));
				    newIdx++) {
					/* Unlike in other functions, this comparison must be exact!
					 * The catalogue must be able to contain personalities that
					 * are proper supersets of others.
					 * Do not compare just the properties present in one driver
					 * personality or the other.
					 */
					if (OSDynamicCast(OSDictionary, thisNewPersonality) == NULL) {
						/* skip thisNewPersonality if it is not an OSDictionary */
						continue;
					}
					if (thisNewPersonality->isEqualTo(thisOldPersonality)) {
						break;
					}
				}
			}
			if (thisNewPersonality) {
				// dup, ignore
				newPersonalities->removeObject(newIdx);
			} else {
				// not in new set - remove
				// only remove dictionary if this module in not loaded - 9953845
				if (isModuleLoadedNoOSKextLock(myKexts.get(), thisOldPersonality) == false) {
					if (matchSet) {
						matchSet->setObject(thisOldPersonality);
					}
					array->removeObject(idx);
					idx--;
				}
			}
		} // for...
	} // while...

	// add new
	if (newPersonalities) {
		for (newIdx = 0;
		    (thisNewPersonality = (OSDictionary *) newPersonalities->getObject(newIdx));
		    newIdx++) {
			if (OSDynamicCast(OSDictionary, thisNewPersonality) == NULL) {
				/* skip thisNewPersonality if it is not an OSDictionary */
				continue;
			}

			OSKext::uniquePersonalityProperties(thisNewPersonality);
			addPersonality(thisNewPersonality);
			matchSet->setObject(thisNewPersonality);
		}
	}

	/* Finally, start device matching on all new & removed personalities.
	 */
	if (result && doNubMatching && (matchSet->getCount() > 0)) {
		IOService::catalogNewDrivers(matchSet.get());
		generation++;
	}

	IORWLockUnlock(lock);

finish:

	return result;
}

bool
IOCatalogue::serialize(OSSerialize * s) const
{
	if (!s) {
		return false;
	}

	return super::serialize(s);
}

bool
IOCatalogue::serializeData(IOOptionBits kind, OSSerialize * s) const
{
	kern_return_t kr = kIOReturnSuccess;

	switch (kind) {
	case kIOCatalogGetContents:
		kr = KERN_NOT_SUPPORTED;
		break;

	case kIOCatalogGetModuleDemandList:
		kr = KERN_NOT_SUPPORTED;
		break;

	case kIOCatalogGetCacheMissList:
		kr = KERN_NOT_SUPPORTED;
		break;

	case kIOCatalogGetROMMkextList:
		kr = KERN_NOT_SUPPORTED;
		break;

	default:
		kr = kIOReturnBadArgument;
		break;
	}

	return kr;
}

/* isModuleLoadedNoOSKextLock - used to check to see if a kext is loaded
 * without taking the OSKext lock.  We use this to avoid the problem
 * where taking the IOCatalog lock then the OSKext lock will dealock when
 * a kext load or unload is happening at the same time as IOCatalog changing.
 *
 * theKexts - is a dictionary of current kexts (from OSKext::copyKexts) with
 *      key set to the kext bundle ID and value set to an OSKext object
 * theModuleDict - is an IOKit personality dictionary for a given module (kext)
 */
static bool
isModuleLoadedNoOSKextLock(OSDictionary *theKexts,
    OSDictionary *theModuleDict)
{
	bool                    myResult = false;
	const OSString *        myBundleID = NULL;// do not release
	OSKext *                myKext = NULL;  // do not release

	if (theKexts == NULL || theModuleDict == NULL) {
		return myResult;
	}

	// gIOModuleIdentifierKey is "CFBundleIdentifier"
	myBundleID = OSDynamicCast(OSString,
	    theModuleDict->getObject(gIOModuleIdentifierKey.get()));
	if (myBundleID == NULL) {
		return myResult;
	}

	myKext = OSDynamicCast(OSKext, theKexts->getObject(myBundleID->getCStringNoCopy()));
	if (myKext) {
		myResult = myKext->isLoaded();
	}

	return myResult;
}


#if PRAGMA_MARK
#pragma mark Obsolete Kext Loading Stuff
#endif
/*********************************************************************
 **********************************************************************
 ***                  BINARY COMPATIBILITY SECTION                  ***
 **********************************************************************
 **********************************************************************
 * These functions are no longer used are necessary for C++ binary
 * compatibility on i386.
 **********************************************************************/
