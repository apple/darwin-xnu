/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
#include <mach/kmod.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/prelink.h>
}

#include <libkern/version.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/c++/OSKext.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOCatalogue.h>

#if __x86_64__
#define KASLR_KEXT_DEBUG 0
#endif

#if PRAGMA_MARK
#pragma mark Bootstrap Declarations
#endif
/*********************************************************************
* Bootstrap Declarations
*
* The ENTIRE point of the libsa/KLD segment is to isolate bootstrap
* code from other parts of the kernel, so function symbols are not
* exported; rather pointers to those functions are exported.
*
* xxx - need to think about locking for handling the 'weak' refs.
* xxx - do export a non-KLD function that says you've called a
* xxx - bootstrap function that has been removed.
*
* ALL call-ins to this segment of the kernel must be done through
* exported pointers. The symbols themselves are private and not to
* be linked against.
*********************************************************************/
extern "C" {
extern void (*record_startup_extensions_function)(void);
extern void (*load_security_extensions_function)(void);
};

static void bootstrapRecordStartupExtensions(void);
static void bootstrapLoadSecurityExtensions(void);


#if NO_KEXTD
extern "C" bool IORamDiskBSDRoot(void);
#endif

#if PRAGMA_MARK
#pragma mark Macros
#endif
/*********************************************************************
* Macros
*********************************************************************/
#define CONST_STRLEN(str) (sizeof(str) - 1)

#if PRAGMA_MARK
#pragma mark Kernel Component Kext Identifiers
#endif
/*********************************************************************
* Kernel Component Kext Identifiers
*
* We could have each kernel resource kext automatically "load" as
* it's created, but it's nicer to have them listed in kextstat in
* the order of this list. We'll walk through this after setting up
* all the boot kexts and have them load up.
*********************************************************************/
static const char * sKernelComponentNames[] = {
	// The kexts for these IDs must have a version matching 'osrelease'.
	"com.apple.kernel",
	"com.apple.kpi.bsd",
	"com.apple.kpi.dsep",
	"com.apple.kpi.iokit",
	"com.apple.kpi.kasan",
	"com.apple.kpi.libkern",
	"com.apple.kpi.mach",
	"com.apple.kpi.private",
	"com.apple.kpi.unsupported",
	"com.apple.iokit.IONVRAMFamily",
	"com.apple.driver.AppleNMI",
	"com.apple.iokit.IOSystemManagementFamily",
	"com.apple.iokit.ApplePlatformFamily",
	NULL
};

static int __whereIsAddr(vm_offset_t theAddr, unsigned long * segSizes, vm_offset_t *segAddrs, int segCount );

#define PLK_SEGMENTS 12

static const char * plk_segNames[] = {
	"__TEXT",
	"__TEXT_EXEC",
	"__DATA",
	"__DATA_CONST",
	"__LINKEDIT",
	"__PRELINK_TEXT",
	"__PLK_TEXT_EXEC",
	"__PRELINK_DATA",
	"__PLK_DATA_CONST",
	"__PLK_LLVM_COV",
	"__PLK_LINKEDIT",
	"__PRELINK_INFO",
	NULL
};

#if PRAGMA_MARK
#pragma mark KLDBootstrap Class
#endif
/*********************************************************************
* KLDBootstrap Class
*
* We use a C++ class here so that it can be a friend of OSKext and
* get at private stuff. We can't hide the class itself, but we can
* hide the instance through which we invoke the functions.
*********************************************************************/
class KLDBootstrap {
	friend void bootstrapRecordStartupExtensions(void);
	friend void bootstrapLoadSecurityExtensions(void);

private:
	void readStartupExtensions(void);

	void readPrelinkedExtensions(
		kernel_section_t * prelinkInfoSect);
	void readBooterExtensions(void);

	OSReturn loadKernelComponentKexts(void);
	void     loadKernelExternalComponents(void);
	void     readBuiltinPersonalities(void);

	void     loadSecurityExtensions(void);

public:
	KLDBootstrap(void);
	~KLDBootstrap(void);
};

LIBKERN_ALWAYS_DESTROY static KLDBootstrap sBootstrapObject;

/*********************************************************************
* Set the function pointers for the entry points into the bootstrap
* segment upon C++ static constructor invocation.
*********************************************************************/
KLDBootstrap::KLDBootstrap(void)
{
	if (this != &sBootstrapObject) {
		panic("Attempt to access bootstrap segment.");
	}
	record_startup_extensions_function = &bootstrapRecordStartupExtensions;
	load_security_extensions_function = &bootstrapLoadSecurityExtensions;
}

/*********************************************************************
* Clear the function pointers for the entry points into the bootstrap
* segment upon C++ static destructor invocation.
*********************************************************************/
KLDBootstrap::~KLDBootstrap(void)
{
	if (this != &sBootstrapObject) {
		panic("Attempt to access bootstrap segment.");
	}


	record_startup_extensions_function = NULL;
	load_security_extensions_function = NULL;
}

/*********************************************************************
*********************************************************************/
void
KLDBootstrap::readStartupExtensions(void)
{
	kernel_section_t * prelinkInfoSect = NULL; // do not free

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogGeneralFlag | kOSKextLogDirectoryScanFlag |
	    kOSKextLogKextBookkeepingFlag,
	    "Reading startup extensions.");

	/* If the prelink info segment has a nonzero size, we are prelinked
	 * and won't have any individual kexts or mkexts to read.
	 * Otherwise, we need to read kexts or the mkext from what the booter
	 * has handed us.
	 */
	prelinkInfoSect = getsectbyname(kPrelinkInfoSegment, kPrelinkInfoSection);
	if (prelinkInfoSect->size) {
		readPrelinkedExtensions(prelinkInfoSect);
	} else {
		readBooterExtensions();
	}

	loadKernelComponentKexts();
	loadKernelExternalComponents();
	readBuiltinPersonalities();
	OSKext::sendAllKextPersonalitiesToCatalog();

	return;
}

typedef struct kaslrPackedOffsets {
	uint32_t    count;          /* number of offsets */
	uint32_t    offsetsArray[]; /* offsets to slide */
} kaslrPackedOffsets;

/*********************************************************************
*********************************************************************/
void
KLDBootstrap::readPrelinkedExtensions(
	kernel_section_t * prelinkInfoSect)
{
	OSArray                   * infoDictArray           = NULL;// do not release
	OSObject                  * parsedXML       = NULL;// must release
	OSDictionary              * prelinkInfoDict         = NULL;// do not release
	OSString                  * errorString             = NULL;// must release
	OSKext                    * theKernel               = NULL;// must release
	OSData                    * kernelcacheUUID         = NULL;// do not release

	kernel_segment_command_t  * prelinkTextSegment      = NULL;// see code
	kernel_segment_command_t  * prelinkInfoSegment      = NULL;// see code

	/* We make some copies of data, but if anything fails we're basically
	 * going to fail the boot, so these won't be cleaned up on error.
	 */
	void                      * prelinkData             = NULL;// see code
	vm_size_t                   prelinkLength           = 0;


	OSDictionary              * infoDict                = NULL;// do not release

	IORegistryEntry           * registryRoot            = NULL;// do not release
	OSNumber                  * prelinkCountObj         = NULL;// must release

	u_int                       i = 0;
#if NO_KEXTD
	bool                        ramDiskBoot;
	bool                        developerDevice;
	bool                        dontLoad;
#endif
	OSData                     * kaslrOffsets = NULL;
	unsigned long               plk_segSizes[PLK_SEGMENTS];
	vm_offset_t                 plk_segAddrs[PLK_SEGMENTS];

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
	    "Starting from prelinked kernel.");

	prelinkTextSegment = getsegbyname(kPrelinkTextSegment);
	if (!prelinkTextSegment) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
		    "Can't find prelinked kexts' text segment.");
		goto finish;
	}

#if KASLR_KEXT_DEBUG
	unsigned long   scratchSize;
	vm_offset_t     scratchAddr;

	IOLog("kaslr: prelinked kernel address info: \n");

	scratchAddr = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__TEXT", &scratchSize);
	IOLog("kaslr: start 0x%lx end 0x%lx length %lu for __TEXT \n",
	    (unsigned long)scratchAddr,
	    (unsigned long)(scratchAddr + scratchSize),
	    scratchSize);

	scratchAddr = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__DATA", &scratchSize);
	IOLog("kaslr: start 0x%lx end 0x%lx length %lu for __DATA \n",
	    (unsigned long)scratchAddr,
	    (unsigned long)(scratchAddr + scratchSize),
	    scratchSize);

	scratchAddr = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__LINKEDIT", &scratchSize);
	IOLog("kaslr: start 0x%lx end 0x%lx length %lu for __LINKEDIT \n",
	    (unsigned long)scratchAddr,
	    (unsigned long)(scratchAddr + scratchSize),
	    scratchSize);

	scratchAddr = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__KLD", &scratchSize);
	IOLog("kaslr: start 0x%lx end 0x%lx length %lu for __KLD \n",
	    (unsigned long)scratchAddr,
	    (unsigned long)(scratchAddr + scratchSize),
	    scratchSize);

	scratchAddr = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_TEXT", &scratchSize);
	IOLog("kaslr: start 0x%lx end 0x%lx length %lu for __PRELINK_TEXT \n",
	    (unsigned long)scratchAddr,
	    (unsigned long)(scratchAddr + scratchSize),
	    scratchSize);

	scratchAddr = (vm_offset_t) getsegdatafromheader(&_mh_execute_header, "__PRELINK_INFO", &scratchSize);
	IOLog("kaslr: start 0x%lx end 0x%lx length %lu for __PRELINK_INFO \n",
	    (unsigned long)scratchAddr,
	    (unsigned long)(scratchAddr + scratchSize),
	    scratchSize);
#endif

	prelinkData = (void *) prelinkTextSegment->vmaddr;
	prelinkLength = prelinkTextSegment->vmsize;

	/* build arrays of plk info for later use */
	const char ** segNamePtr;

	for (segNamePtr = &plk_segNames[0], i = 0; *segNamePtr && i < PLK_SEGMENTS; segNamePtr++, i++) {
		plk_segSizes[i] = 0;
		plk_segAddrs[i] = (vm_offset_t)getsegdatafromheader(&_mh_execute_header, *segNamePtr, &plk_segSizes[i]);
	}


	/* Unserialize the info dictionary from the prelink info section.
	 */
	parsedXML = OSUnserializeXML((const char *)prelinkInfoSect->addr,
	    &errorString);
	if (parsedXML) {
		prelinkInfoDict = OSDynamicCast(OSDictionary, parsedXML);
	}
	if (!prelinkInfoDict) {
		const char * errorCString = "(unknown error)";

		if (errorString && errorString->getCStringNoCopy()) {
			errorCString = errorString->getCStringNoCopy();
		} else if (parsedXML) {
			errorCString = "not a dictionary";
		}
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "Error unserializing prelink plist: %s.", errorCString);
		goto finish;
	}

#if NO_KEXTD
	/* Check if we should keep developer kexts around.
	 * TODO: Check DeviceTree instead of a boot-arg <rdar://problem/10604201>
	 */
	developerDevice = true;
	PE_parse_boot_argn("developer", &developerDevice, sizeof(developerDevice));

	ramDiskBoot = IORamDiskBSDRoot();
#endif /* NO_KEXTD */

	/* Copy in the kernelcache UUID */
	kernelcacheUUID = OSDynamicCast(OSData,
	    prelinkInfoDict->getObject(kPrelinkInfoKCIDKey));
	if (kernelcacheUUID) {
		if (kernelcacheUUID->getLength() != sizeof(kernelcache_uuid)) {
			panic("kernelcacheUUID length is %d, expected %lu", kernelcacheUUID->getLength(),
			    sizeof(kernelcache_uuid));
		} else {
			kernelcache_uuid_valid = TRUE;
			memcpy((void *)&kernelcache_uuid, (const void *)kernelcacheUUID->getBytesNoCopy(), kernelcacheUUID->getLength());
			uuid_unparse_upper(kernelcache_uuid, kernelcache_uuid_string);
		}
	}

	infoDictArray = OSDynamicCast(OSArray,
	    prelinkInfoDict->getObject(kPrelinkInfoDictionaryKey));
	if (!infoDictArray) {
		OSKextLog(/* kext */ NULL, kOSKextLogErrorLevel | kOSKextLogArchiveFlag,
		    "The prelinked kernel has no kext info dictionaries");
		goto finish;
	}

	/* kaslrOffsets are available use them to slide local relocations */
	kaslrOffsets = OSDynamicCast(OSData,
	    prelinkInfoDict->getObject(kPrelinkLinkKASLROffsetsKey));

	/* Create dictionary of excluded kexts
	 */
#ifndef CONFIG_EMBEDDED
	OSKext::createExcludeListFromPrelinkInfo(infoDictArray);
#endif
	/* Create OSKext objects for each info dictionary.
	 */
	for (i = 0; i < infoDictArray->getCount(); ++i) {
		infoDict = OSDynamicCast(OSDictionary, infoDictArray->getObject(i));
		if (!infoDict) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
			    "Can't find info dictionary for prelinked kext #%d.", i);
			continue;
		}

#if NO_KEXTD
		dontLoad = false;

		/* If we're not on a developer device, skip and free developer kexts.
		 */
		if (developerDevice == false) {
			OSBoolean *devOnlyBool = OSDynamicCast(OSBoolean,
			    infoDict->getObject(kOSBundleDeveloperOnlyKey));
			if (devOnlyBool == kOSBooleanTrue) {
				dontLoad = true;
			}
		}

		/* Skip and free kexts that are only needed when booted from a ram disk.
		 */
		if (ramDiskBoot == false) {
			OSBoolean *ramDiskOnlyBool = OSDynamicCast(OSBoolean,
			    infoDict->getObject(kOSBundleRamDiskOnlyKey));
			if (ramDiskOnlyBool == kOSBooleanTrue) {
				dontLoad = true;
			}
		}

		if (dontLoad == true) {
			OSString *bundleID = OSDynamicCast(OSString,
			    infoDict->getObject(kCFBundleIdentifierKey));
			if (bundleID) {
				OSKextLog(NULL, kOSKextLogWarningLevel | kOSKextLogGeneralFlag,
				    "Kext %s not loading.", bundleID->getCStringNoCopy());
			}

			OSNumber *addressNum = OSDynamicCast(OSNumber,
			    infoDict->getObject(kPrelinkExecutableLoadKey));
			OSNumber *lengthNum = OSDynamicCast(OSNumber,
			    infoDict->getObject(kPrelinkExecutableSizeKey));
			if (addressNum && lengthNum) {
#if __arm__ || __arm64__
				vm_offset_t data = ml_static_slide(addressNum->unsigned64BitValue());
				vm_size_t length = (vm_size_t) (lengthNum->unsigned32BitValue());
				ml_static_mfree(data, length);
#else
#error Pick the right way to free prelinked data on this arch
#endif
			}

			infoDictArray->removeObject(i--);
			continue;
		}
#endif /* NO_KEXTD */

		/* Create the kext for the entry, then release it, because the
		 * kext system keeps them around until explicitly removed.
		 * Any creation/registration failures are already logged for us.
		 */
		OSKext * newKext = OSKext::withPrelinkedInfoDict(infoDict, (kaslrOffsets ? TRUE : FALSE));
		OSSafeReleaseNULL(newKext);
	}

	/* slide kxld relocations */
	if (kaslrOffsets && vm_kernel_slide > 0) {
		int slidKextAddrCount = 0;
		int badSlideAddr = 0;
		int badSlideTarget = 0;

		const kaslrPackedOffsets * myOffsets = NULL;
		myOffsets = (const kaslrPackedOffsets *) kaslrOffsets->getBytesNoCopy();

		for (uint32_t j = 0; j < myOffsets->count; j++) {
			uint64_t        slideOffset = (uint64_t) myOffsets->offsetsArray[j];
			uintptr_t *     slideAddr = (uintptr_t *) ((uint64_t)prelinkData + slideOffset);
			int             slideAddrSegIndex = -1;
			int             addrToSlideSegIndex = -1;

			slideAddrSegIndex = __whereIsAddr((vm_offset_t)slideAddr, &plk_segSizes[0], &plk_segAddrs[0], PLK_SEGMENTS );
			if (slideAddrSegIndex >= 0) {
				addrToSlideSegIndex = __whereIsAddr(ml_static_slide((vm_offset_t)(*slideAddr)), &plk_segSizes[0], &plk_segAddrs[0], PLK_SEGMENTS );
				if (addrToSlideSegIndex < 0) {
					badSlideTarget++;
					continue;
				}
			} else {
				badSlideAddr++;
				continue;
			}

			slidKextAddrCount++;
			*slideAddr = ml_static_slide(*slideAddr);
		} // for ...

		/* All kexts are now slid, set VM protections for them */
		OSKext::setAllVMAttributes();
	}

	/* Store the number of prelinked kexts in the registry so we can tell
	 * when the system has been started from a prelinked kernel.
	 */
	registryRoot = IORegistryEntry::getRegistryRoot();
	assert(registryRoot);

	prelinkCountObj = OSNumber::withNumber(
		(unsigned long long)infoDictArray->getCount(),
		8 * sizeof(uint32_t));
	assert(prelinkCountObj);
	if (prelinkCountObj) {
		registryRoot->setProperty(kOSPrelinkKextCountKey, prelinkCountObj);
	}

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogGeneralFlag | kOSKextLogKextBookkeepingFlag |
	    kOSKextLogDirectoryScanFlag | kOSKextLogArchiveFlag,
	    "%u prelinked kexts",
	    infoDictArray->getCount());

#if CONFIG_KEXT_BASEMENT
	/* On CONFIG_KEXT_BASEMENT systems, kexts are copied to their own
	 * special VM region during OSKext init time, so we can free the whole
	 * segment now.
	 */
	ml_static_mfree((vm_offset_t) prelinkData, prelinkLength);
#endif /* __x86_64__ */

	/* Free the prelink info segment, we're done with it.
	 */
	prelinkInfoSegment = getsegbyname(kPrelinkInfoSegment);
	if (prelinkInfoSegment) {
		ml_static_mfree((vm_offset_t)prelinkInfoSegment->vmaddr,
		    (vm_size_t)prelinkInfoSegment->vmsize);
	}

finish:
	OSSafeReleaseNULL(errorString);
	OSSafeReleaseNULL(parsedXML);
	OSSafeReleaseNULL(theKernel);
	OSSafeReleaseNULL(prelinkCountObj);
	return;
}

static int
__whereIsAddr(vm_offset_t theAddr, unsigned long * segSizes, vm_offset_t *segAddrs, int segCount)
{
	int i;

	for (i = 0; i < segCount; i++) {
		vm_offset_t         myAddr = *(segAddrs + i);
		unsigned long       mySize = *(segSizes + i);

		if (theAddr >= myAddr && theAddr < (myAddr + mySize)) {
			return i;
		}
	}

	return -1;
}


/*********************************************************************
*********************************************************************/
#define BOOTER_KEXT_PREFIX   "Driver-"

typedef struct _DeviceTreeBuffer {
	uint32_t paddr;
	uint32_t length;
} _DeviceTreeBuffer;

void
KLDBootstrap::readBooterExtensions(void)
{
	IORegistryEntry           * booterMemoryMap         = NULL;// must release
	OSDictionary              * propertyDict            = NULL;// must release
	OSCollectionIterator      * keyIterator             = NULL;// must release
	OSString                  * deviceTreeName          = NULL;// do not release

	const _DeviceTreeBuffer   * deviceTreeBuffer        = NULL;// do not free
	char                      * booterDataPtr           = NULL;// do not free
	OSData                    * booterData              = NULL;// must release

	OSKext                    * aKext                   = NULL;// must release

	OSKextLog(/* kext */ NULL,
	    kOSKextLogProgressLevel |
	    kOSKextLogDirectoryScanFlag | kOSKextLogKextBookkeepingFlag,
	    "Reading startup extensions from booter memory.");

	booterMemoryMap = IORegistryEntry::fromPath( "/chosen/memory-map", gIODTPlane);

	if (!booterMemoryMap) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag | kOSKextLogDirectoryScanFlag,
		    "Can't read booter memory map.");
		goto finish;
	}

	propertyDict = booterMemoryMap->dictionaryWithProperties();
	if (!propertyDict) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogDirectoryScanFlag,
		    "Can't get property dictionary from memory map.");
		goto finish;
	}

	keyIterator = OSCollectionIterator::withCollection(propertyDict);
	if (!keyIterator) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag,
		    "Can't allocate iterator for driver images.");
		goto finish;
	}

	/* Create dictionary of excluded kexts
	 */
#ifndef CONFIG_EMBEDDED
	OSKext::createExcludeListFromBooterData(propertyDict, keyIterator);
#endif
	keyIterator->reset();

	while ((deviceTreeName =
	    OSDynamicCast(OSString, keyIterator->getNextObject()))) {
		const char * devTreeNameCString = deviceTreeName->getCStringNoCopy();
		OSData * deviceTreeEntry = OSDynamicCast(OSData,
		    propertyDict->getObject(deviceTreeName));

		/* Clear out the booterData from the prior iteration.
		 */
		OSSafeReleaseNULL(booterData);

		/* If there is no entry for the name, we can't do much with it. */
		if (!deviceTreeEntry) {
			continue;
		}

		/* Make sure it is a kext */
		if (strncmp(devTreeNameCString,
		    BOOTER_KEXT_PREFIX,
		    CONST_STRLEN(BOOTER_KEXT_PREFIX))) {
			continue;
		}

		deviceTreeBuffer = (const _DeviceTreeBuffer *)
		    deviceTreeEntry->getBytesNoCopy(0, sizeof(deviceTreeBuffer));
		if (!deviceTreeBuffer) {
			/* We can't get to the data, so we can't do anything,
			 * not even free it from physical memory (if it's there).
			 */
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogDirectoryScanFlag,
			    "Device tree entry %s has NULL pointer.",
			    devTreeNameCString);
			goto finish; // xxx - continue, panic?
		}

		booterDataPtr = (char *)ml_static_ptovirt(deviceTreeBuffer->paddr);
		if (!booterDataPtr) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogDirectoryScanFlag,
			    "Can't get virtual address for device tree entry %s.",
			    devTreeNameCString);
			goto finish;
		}

		/* Wrap the booter data buffer in an OSData and set a dealloc function
		 * so it will take care of the physical memory when freed. Kexts will
		 * retain the booterData for as long as they need it. Remove the entry
		 * from the booter memory map after this is done.
		 */
		booterData = OSData::withBytesNoCopy(booterDataPtr,
		    deviceTreeBuffer->length);
		if (!booterData) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogErrorLevel |
			    kOSKextLogGeneralFlag,
			    "Error - Can't allocate OSData wrapper for device tree entry %s.",
			    devTreeNameCString);
			goto finish;
		}
		booterData->setDeallocFunction(osdata_phys_free);

		/* Create the kext for the entry, then release it, because the
		 * kext system keeps them around until explicitly removed.
		 * Any creation/registration failures are already logged for us.
		 */
		OSKext * newKext = OSKext::withBooterData(deviceTreeName, booterData);
		OSSafeReleaseNULL(newKext);

		booterMemoryMap->removeProperty(deviceTreeName);
	} /* while ( (deviceTreeName = OSDynamicCast(OSString, ...) ) ) */

finish:

	OSSafeReleaseNULL(booterMemoryMap);
	OSSafeReleaseNULL(propertyDict);
	OSSafeReleaseNULL(keyIterator);
	OSSafeReleaseNULL(booterData);
	OSSafeReleaseNULL(aKext);
	return;
}

/*********************************************************************
*********************************************************************/
#define COM_APPLE  "com.apple."

void
KLDBootstrap::loadSecurityExtensions(void)
{
	OSDictionary         * extensionsDict = NULL;// must release
	OSCollectionIterator * keyIterator    = NULL;// must release
	OSString             * bundleID       = NULL;// don't release
	OSKext               * theKext        = NULL;// don't release

	OSKextLog(/* kext */ NULL,
	    kOSKextLogStepLevel |
	    kOSKextLogLoadFlag,
	    "Loading security extensions.");

	extensionsDict = OSKext::copyKexts();
	if (!extensionsDict) {
		return;
	}

	keyIterator = OSCollectionIterator::withCollection(extensionsDict);
	if (!keyIterator) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag,
		    "Failed to allocate iterator for security extensions.");
		goto finish;
	}

	while ((bundleID = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
		const char * bundle_id = bundleID->getCStringNoCopy();

		/* Skip extensions whose bundle IDs don't start with "com.apple.".
		 */
		if (!bundle_id ||
		    (strncmp(bundle_id, COM_APPLE, CONST_STRLEN(COM_APPLE)) != 0)) {
			continue;
		}

		theKext = OSDynamicCast(OSKext, extensionsDict->getObject(bundleID));
		if (!theKext) {
			continue;
		}

		if (kOSBooleanTrue == theKext->getPropertyForHostArch(kAppleSecurityExtensionKey)) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogStepLevel |
			    kOSKextLogLoadFlag,
			    "Loading security extension %s.", bundleID->getCStringNoCopy());
			OSKext::loadKextWithIdentifier(bundleID->getCStringNoCopy(),
			    /* allowDefer */ false);
		}
	}

finish:
	OSSafeReleaseNULL(keyIterator);
	OSSafeReleaseNULL(extensionsDict);

	return;
}

/*********************************************************************
* We used to require that all listed kernel components load, but
* nowadays we can get them from userland so we only try to load the
* ones we have. If an error occurs later, such is life.
*
* Note that we look the kexts up first, so we can avoid spurious
* (in this context, anyhow) log messages about kexts not being found.
*
* xxx - do we even need to do this any more? Check if the kernel
* xxx - compoonents just load in the regular paths
*********************************************************************/
OSReturn
KLDBootstrap::loadKernelComponentKexts(void)
{
	OSReturn      result      = kOSReturnSuccess;// optimistic
	OSKext      * theKext     = NULL;          // must release
	const char ** kextIDPtr   = NULL;          // do not release

	for (kextIDPtr = &sKernelComponentNames[0]; *kextIDPtr; kextIDPtr++) {
		OSSafeReleaseNULL(theKext);
		theKext = OSKext::lookupKextWithIdentifier(*kextIDPtr);

		if (theKext) {
			if (kOSReturnSuccess != OSKext::loadKextWithIdentifier(
				    *kextIDPtr, /* allowDefer */ false)) {
				// xxx - check KextBookkeeping, might be redundant
				OSKextLog(/* kext */ NULL,
				    kOSKextLogErrorLevel |
				    kOSKextLogDirectoryScanFlag | kOSKextLogKextBookkeepingFlag,
				    "Failed to initialize kernel component %s.", *kextIDPtr);
				result = kOSReturnError;
			}
		}
	}

	OSSafeReleaseNULL(theKext);
	return result;
}

/*********************************************************************
* Ensure that Kernel External Components are loaded early in boot,
* before other kext personalities get sent to the IOCatalogue. These
* kexts are treated specially because they may provide the implementation
* for kernel-vended KPI, so they must register themselves before
* general purpose IOKit probing begins.
*********************************************************************/

#define COM_APPLE_KEC  "com.apple.kec."

void
KLDBootstrap::loadKernelExternalComponents(void)
{
	OSDictionary         * extensionsDict = NULL;// must release
	OSCollectionIterator * keyIterator    = NULL;// must release
	OSString             * bundleID       = NULL;// don't release
	OSKext               * theKext        = NULL;// don't release
	OSBoolean            * isKernelExternalComponent = NULL;// don't release

	OSKextLog(/* kext */ NULL,
	    kOSKextLogStepLevel |
	    kOSKextLogLoadFlag,
	    "Loading Kernel External Components.");

	extensionsDict = OSKext::copyKexts();
	if (!extensionsDict) {
		return;
	}

	keyIterator = OSCollectionIterator::withCollection(extensionsDict);
	if (!keyIterator) {
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogGeneralFlag,
		    "Failed to allocate iterator for Kernel External Components.");
		goto finish;
	}

	while ((bundleID = OSDynamicCast(OSString, keyIterator->getNextObject()))) {
		const char * bundle_id = bundleID->getCStringNoCopy();

		/* Skip extensions whose bundle IDs don't start with "com.apple.kec.".
		 */
		if (!bundle_id ||
		    (strncmp(bundle_id, COM_APPLE_KEC, CONST_STRLEN(COM_APPLE_KEC)) != 0)) {
			continue;
		}

		theKext = OSDynamicCast(OSKext, extensionsDict->getObject(bundleID));
		if (!theKext) {
			continue;
		}

		isKernelExternalComponent = OSDynamicCast(OSBoolean,
		    theKext->getPropertyForHostArch(kAppleKernelExternalComponentKey));
		if (isKernelExternalComponent && isKernelExternalComponent->isTrue()) {
			OSKextLog(/* kext */ NULL,
			    kOSKextLogStepLevel |
			    kOSKextLogLoadFlag,
			    "Loading kernel external component %s.", bundleID->getCStringNoCopy());
			OSKext::loadKextWithIdentifier(bundleID->getCStringNoCopy(),
			    /* allowDefer */ false);
		}
	}

finish:
	OSSafeReleaseNULL(keyIterator);
	OSSafeReleaseNULL(extensionsDict);

	return;
}

/*********************************************************************
*********************************************************************/
void
KLDBootstrap::readBuiltinPersonalities(void)
{
	OSObject              * parsedXML             = NULL;// must release
	OSArray               * builtinExtensions     = NULL;// do not release
	OSArray               * allPersonalities      = NULL;// must release
	OSString              * errorString           = NULL;// must release
	kernel_section_t      * infosect              = NULL;// do not free
	OSCollectionIterator  * personalitiesIterator = NULL;// must release
	unsigned int            count, i;

	OSKextLog(/* kext */ NULL,
	    kOSKextLogStepLevel |
	    kOSKextLogLoadFlag,
	    "Reading built-in kernel personalities for I/O Kit drivers.");

	/* Look in the __BUILTIN __info segment for an array of Info.plist
	 * entries. For each one, extract the personalities dictionary, add
	 * it to our array, then push them all (without matching) to
	 * the IOCatalogue. This can be used to augment the personalities
	 * in gIOKernelConfigTables, especially when linking entire kexts into
	 * the mach_kernel image.
	 */
	infosect   = getsectbyname("__BUILTIN", "__info");
	if (!infosect) {
		// this isn't fatal
		goto finish;
	}

	parsedXML = OSUnserializeXML((const char *) (uintptr_t)infosect->addr,
	    &errorString);
	if (parsedXML) {
		builtinExtensions = OSDynamicCast(OSArray, parsedXML);
	}
	if (!builtinExtensions) {
		const char * errorCString = "(unknown error)";

		if (errorString && errorString->getCStringNoCopy()) {
			errorCString = errorString->getCStringNoCopy();
		} else if (parsedXML) {
			errorCString = "not an array";
		}
		OSKextLog(/* kext */ NULL,
		    kOSKextLogErrorLevel |
		    kOSKextLogLoadFlag,
		    "Error unserializing built-in personalities: %s.", errorCString);
		goto finish;
	}

	// estimate 3 personalities per Info.plist/kext
	count = builtinExtensions->getCount();
	allPersonalities = OSArray::withCapacity(count * 3);

	for (i = 0; i < count; i++) {
		OSDictionary            * infoDict = NULL;// do not release
		OSString                * moduleName = NULL;// do not release
		OSDictionary            * personalities;// do not release
		OSString                * personalityName;// do not release

		OSSafeReleaseNULL(personalitiesIterator);

		infoDict = OSDynamicCast(OSDictionary,
		    builtinExtensions->getObject(i));
		if (!infoDict) {
			continue;
		}

		moduleName = OSDynamicCast(OSString,
		    infoDict->getObject(kCFBundleIdentifierKey));
		if (!moduleName) {
			continue;
		}

		OSKextLog(/* kext */ NULL,
		    kOSKextLogStepLevel |
		    kOSKextLogLoadFlag,
		    "Adding personalities for built-in driver %s:",
		    moduleName->getCStringNoCopy());

		personalities = OSDynamicCast(OSDictionary,
		    infoDict->getObject("IOKitPersonalities"));
		if (!personalities) {
			continue;
		}

		personalitiesIterator = OSCollectionIterator::withCollection(personalities);
		if (!personalitiesIterator) {
			continue; // xxx - well really, what can we do? should we panic?
		}

		while ((personalityName = OSDynamicCast(OSString,
		    personalitiesIterator->getNextObject()))) {
			OSDictionary * personality = OSDynamicCast(OSDictionary,
			    personalities->getObject(personalityName));

			OSKextLog(/* kext */ NULL,
			    kOSKextLogDetailLevel |
			    kOSKextLogLoadFlag,
			    "Adding built-in driver personality %s.",
			    personalityName->getCStringNoCopy());

			if (personality && !personality->getObject(kCFBundleIdentifierKey)) {
				personality->setObject(kCFBundleIdentifierKey, moduleName);
			}
			allPersonalities->setObject(personality);
		}
	}

	gIOCatalogue->addDrivers(allPersonalities, false);

finish:
	OSSafeReleaseNULL(parsedXML);
	OSSafeReleaseNULL(allPersonalities);
	OSSafeReleaseNULL(errorString);
	OSSafeReleaseNULL(personalitiesIterator);
	return;
}

#if PRAGMA_MARK
#pragma mark Bootstrap Functions
#endif
/*********************************************************************
* Bootstrap Functions
*********************************************************************/
static void
bootstrapRecordStartupExtensions(void)
{
	sBootstrapObject.readStartupExtensions();
	return;
}

static void
bootstrapLoadSecurityExtensions(void)
{
	sBootstrapObject.loadSecurityExtensions();
	return;
}

