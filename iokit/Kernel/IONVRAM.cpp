/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
 * Copyright (c) 2007-2012 Apple Inc. All rights reserved.
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

#define IOKIT_ENABLE_SHARED_PTR

#include <AssertMacros.h>
#include <IOKit/IOLib.h>
#include <IOKit/IONVRAM.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOKitKeysPrivate.h>
#include <IOKit/IOBSD.h>
#include <kern/debug.h>
#include <pexpert/boot.h>
#include <pexpert/pexpert.h>
#include <sys/csr.h>

#define super IOService

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

// Internal values
#define NVRAM_CHRP_SIG_APPLE             0x5A
#define NVRAM_CHRP_APPLE_HEADER_NAME     "nvram"

// From Apple CHRP Spec
#define NVRAM_CHRP_SIG_SYSTEM    0x70
#define NVRAM_CHRP_SIG_CONFIG    0x71

#define NVRAM_CHRP_PARTITION_NAME_COMMON_V1   "common"
#define NVRAM_CHRP_PARTITION_NAME_SYSTEM_V1   "system"
#define NVRAM_CHRP_PARTITION_NAME_COMMON_V2   "2common"
#define NVRAM_CHRP_PARTITION_NAME_SYSTEM_V2   "2system"

#define NVRAM_CHRP_LENGTH_BLOCK_SIZE 0x10 // CHRP length field is in 16 byte blocks

typedef struct chrp_nvram_header { //16 bytes
	uint8_t  sig;
	uint8_t  cksum; // checksum on sig, len, and name
	uint16_t len;   // total length of the partition in 16 byte blocks starting with the signature
	// and ending with the last byte of data area, ie len includes its own header size
	char     name[12];
	uint8_t  data[0];
} chrp_nvram_header_t;

typedef struct apple_nvram_header {  // 16 + 16 bytes
	struct   chrp_nvram_header chrp;
	uint32_t adler;
	uint32_t generation;
	uint8_t  padding[8];
} apple_nvram_header_t;


#define kIONVRAMPrivilege       kIOClientPrivilegeAdministrator

OSDefineMetaClassAndStructors(IODTNVRAM, IOService);

#if defined(DEBUG) || defined(DEVELOPMENT)
#define DEBUG_INFO(fmt, args...)                                    \
({                                                                  \
	if (gNVRAMLogging)                                              \
	IOLog("IONVRAM::%s:%u - " fmt, __FUNCTION__, __LINE__, ##args); \
})

#define DEBUG_ALWAYS(fmt, args...)                                  \
({                                                                  \
	IOLog("IONVRAM::%s:%u - " fmt, __FUNCTION__, __LINE__, ##args); \
})
#else
#define DEBUG_INFO(fmt, args...)
#define DEBUG_ALWAYS(fmt, args...)
#endif

#define DEBUG_ERROR DEBUG_ALWAYS

#define CONTROLLERLOCK()                             \
({                                                   \
	if (preemption_enabled() && !panic_active()) \
	        IOLockLock(_controllerLock);         \
})

#define CONTROLLERUNLOCK()                           \
({                                                   \
	if (preemption_enabled() && !panic_active()) \
	        IOLockUnlock(_controllerLock);       \
})

#define NVRAMREADLOCK()                             \
({                                                  \
	if (preemption_enabled() && !panic_active()) \
	        IORWLockRead(_variableLock);         \
})

#define NVRAMWRITELOCK()                            \
({                                                  \
	if (preemption_enabled() && !panic_active()) \
	        IORWLockWrite(_variableLock);        \
})

#define NVRAMUNLOCK()                               \
({                                                  \
	if (preemption_enabled() && !panic_active()) \
	        IORWLockUnlock(_variableLock);       \
})

#define NVRAMLOCKASSERTHELD()                                      \
({                                                                 \
	if (preemption_enabled() && !panic_active())                \
	        IORWLockAssert(_variableLock, kIORWLockAssertHeld); \
})

#define NVRAMLOCKASSERTEXCLUSIVE()                                  \
({                                                                  \
	if (preemption_enabled() && !panic_active())                 \
	        IORWLockAssert(_variableLock, kIORWLockAssertWrite); \
})

enum NVRAMPartitionType {
	kIONVRAMPartitionSystem,
	kIONVRAMPartitionCommon
};

typedef struct {
	NVRAMPartitionType        type;
	UInt32                    offset;
	UInt32                    size;
	OSSharedPtr<OSDictionary> &dict;
	UInt8                     *image;
} NVRAMRegionInfo;

// Guid for Apple System Boot variables
// 40A0DDD2-77F8-4392-B4A3-1E7304206516
UUID_DEFINE(gAppleSystemVariableGuid, 0x40, 0xA0, 0xDD, 0xD2, 0x77, 0xF8, 0x43, 0x92, 0xB4, 0xA3, 0x1E, 0x73, 0x04, 0x20, 0x65, 0x16);

// Apple NVRAM Variable namespace (APPLE_VENDOR_OS_VARIABLE_GUID)
// 7C436110-AB2A-4BBB-A880-FE41995C9F82
UUID_DEFINE(gAppleNVRAMGuid, 0x7C, 0x43, 0x61, 0x10, 0xAB, 0x2A, 0x4B, 0xBB, 0xA8, 0x80, 0xFE, 0x41, 0x99, 0x5C, 0x9F, 0x82);

static bool gNVRAMLogging = false;
static bool gInternalBuild = false;

// allowlist variables from macboot that need to be set/get from system region if present
static const char * const gNVRAMSystemList[] = {
	"allow-root-hash-mismatch",
	"auto-boot",
	"auto-boot-halt-stage",
	"base-system-path",
	"boot-args",
	"boot-command",
	"boot-image",
	"bootdelay",
	"com.apple.System.boot-nonce",
	"darkboot",
	"emu",
	"one-time-boot-command", // Needed for diags customer install flows
	"policy-nonce-digests",
	"prevent-restores", // Keep for factory <rdar://problem/70476321>
	"prev-lang:kbd",
	"root-live-fs",
	"StartupMute", // Set by customers via nvram tool
	"SystemAudioVolume",
	"SystemAudioVolumeExtension",
	"SystemAudioVolumeSaved",
	nullptr
};

typedef struct {
	const char *name;
	IONVRAMVariableType type;
} VariableTypeEntry;

static const
VariableTypeEntry gVariableTypes[] = {
	{"auto-boot?", kOFVariableTypeBoolean},
	{"boot-args", kOFVariableTypeString},
	{"boot-command", kOFVariableTypeString},
	{"boot-device", kOFVariableTypeString},
	{"boot-file", kOFVariableTypeString},
	{"boot-screen", kOFVariableTypeString},
	{"boot-script", kOFVariableTypeString},
	{"console-screen", kOFVariableTypeString},
	{"default-client-ip", kOFVariableTypeString},
	{"default-gateway-ip", kOFVariableTypeString},
	{"default-mac-address?", kOFVariableTypeBoolean},
	{"default-router-ip", kOFVariableTypeString},
	{"default-server-ip", kOFVariableTypeString},
	{"default-subnet-mask", kOFVariableTypeString},
	{"diag-device", kOFVariableTypeString},
	{"diag-file", kOFVariableTypeString},
	{"diag-switch?", kOFVariableTypeBoolean},
	{"fcode-debug?", kOFVariableTypeBoolean},
	{"input-device", kOFVariableTypeString},
	{"input-device-1", kOFVariableTypeString},
	{"little-endian?", kOFVariableTypeBoolean},
	{"load-base", kOFVariableTypeNumber},
	{"mouse-device", kOFVariableTypeString},
	{"nvramrc", kOFVariableTypeString},
	{"oem-banner", kOFVariableTypeString},
	{"oem-banner?", kOFVariableTypeBoolean},
	{"oem-logo", kOFVariableTypeString},
	{"oem-logo?", kOFVariableTypeBoolean},
	{"output-device", kOFVariableTypeString},
	{"output-device-1", kOFVariableTypeString},
	{"pci-probe-list", kOFVariableTypeNumber},
	{"pci-probe-mask", kOFVariableTypeNumber},
	{"real-base", kOFVariableTypeNumber},
	{"real-mode?", kOFVariableTypeBoolean},
	{"real-size", kOFVariableTypeNumber},
	{"screen-#columns", kOFVariableTypeNumber},
	{"screen-#rows", kOFVariableTypeNumber},
	{"security-mode", kOFVariableTypeString},
	{"selftest-#megs", kOFVariableTypeNumber},
	{"use-generic?", kOFVariableTypeBoolean},
	{"use-nvramrc?", kOFVariableTypeBoolean},
	{"virt-base", kOFVariableTypeNumber},
	{"virt-size", kOFVariableTypeNumber},

#if !defined(__x86_64__)
	{"acc-cm-override-charger-count", kOFVariableTypeNumber},
	{"acc-cm-override-count", kOFVariableTypeNumber},
	{"acc-mb-ld-lifetime", kOFVariableTypeNumber},
	{"com.apple.System.boot-nonce", kOFVariableTypeString},
	{"darkboot", kOFVariableTypeBoolean},
	{"enter-tdm-mode", kOFVariableTypeBoolean},
#endif /* !defined(__x86_64__) */
	{nullptr, kOFVariableTypeData} // Default type to return
};

union VariablePermission {
	struct {
		uint64_t UserWrite            :1;
		uint64_t RootRequired         :1;
		uint64_t KernelOnly           :1;
		uint64_t ResetNVRAMOnlyDelete :1;
		uint64_t NeverAllowedToDelete :1;
		uint64_t SystemReadHidden     :1;
		uint64_t FullAccess           :1;
		uint64_t Reserved:57;
	} Bits;
	uint64_t Uint64;
};

typedef struct {
	const char *name;
	VariablePermission p;
} VariablePermissionEntry;

static const
VariablePermissionEntry gVariablePermissions[] = {
	{"aapl,pci", .p.Bits.RootRequired = 1},
	{"battery-health", .p.Bits.RootRequired = 1,
	 .p.Bits.NeverAllowedToDelete = 1},
	{"boot-image", .p.Bits.UserWrite = 1},
	{"com.apple.System.fp-state", .p.Bits.KernelOnly = 1},
	{"policy-nonce-digests", .p.Bits.ResetNVRAMOnlyDelete = 1}, // Deleting this via user triggered obliterate leave J273a unable to boot
	{"recoveryos-passcode-blob", .p.Bits.SystemReadHidden = 1},
	{"security-password", .p.Bits.RootRequired = 1},
	{"system-passcode-lock-blob", .p.Bits.SystemReadHidden = 1},

#if !defined(__x86_64__)
	{"acc-cm-override-charger-count", .p.Bits.KernelOnly = 1},
	{"acc-cm-override-count", .p.Bits.KernelOnly = 1},
	{"acc-mb-ld-lifetime", .p.Bits.KernelOnly = 1},
	{"backlight-level", .p.Bits.UserWrite = 1},
	{"backlight-nits", .p.Bits.UserWrite = 1},
	{"com.apple.System.boot-nonce", .p.Bits.KernelOnly = 1},
	{"com.apple.System.sep.art", .p.Bits.KernelOnly = 1},
	{"darkboot", .p.Bits.UserWrite = 1},
	{"nonce-seeds", .p.Bits.KernelOnly = 1},
#endif /* !defined(__x86_64__) */

	{nullptr, {.Bits.FullAccess = 1}} // Default access
};

static IONVRAMVariableType
getVariableType(const char *propName)
{
	const VariableTypeEntry *entry;

	entry = gVariableTypes;
	while (entry->name != nullptr) {
		if (strcmp(entry->name, propName) == 0) {
			break;
		}
		entry++;
	}

	return entry->type;
}

static IONVRAMVariableType
getVariableType(const OSSymbol *propSymbol)
{
	return getVariableType(propSymbol->getCStringNoCopy());
}

static VariablePermission
getVariablePermission(const char *propName)
{
	const VariablePermissionEntry *entry;

	entry = gVariablePermissions;
	while (entry->name != nullptr) {
		if (strcmp(entry->name, propName) == 0) {
			break;
		}
		entry++;
	}

	return entry->p;
}

static bool
variableInAllowList(const char *varName)
{
	unsigned int i = 0;

	while (gNVRAMSystemList[i] != nullptr) {
		if (strcmp(varName, gNVRAMSystemList[i]) == 0) {
			return true;
		}
		i++;
	}

	return false;
}

static bool
verifyWriteSizeLimit(const uuid_t *varGuid, const char *variableName, size_t propDataSize)
{
	if (variableInAllowList(variableName)) {
		if (strnstr(variableName, "breadcrumbs", strlen(variableName)) != NULL) {
			return propDataSize <= 1024;
		} else {
			return propDataSize <= 768;
		}
	}

	return true;
}

#if defined(DEBUG) || defined(DEVELOPMENT)
static const char *
getNVRAMOpString(IONVRAMOperation op)
{
	switch (op) {
	case kIONVRAMOperationRead:
		return "Read";
	case kIONVRAMOperationWrite:
		return "Write";
	case kIONVRAMOperationDelete:
		return "Delete";
	case kIONVRAMOperationObliterate:
		return "Obliterate";
	case kIONVRAMOperationReset:
		return "Reset";
	default:
		return "Unknown";
	}
}
#endif

static bool
verifyPermission(IONVRAMOperation op, const uuid_t *varGuid, const char *varName)
{
	VariablePermission perm;
	bool kernel, writeEntitled, readEntitled, allowList, systemGuid, systemEntitled, systemInternalEntitled, systemAllow, systemReadHiddenAllow;
	bool admin = false;
	bool ok = false;

	perm = getVariablePermission(varName);

	kernel = current_task() == kernel_task;

	if (perm.Bits.KernelOnly) {
		DEBUG_INFO("KernelOnly access for %s, kernel=%d\n", varName, kernel);
		ok = kernel;
		goto exit;
	}

	allowList              = variableInAllowList(varName);
	systemGuid             = uuid_compare(*varGuid, gAppleSystemVariableGuid) == 0;
	admin                  = IOUserClient::clientHasPrivilege(current_task(), kIONVRAMPrivilege) == kIOReturnSuccess;
	writeEntitled          = IOTaskHasEntitlement(current_task(), kIONVRAMWriteAccessKey);
	readEntitled           = IOTaskHasEntitlement(current_task(), kIONVRAMReadAccessKey);
	systemEntitled         = IOTaskHasEntitlement(current_task(), kIONVRAMSystemAllowKey);
	systemInternalEntitled = IOTaskHasEntitlement(current_task(), kIONVRAMSystemInternalAllowKey);
	systemReadHiddenAllow  = IOTaskHasEntitlement(current_task(), kIONVRAMSystemHiddenAllowKey);

	systemAllow = systemEntitled || (systemInternalEntitled && gInternalBuild) || kernel;

	switch (op) {
	case kIONVRAMOperationRead:
		if (systemGuid && perm.Bits.SystemReadHidden) {
			ok = systemReadHiddenAllow;
		} else if (kernel || admin || readEntitled || perm.Bits.FullAccess) {
			ok = true;
		}
		break;

	case kIONVRAMOperationWrite:
		if (kernel || perm.Bits.UserWrite || admin || writeEntitled) {
			if (systemGuid) {
				if (allowList) {
					if (!systemAllow) {
						DEBUG_ERROR("Allowed write to system region when NOT entitled for %s\n", varName);
					}
				} else if (!systemAllow) {
					DEBUG_ERROR("Not entitled for system region writes for %s\n", varName);
					break;
				}
			}
			ok = true;
		}
		break;

	case kIONVRAMOperationDelete:
	case kIONVRAMOperationObliterate:
	case kIONVRAMOperationReset:
		if (perm.Bits.NeverAllowedToDelete) {
			DEBUG_INFO("Never allowed to delete %s\n", varName);
			break;
		} else if ((op == kIONVRAMOperationObliterate) && perm.Bits.ResetNVRAMOnlyDelete) {
			DEBUG_INFO("Not allowed to obliterate %s\n", varName);
			break;
		} else if ((op == kIONVRAMOperationDelete) && perm.Bits.ResetNVRAMOnlyDelete) {
			DEBUG_INFO("Only allowed to delete %s via NVRAM reset\n", varName);
			break;
		}

		if (kernel || perm.Bits.UserWrite || admin || writeEntitled) {
			if (systemGuid) {
				if (allowList) {
					if (!systemAllow) {
						DEBUG_ERROR("Allowed delete to system region when NOT entitled for %s\n", varName);
					}
				} else if (!systemAllow) {
					DEBUG_ERROR("Not entitled for system region deletes for %s\n", varName);
					break;
				}
			}
			ok = true;
		}
		break;
	}

exit:
	DEBUG_INFO("Permission for %s of %s %s: kernel=%d, admin=%d, writeEntitled=%d, readEntitled=%d, systemGuid=%d, systemEntitled=%d, systemInternalEntitled=%d, systemReadHiddenAllow=%d, UserWrite=%d\n",
	    getNVRAMOpString(op), varName, ok ? "granted" : "denied", kernel, admin, writeEntitled, readEntitled, systemGuid, systemEntitled, systemInternalEntitled, systemReadHiddenAllow, perm.Bits.UserWrite);
	return ok;
}

static bool
verifyPermission(IONVRAMOperation op, const uuid_t *varGuid, const OSSymbol *varName)
{
	return verifyPermission(op, varGuid, varName->getCStringNoCopy());
}

/*
 * Parse a variable name of the form "GUID:name".
 * If the name cannot be parsed, substitute the Apple global variable GUID.
 * Returns TRUE if a GUID was found in the name, FALSE otherwise.
 * The guidResult and nameResult arguments may be nullptr if you just want
 * to check the format of the string.
 */
static bool
parseVariableName(const char *key, uuid_t *guidResult, const char **nameResult)
{
	uuid_string_t temp    = {0};
	size_t        keyLen  = strlen(key);
	bool          ok      = false;
	const char    *name   = key;
	uuid_t        guid;

	if (keyLen > sizeof(temp)) {
		// check for at least UUID + ":" + more
		memcpy(temp, key, sizeof(temp) - 1);

		if ((uuid_parse(temp, guid) == 0) &&
		    (key[sizeof(temp) - 1] == ':')) {
			name = key + sizeof(temp);
			ok     = true;
		}
	}

	if (guidResult) {
		ok ? uuid_copy(*guidResult, guid) : uuid_copy(*guidResult, gAppleNVRAMGuid);
	}
	if (nameResult) {
		*nameResult = name;
	}

	return false;
}

static bool
skipKey(const OSSymbol *aKey)
{
	return aKey->isEqualTo(kIOClassNameOverrideKey) ||
	       aKey->isEqualTo(kIOBSDNameKey) ||
	       aKey->isEqualTo(kIOBSDNamesKey) ||
	       aKey->isEqualTo(kIOBSDMajorKey) ||
	       aKey->isEqualTo(kIOBSDMinorKey) ||
	       aKey->isEqualTo(kIOBSDUnitKey);
}

// ************************** IODTNVRAMVariables ****************************

// private IOService based class for publishing distinct dictionary properties on
// for easy ioreg access since the serializeProperties call is overloaded and is used
// as variable access
class IODTNVRAMVariables : public IOService
{
	OSDeclareDefaultStructors(IODTNVRAMVariables)
private:
	IODTNVRAM        *_provider;
	OSDictionary     *_variables;
	uuid_t           _guid;

public:
	bool                    init(const uuid_t *guid);
	virtual bool            start(IOService * provider) APPLE_KEXT_OVERRIDE;
	virtual IOReturn        setVariables(OSObject * properties);

	virtual bool            serializeProperties(OSSerialize *s) const APPLE_KEXT_OVERRIDE;
	virtual OSPtr<OSObject> copyProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual OSObject        *getProperty(const OSSymbol *aKey) const APPLE_KEXT_OVERRIDE;
	virtual bool            setProperty(const OSSymbol *aKey, OSObject *anObject) APPLE_KEXT_OVERRIDE;
	virtual IOReturn        setProperties(OSObject *properties) APPLE_KEXT_OVERRIDE;
	virtual void            removeProperty(const OSSymbol *aKey) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(IODTNVRAMVariables, IOService)

bool
IODTNVRAMVariables::init(const uuid_t *guid)
{
	if (!super::init()) {
		return false;
	}

	if (guid == nullptr) {
		return false;
	}

	uuid_copy(_guid, *guid);

	return true;
}

bool
IODTNVRAMVariables::start(IOService * provider)
{
	if (!IOService::start(provider)) {
		goto error;
	}

	_provider = OSDynamicCast(IODTNVRAM, provider);
	if (_provider == nullptr) {
		goto error;
	}

	registerService();

	return true;

error:
	stop(provider);

	return false;
}

IOReturn
IODTNVRAMVariables::setVariables(OSObject * variables)
{
	if (OSDynamicCast(OSDictionary, variables)) {
		OSSafeReleaseNULL(_variables);
		_variables = OSDynamicCast(OSDictionary, variables);
		variables->retain();
	}

	return kIOReturnSuccess;
}

bool
IODTNVRAMVariables::serializeProperties(OSSerialize *s) const
{
	const OSSymbol                    *key;
	OSSharedPtr<OSDictionary>         dict;
	OSSharedPtr<OSCollectionIterator> iter;
	OSSharedPtr<OSDictionary>         localVariables(_variables, OSRetain);
	bool                              ok = false;

	if (localVariables == nullptr) {
		goto exit;
	}

	dict = OSDictionary::withCapacity(localVariables->getCount());
	if (dict == nullptr) {
		DEBUG_ERROR("No dictionary\n");
		goto exit;
	}

	iter = OSCollectionIterator::withCollection(localVariables.get());
	if (iter == nullptr) {
		DEBUG_ERROR("failed to create iterator\n");
		goto exit;
	}

	while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
		if (verifyPermission(kIONVRAMOperationRead, &_guid, key)) {
			dict->setObject(key, localVariables->getObject(key));
		}
	}

	ok = dict->serialize(s);

exit:
	DEBUG_INFO("ok=%d\n", ok);
	return ok;
}

OSPtr<OSObject>
IODTNVRAMVariables::copyProperty(const OSSymbol *aKey) const
{
	if (_provider && !skipKey(aKey)) {
		DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

		return _provider->copyPropertyWithGUIDAndName(&_guid, aKey->getCStringNoCopy());
	} else {
		return nullptr;
	}
}

OSObject *
IODTNVRAMVariables::getProperty(const OSSymbol *aKey) const
{
	OSSharedPtr<OSObject> theObject = copyProperty(aKey);

	return theObject.get();
}

bool
IODTNVRAMVariables::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
	if (_provider) {
		return _provider->setPropertyWithGUIDAndName(&_guid, aKey->getCStringNoCopy(), anObject);
	} else {
		return false;
	}
}

IOReturn
IODTNVRAMVariables::setProperties(OSObject *properties)
{
	IOReturn                          ret = kIOReturnSuccess;
	OSObject                          *object;
	const OSSymbol                    *key;
	OSDictionary                      *dict;
	OSSharedPtr<OSCollectionIterator> iter;

	if (_provider) {
		dict = OSDynamicCast(OSDictionary, properties);
		if (dict == nullptr) {
			DEBUG_ERROR("Not a dictionary\n");
			return kIOReturnBadArgument;
		}

		iter = OSCollectionIterator::withCollection(dict);
		if (iter == nullptr) {
			DEBUG_ERROR("Couldn't create iterator\n");
			return kIOReturnBadArgument;
		}

		while (ret == kIOReturnSuccess) {
			key = OSDynamicCast(OSSymbol, iter->getNextObject());
			if (key == nullptr) {
				break;
			}

			object = dict->getObject(key);
			if (object == nullptr) {
				continue;
			}

			ret = setProperty(key, object);
		}
	} else {
		ret = kIOReturnNotReady;
	}

	DEBUG_INFO("ret=%#08x\n", ret);

	return ret;
}

void
IODTNVRAMVariables::removeProperty(const OSSymbol *aKey)
{
	if (_provider) {
		_provider->removePropertyWithGUIDAndName(&_guid, aKey->getCStringNoCopy());
	}
}


// **************************** IODTNVRAM *********************************

bool
IODTNVRAM::init(IORegistryEntry *old, const IORegistryPlane *plane)
{
	OSSharedPtr<OSDictionary> dict;

	if (!super::init(old, plane)) {
		return false;
	}

	PE_parse_boot_argn("nvram-log", &gNVRAMLogging, sizeof(gNVRAMLogging));

#if XNU_TARGET_OS_OSX
#if CONFIG_CSR
	gInternalBuild = (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0);
#endif // CONFIG_CSR
#endif // XNU_TARGET_OS_OSX

	DEBUG_INFO("gInternalBuild = %d\n", gInternalBuild);

	_variableLock = IORWLockAlloc();
	if (!_variableLock) {
		return false;
	}

	_controllerLock = IOLockAlloc();
	if (!_controllerLock) {
		return false;
	}

	dict =  OSDictionary::withCapacity(1);
	if (dict == nullptr) {
		return false;
	}
	setPropertyTable(dict.get());
	dict.reset();

	_nvramSize = getNVRAMSize();
	if (_nvramSize == 0) {
		DEBUG_ERROR("NVRAM : Error - default size not specified in DT\n");
		return false;
	}
	// partition offsets are UInt16 (bytes / 0x10) + 1
	if (_nvramSize > 0xFFFF * 0x10) {
		DEBUG_ERROR("NVRAM : truncating _nvramSize from %ld\n", (long) _nvramSize);
		_nvramSize = 0xFFFF * 0x10;
	}
	_nvramImage = IONew(UInt8, _nvramSize);
	if (_nvramImage == nullptr) {
		return false;
	}

	_nvramPartitionOffsets = OSDictionary::withCapacity(1);
	if (_nvramPartitionOffsets == nullptr) {
		return false;
	}

	_nvramPartitionLengths = OSDictionary::withCapacity(1);
	if (_nvramPartitionLengths == nullptr) {
		return false;
	}

	_registryPropertiesKey = OSSymbol::withCStringNoCopy("aapl,pci");
	if (_registryPropertiesKey == nullptr) {
		return false;
	}

	// <rdar://problem/9529235> race condition possible between
	// IODTNVRAM and IONVRAMController (restore loses boot-args)
	initProxyData();

	// Require at least the common partition to be present and error free
	if (_commonDict == nullptr) {
		return false;
	}

	return true;
}

void
IODTNVRAM::initProxyData(void)
{
	OSSharedPtr<IORegistryEntry> entry;
	const char                   *key = "nvram-proxy-data";
	OSData                       *data;
	const void                   *bytes;

	entry = IORegistryEntry::fromPath("/chosen", gIODTPlane);
	if (entry != nullptr) {
		OSSharedPtr<OSObject> prop = entry->copyProperty(key);
		if (prop != nullptr) {
			data = OSDynamicCast(OSData, prop.get());
			if (data != nullptr) {
				bytes = data->getBytesNoCopy();
				if ((bytes != nullptr) && (data->getLength() <= _nvramSize)) {
					bcopy(bytes, _nvramImage, data->getLength());
					initNVRAMImage();
					_isProxied = true;
				}
			}
		}
		entry->removeProperty(key);
	}
}

UInt32
IODTNVRAM::getNVRAMSize(void)
{
	OSSharedPtr<IORegistryEntry> entry;
	const char                   *key = "nvram-total-size";
	OSData                       *data;
	UInt32                       size = 0;

	entry = IORegistryEntry::fromPath("/chosen", gIODTPlane);
	if (entry != nullptr) {
		OSSharedPtr<OSObject> prop = entry->copyProperty(key);
		if (prop != nullptr) {
			data = OSDynamicCast(OSData, prop.get());
			if (data != nullptr) {
				size = *((UInt32*)data->getBytesNoCopy());
				DEBUG_ALWAYS("NVRAM size is %u bytes\n", (unsigned int) size);
			}
		}
	}
	return size;
}


void
IODTNVRAM::registerNVRAMController(IONVRAMController *nvram)
{
	IOReturn ret;

	if (_nvramController != nullptr) {
		DEBUG_ERROR("Duplicate controller set\n");
		return;
	}

	DEBUG_INFO("setting controller\n");

	CONTROLLERLOCK();
	_nvramController = nvram;
	CONTROLLERUNLOCK();

	// <rdar://problem/9529235> race condition possible between
	// IODTNVRAM and IONVRAMController (restore loses boot-args)
	if (!_isProxied) {
		DEBUG_INFO("Reading non-proxied NVRAM data\n");
		_nvramController->read(0, _nvramImage, _nvramSize);
		initNVRAMImage();
	}

	if (_systemPartitionSize) {
		_systemService = new IODTNVRAMVariables;

		if (!_systemService || !_systemService->init(&gAppleSystemVariableGuid)) {
			DEBUG_ERROR("Unable to start the system service!\n");
			goto no_system;
		}

		_systemService->setName("options-system");

		if (!_systemService->attach(this)) {
			DEBUG_ERROR("Unable to attach the system service!\n");
			OSSafeReleaseNULL(_systemService);
			goto no_system;
		}

		if (!_systemService->start(this)) {
			DEBUG_ERROR("Unable to start the system service!\n");
			_systemService->detach(this);
			OSSafeReleaseNULL(_systemService);
			goto no_system;
		}
	}

no_system:
	if (_commonPartitionSize) {
		_commonService = new IODTNVRAMVariables;

		if (!_commonService || !_commonService->init(&gAppleNVRAMGuid)) {
			DEBUG_ERROR("Unable to start the common service!\n");
			goto no_common;
		}

		_commonService->setName("options-common");

		if (!_commonService->attach(this)) {
			DEBUG_ERROR("Unable to attach the common service!\n");
			OSSafeReleaseNULL(_commonService);
			goto no_common;
		}

		if (!_commonService->start(this)) {
			DEBUG_ERROR("Unable to start the common service!\n");
			_commonService->detach(this);
			OSSafeReleaseNULL(_commonService);
			goto no_common;
		}
	}

no_common:
	ret = serializeVariables();
	DEBUG_INFO("serializeVariables ret=%#08x\n", ret);
}

void
IODTNVRAM::initNVRAMImage(void)
{
	char   partitionID[18];
	UInt32 partitionOffset, partitionLength;
	UInt32 currentLength, currentOffset = 0;

	_commonPartitionOffset = 0xFFFFFFFF;
	_systemPartitionOffset = 0xFFFFFFFF;

	// Look through the partitions to find the OF and System partitions.
	while (currentOffset < _nvramSize) {
		bool common_partition;
		bool system_partition;
		chrp_nvram_header_t * header = (chrp_nvram_header_t *)(_nvramImage + currentOffset);
		const uint8_t common_v1_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_COMMON_V1};
		const uint8_t common_v2_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_COMMON_V2};
		const uint8_t system_v1_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_SYSTEM_V1};
		const uint8_t system_v2_name[sizeof(header->name)] = {NVRAM_CHRP_PARTITION_NAME_SYSTEM_V2};

		currentLength = header->len * NVRAM_CHRP_LENGTH_BLOCK_SIZE;

		if (currentLength < sizeof(chrp_nvram_header_t)) {
			break;
		}

		partitionOffset = currentOffset + sizeof(chrp_nvram_header_t);
		partitionLength = currentLength - sizeof(chrp_nvram_header_t);

		if ((partitionOffset + partitionLength) > _nvramSize) {
			break;
		}

		common_partition = (memcmp(header->name, common_v1_name, sizeof(header->name)) == 0) ||
		    (memcmp(header->name, common_v2_name, sizeof(header->name)) == 0);
		system_partition = (memcmp(header->name, system_v1_name, sizeof(header->name)) == 0) ||
		    (memcmp(header->name, system_v2_name, sizeof(header->name)) == 0);

		if (common_partition) {
			_commonPartitionOffset = partitionOffset;
			_commonPartitionSize = partitionLength;
		} else if (system_partition) {
			_systemPartitionOffset = partitionOffset;
			_systemPartitionSize = partitionLength;
		} else {
			OSSharedPtr<OSNumber> partitionOffsetNumber, partitionLengthNumber;

			// Construct the partition ID from the signature and name.
			snprintf(partitionID, sizeof(partitionID), "%#02x,", header->sig);
			memcpy(partitionID + 5, header->name, sizeof(header->name));
			partitionID[17] = '\0';

			partitionOffsetNumber = OSNumber::withNumber(partitionOffset, 32);
			partitionLengthNumber = OSNumber::withNumber(partitionLength, 32);

			// Save the partition offset and length
			_nvramPartitionOffsets->setObject(partitionID, partitionOffsetNumber.get());
			_nvramPartitionLengths->setObject(partitionID, partitionLengthNumber.get());
		}
		currentOffset += currentLength;
	}

	if (_commonPartitionOffset != 0xFFFFFFFF) {
		_commonImage = _nvramImage + _commonPartitionOffset;
	}

	if (_systemPartitionOffset != 0xFFFFFFFF) {
		_systemImage = _nvramImage + _systemPartitionOffset;
	}

	DEBUG_ALWAYS("NVRAM : commonPartitionOffset - %#x, commonPartitionSize - %#x, systemPartitionOffset - %#x, systemPartitionSize - %#x\n",
	    (unsigned int) _commonPartitionOffset, (unsigned int) _commonPartitionSize, (unsigned int) _systemPartitionOffset, (unsigned int) _systemPartitionSize);

	_lastDeviceSync = 0;
	_freshInterval = TRUE;          // we will allow sync() even before the first 15 minutes have passed.

	initVariables();
}

void
IODTNVRAM::syncInternal(bool rateLimit)
{
	DEBUG_INFO("rateLimit=%d\n", rateLimit);

	// Don't try to perform controller operations if none has been registered.
	if (_nvramController == nullptr) {
		return;
	}

	// Rate limit requests to sync. Drivers that need this rate limiting will
	// shadow the data and only write to flash when they get a sync call
	if (rateLimit && !safeToSync()) {
		return;
	}

	DEBUG_INFO("Calling sync()\n");

	CONTROLLERLOCK();
	_nvramController->sync();
	CONTROLLERUNLOCK();
}

void
IODTNVRAM::sync(void)
{
	syncInternal(false);
}

bool
IODTNVRAM::serializeProperties(OSSerialize *s) const
{
	const OSSymbol                    *key;
	OSSharedPtr<OSDictionary>         systemDict, commonDict, dict;
	OSSharedPtr<OSCollectionIterator> iter;
	bool                              ok = false;
	unsigned int                      totalCapacity = 0;

	NVRAMREADLOCK();
	if (_commonDict) {
		commonDict = OSDictionary::withDictionary(_commonDict.get());
	}

	if (_systemDict) {
		systemDict = OSDictionary::withDictionary(_systemDict.get());
	}
	NVRAMUNLOCK();

	totalCapacity += (commonDict != nullptr) ? commonDict->getCapacity() : 0;
	totalCapacity += (systemDict != nullptr) ? systemDict->getCapacity() : 0;

	dict = OSDictionary::withCapacity(totalCapacity);

	if (dict == nullptr) {
		DEBUG_ERROR("No dictionary\n");
		goto exit;
	}

	// Copy system entries first if present then copy unique common entries
	if (systemDict != nullptr) {
		iter = OSCollectionIterator::withCollection(systemDict.get());
		if (iter == nullptr) {
			DEBUG_ERROR("failed to create iterator\n");
			goto exit;
		}

		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (verifyPermission(kIONVRAMOperationRead, &gAppleSystemVariableGuid, key)) {
				dict->setObject(key, systemDict->getObject(key));
			}
		}

		iter.reset();
	}

	if (commonDict != nullptr) {
		iter = OSCollectionIterator::withCollection(commonDict.get());
		if (iter == nullptr) {
			DEBUG_ERROR("failed to create common iterator\n");
			goto exit;
		}

		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (dict->getObject(key) != nullptr) {
				// Skip non uniques
				continue;
			}
			if (verifyPermission(kIONVRAMOperationRead, &gAppleNVRAMGuid, key)) {
				dict->setObject(key, commonDict->getObject(key));
			}
		}
	}

	ok = dict->serialize(s);

exit:
	DEBUG_INFO("ok=%d\n", ok);

	return ok;
}

IOReturn
IODTNVRAM::chooseDictionary(IONVRAMOperation operation, const uuid_t *varGuid, const char *variableName, OSDictionary **dict) const
{
	if (_systemDict != nullptr) {
		bool systemGuid = uuid_compare(*varGuid, gAppleSystemVariableGuid) == 0;

		if (variableInAllowList(variableName)) {
			DEBUG_INFO("Using system dictionary due to allow list\n");
			if (!systemGuid) {
				DEBUG_ERROR("System GUID NOT used for %s\n", variableName);
			}
			*dict = _systemDict.get();
		} else if (systemGuid) {
			DEBUG_INFO("Using system dictionary via GUID\n");
			*dict = _systemDict.get();
		} else {
			DEBUG_INFO("Using common dictionary\n");
			*dict = _commonDict.get();
		}
		return kIOReturnSuccess;
	} else if (_commonDict != nullptr) {
		DEBUG_INFO("Defaulting to common dictionary\n");
		*dict = _commonDict.get();
		return kIOReturnSuccess;
	}

	return kIOReturnNotFound;
}

IOReturn
IODTNVRAM::flushDict(const uuid_t *guid, IONVRAMOperation op)
{
	IOReturn err = kIOReturnSuccess;

	if ((_systemDict != nullptr) && (uuid_compare(*guid, gAppleSystemVariableGuid) == 0)) {
		const OSSymbol *key;
		OSSharedPtr<OSDictionary> newDict;
		OSSharedPtr<OSCollectionIterator> iter;

		newDict = OSDictionary::withCapacity(_systemDict->getCapacity());
		iter = OSCollectionIterator::withCollection(_systemDict.get());
		if ((newDict == nullptr) || (iter == nullptr)) {
			err = kIOReturnNoMemory;
			goto exit;
		}

		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (!verifyPermission(op, &gAppleSystemVariableGuid, key)) {
				newDict->setObject(key, _systemDict->getObject(key));
			}
		}

		_systemDict = newDict;

		DEBUG_INFO("system dictionary flushed\n");
	} else if ((_commonDict != nullptr) && (uuid_compare(*guid, gAppleNVRAMGuid) == 0)) {
		const OSSymbol *key;
		OSSharedPtr<OSDictionary> newDict;
		OSSharedPtr<OSCollectionIterator> iter;

		newDict = OSDictionary::withCapacity(_commonDict->getCapacity());
		iter = OSCollectionIterator::withCollection(_commonDict.get());
		if ((newDict == nullptr) || (iter == nullptr)) {
			err = kIOReturnNoMemory;
			goto exit;
		}

		while ((key = OSDynamicCast(OSSymbol, iter->getNextObject()))) {
			if (!verifyPermission(op, &gAppleNVRAMGuid, key)) {
				newDict->setObject(key, _commonDict->getObject(key));
			}
		}

		_commonDict = newDict;

		DEBUG_INFO("common dictionary flushed\n");
	}

exit:
	return err;
}

bool
IODTNVRAM::handleSpecialVariables(const char *name, const uuid_t *guid, const OSObject *obj, IOReturn *error)
{
	IOReturn err = kIOReturnSuccess;
	bool special = false;

	NVRAMLOCKASSERTEXCLUSIVE();

	// ResetNVRam flushes both regions in one call
	// Obliterate can flush either separately
	if (strcmp(name, "ObliterateNVRam") == 0) {
		err = flushDict(guid, kIONVRAMOperationObliterate);
	} else if (strcmp(name, "ResetNVRam") == 0) {
		err = flushDict(&gAppleSystemVariableGuid, kIONVRAMOperationReset);

		if (err != kIOReturnSuccess) {
			goto exit;
		}

		err = flushDict(&gAppleNVRAMGuid, kIONVRAMOperationReset);
	}

exit:
	if (error) {
		*error = err;
	}

	return special;
}

OSSharedPtr<OSObject>
IODTNVRAM::copyPropertyWithGUIDAndName(const uuid_t *guid, const char *name) const
{
	IOReturn              result;
	OSDictionary          *dict;
	OSSharedPtr<OSObject> theObject = nullptr;

	result = chooseDictionary(kIONVRAMOperationRead, guid, name, &dict);
	if (result != kIOReturnSuccess) {
		DEBUG_INFO("No dictionary\n");
		goto exit;
	}

	if (!verifyPermission(kIONVRAMOperationRead, guid, name)) {
		DEBUG_INFO("Not privileged\n");
		goto exit;
	}

	NVRAMREADLOCK();
	theObject.reset(dict->getObject(name), OSRetain);
	NVRAMUNLOCK();

	if (theObject != nullptr) {
		DEBUG_INFO("found data\n");
	}

exit:
	return theObject;
}

OSSharedPtr<OSObject>
IODTNVRAM::copyProperty(const OSSymbol *aKey) const
{
	const char            *variableName;
	uuid_t                varGuid;

	if (skipKey(aKey)) {
		return nullptr;
	}
	DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

	parseVariableName(aKey->getCStringNoCopy(), &varGuid, &variableName);

	return copyPropertyWithGUIDAndName(&varGuid, variableName);
}

OSSharedPtr<OSObject>
IODTNVRAM::copyProperty(const char *aKey) const
{
	OSSharedPtr<const OSSymbol> keySymbol;
	OSSharedPtr<OSObject>       theObject;

	keySymbol = OSSymbol::withCString(aKey);
	if (keySymbol != nullptr) {
		theObject = copyProperty(keySymbol.get());
	}

	return theObject;
}

OSObject *
IODTNVRAM::getProperty(const OSSymbol *aKey) const
{
	// The shared pointer gets released at the end of the function,
	// and returns a view into theObject.
	OSSharedPtr<OSObject> theObject = copyProperty(aKey);

	return theObject.get();
}

OSObject *
IODTNVRAM::getProperty(const char *aKey) const
{
	// The shared pointer gets released at the end of the function,
	// and returns a view into theObject.
	OSSharedPtr<OSObject> theObject = copyProperty(aKey);

	return theObject.get();
}

IOReturn
IODTNVRAM::setPropertyWithGUIDAndName(const uuid_t *guid, const char *name, OSObject *anObject)
{
	IOReturn              ret = kIOReturnSuccess;
	bool                  remove = false;
	OSString              *tmpString = nullptr;
	OSSharedPtr<OSObject> propObject, oldObject;
	OSSharedPtr<OSObject> sharedObject(anObject, OSRetain);
	OSDictionary          *dict;
	bool                  deletePropertyKey, syncNowPropertyKey, forceSyncNowPropertyKey;
	bool                  ok;
	size_t                propDataSize = 0;

	deletePropertyKey = strncmp(name, kIONVRAMDeletePropertyKey, sizeof(kIONVRAMDeletePropertyKey)) == 0;
	syncNowPropertyKey = strncmp(name, kIONVRAMSyncNowPropertyKey, sizeof(kIONVRAMSyncNowPropertyKey)) == 0;
	forceSyncNowPropertyKey = strncmp(name, kIONVRAMForceSyncNowPropertyKey, sizeof(kIONVRAMForceSyncNowPropertyKey)) == 0;

	if (deletePropertyKey) {
		tmpString = OSDynamicCast(OSString, anObject);
		if (tmpString != nullptr) {
			const char *variableName;
			uuid_t     varGuid;

			DEBUG_INFO("kIONVRAMDeletePropertyKey found\n");

			parseVariableName(tmpString->getCStringNoCopy(), &varGuid, &variableName);
			removePropertyWithGUIDAndName(&varGuid, variableName);
		} else {
			DEBUG_INFO("kIONVRAMDeletePropertyKey value needs to be an OSString\n");
			ret = kIOReturnError;
		}
		goto exit;
	} else if (syncNowPropertyKey || forceSyncNowPropertyKey) {
		tmpString = OSDynamicCast(OSString, anObject);
		DEBUG_INFO("NVRAM sync key %s found\n", name);
		if (tmpString != nullptr) {
			// We still want to throttle NVRAM commit rate for SyncNow. ForceSyncNow is provided as a really big hammer.
			syncInternal(syncNowPropertyKey);
		} else {
			DEBUG_INFO("%s value needs to be an OSString\n", name);
			ret = kIOReturnError;
		}
		goto exit;
	}

	ret = chooseDictionary(kIONVRAMOperationWrite, guid, name, &dict);
	if (ret != kIOReturnSuccess) {
		DEBUG_INFO("No dictionary\n");
		goto exit;
	}

	if (!verifyPermission(kIONVRAMOperationWrite, guid, name)) {
		DEBUG_INFO("Not privileged\n");
		ret = kIOReturnNotPrivileged;
		goto exit;
	}

	// Make sure the object is of the correct type.
	switch (getVariableType(name)) {
	case kOFVariableTypeBoolean:
		propObject = OSDynamicPtrCast<OSBoolean>(sharedObject);
		break;

	case kOFVariableTypeNumber:
		propObject = OSDynamicPtrCast<OSNumber>(sharedObject);
		break;

	case kOFVariableTypeString:
		propObject = OSDynamicPtrCast<OSString>(sharedObject);
		if (propObject != nullptr) {
			propDataSize = (OSDynamicPtrCast<OSString>(propObject))->getLength();

			if ((strncmp(name, kIONVRAMBootArgsKey, sizeof(kIONVRAMBootArgsKey)) == 0) && (propDataSize >= BOOT_LINE_LENGTH)) {
				DEBUG_ERROR("boot-args size too large for BOOT_LINE_LENGTH, propDataSize=%zu\n", propDataSize);
				ret = kIOReturnNoSpace;
				goto exit;
			}
		}
		break;

	case kOFVariableTypeData:
		propObject = OSDynamicPtrCast<OSData>(sharedObject);
		if (propObject == nullptr) {
			tmpString = OSDynamicCast(OSString, sharedObject.get());
			if (tmpString != nullptr) {
				propObject = OSData::withBytes(tmpString->getCStringNoCopy(),
				    tmpString->getLength());
			}
		}

		if (propObject != nullptr) {
			propDataSize = (OSDynamicPtrCast<OSData>(propObject))->getLength();
		}

#if defined(XNU_TARGET_OS_OSX)
		if ((propObject != nullptr) && ((OSDynamicPtrCast<OSData>(propObject))->getLength() == 0)) {
			remove = true;
		}
#endif /* defined(XNU_TARGET_OS_OSX) */
		break;
	default:
		break;
	}

	if (propObject == nullptr) {
		DEBUG_INFO("No property object\n");
		ret = kIOReturnBadArgument;
		goto exit;
	}

	if (!verifyWriteSizeLimit(guid, name, propDataSize)) {
		DEBUG_ERROR("Property data size of %zu too long for %s\n", propDataSize, name);
		ret = kIOReturnNoSpace;
		goto exit;
	}

	NVRAMWRITELOCK();
	ok = handleSpecialVariables(name, guid, propObject.get(), &ret);
	NVRAMUNLOCK();

	if (ok) {
		serializeVariables();
		goto exit;
	}

	NVRAMREADLOCK();
	oldObject.reset(dict->getObject(name), OSRetain);
	NVRAMUNLOCK();

	if (remove == false) {
		DEBUG_INFO("Adding object\n");
		NVRAMWRITELOCK();
		if (!dict->setObject(name, propObject.get())) {
			ret = kIOReturnBadArgument;
		}
		NVRAMUNLOCK();
	} else {
		DEBUG_INFO("Removing object\n");
		// Check for existence so we can decide whether we need to sync variables
		if (oldObject) {
			ret = removePropertyWithGUIDAndName(guid, name);
		} else {
			ret = kIOReturnNotFound;
		}
	}

	if (ret == kIOReturnSuccess) {
		ret = serializeVariables();
		if (ret != kIOReturnSuccess) {
			DEBUG_ERROR("serializeVariables failed, ret=%#08x\n", ret);

			NVRAMWRITELOCK();
			if (oldObject) {
				dict->setObject(name, oldObject.get());
			} else {
				dict->removeObject(name);
			}
			NVRAMUNLOCK();

			(void) serializeVariables();
			ret = kIOReturnNoMemory;
		}
	}

	if (oldObject) {
		oldObject.reset();
	}
	if (tmpString) {
		propObject.reset();
	}

exit:
	DEBUG_INFO("ret=%#08x\n", ret);

	return ret;
}

IOReturn
IODTNVRAM::setPropertyInternal(const OSSymbol *aKey, OSObject *anObject)
{
	const char            *variableName;
	uuid_t                varGuid;

	DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

	parseVariableName(aKey->getCStringNoCopy(), &varGuid, &variableName);

	return setPropertyWithGUIDAndName(&varGuid, variableName, anObject);
}

bool
IODTNVRAM::setProperty(const OSSymbol *aKey, OSObject *anObject)
{
	return setPropertyInternal(aKey, anObject) == kIOReturnSuccess;
}

void
IODTNVRAM::removeProperty(const OSSymbol *aKey)
{
	IOReturn ret;

	ret = removePropertyInternal(aKey);

	if (ret == kIOReturnSuccess) {
		serializeVariables();
	} else {
		DEBUG_INFO("removePropertyInternal failed, ret=%#08x\n", ret);
	}
}

IOReturn
IODTNVRAM::removePropertyWithGUIDAndName(const uuid_t *guid, const char *name)
{
	IOReturn     ret;
	OSDictionary *dict;
	bool removed = false;

	DEBUG_INFO("name=%s\n", name);

	ret = chooseDictionary(kIONVRAMOperationDelete, guid, name, &dict);
	if (ret != kIOReturnSuccess) {
		DEBUG_INFO("No dictionary\n");
		goto exit;
	}

	if (!verifyPermission(kIONVRAMOperationDelete, guid, name)) {
		DEBUG_INFO("Not priveleged\n");
		ret = kIOReturnNotPrivileged;
		goto exit;
	}

	NVRAMWRITELOCK();

	// If the object exists, remove it from the dictionary.
	if (dict->getObject(name) != nullptr) {
		dict->removeObject(name);
		removed = true;
	} else {
		DEBUG_INFO("%s not found\n", name);
	}

	NVRAMUNLOCK();

	if (removed) {
		ret = serializeVariables();
		DEBUG_INFO("serializeVariables ret=0x%08x\n", ret);
	}

exit:
	return ret;
}

IOReturn
IODTNVRAM::removePropertyInternal(const OSSymbol *aKey)
{
	IOReturn     ret;
	const char   *variableName;
	uuid_t       varGuid;

	DEBUG_INFO("aKey=%s\n", aKey->getCStringNoCopy());

	parseVariableName(aKey->getCStringNoCopy(), &varGuid, &variableName);

	ret = removePropertyWithGUIDAndName(&varGuid, variableName);

	return ret;
}

IOReturn
IODTNVRAM::setProperties(OSObject *properties)
{
	IOReturn                          ret = kIOReturnSuccess;
	OSObject                          *object;
	const OSSymbol                    *key;
	OSDictionary                      *dict;
	OSSharedPtr<OSCollectionIterator> iter;

	dict = OSDynamicCast(OSDictionary, properties);
	if (dict == nullptr) {
		DEBUG_ERROR("Not a dictionary\n");
		return kIOReturnBadArgument;
	}

	iter = OSCollectionIterator::withCollection(dict);
	if (iter == nullptr) {
		DEBUG_ERROR("Couldn't create iterator\n");
		return kIOReturnBadArgument;
	}

	while (ret == kIOReturnSuccess) {
		key = OSDynamicCast(OSSymbol, iter->getNextObject());
		if (key == nullptr) {
			break;
		}

		object = dict->getObject(key);
		if (object == nullptr) {
			continue;
		}

		ret = setPropertyInternal(key, object);
	}

	DEBUG_INFO("ret=%#08x\n", ret);

	return ret;
}

IOReturn
IODTNVRAM::readXPRAM(IOByteCount offset, UInt8 *buffer,
    IOByteCount length)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::writeXPRAM(IOByteCount offset, UInt8 *buffer,
    IOByteCount length)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::readNVRAMProperty(IORegistryEntry *entry,
    const OSSymbol **name,
    OSData **value)
{
	IOReturn err;

	err = readNVRAMPropertyType1(entry, name, value);

	return err;
}

IOReturn
IODTNVRAM::writeNVRAMProperty(IORegistryEntry *entry,
    const OSSymbol *name,
    OSData *value)
{
	IOReturn err;

	err = writeNVRAMPropertyType1(entry, name, value);

	return err;
}

OSDictionary *
IODTNVRAM::getNVRAMPartitions(void)
{
	return _nvramPartitionLengths.get();
}

IOReturn
IODTNVRAM::readNVRAMPartition(const OSSymbol *partitionID,
    IOByteCount offset, UInt8 *buffer,
    IOByteCount length)
{
	OSNumber *partitionOffsetNumber, *partitionLengthNumber;
	UInt32   partitionOffset, partitionLength, end;

	partitionOffsetNumber =
	    (OSNumber *)_nvramPartitionOffsets->getObject(partitionID);
	partitionLengthNumber =
	    (OSNumber *)_nvramPartitionLengths->getObject(partitionID);

	if ((partitionOffsetNumber == nullptr) || (partitionLengthNumber == nullptr)) {
		return kIOReturnNotFound;
	}

	partitionOffset = partitionOffsetNumber->unsigned32BitValue();
	partitionLength = partitionLengthNumber->unsigned32BitValue();

	if (os_add_overflow(offset, length, &end)) {
		return kIOReturnBadArgument;
	}
	if ((buffer == nullptr) || (length == 0) || (end > partitionLength)) {
		return kIOReturnBadArgument;
	}

	bcopy(_nvramImage + partitionOffset + offset, buffer, length);

	return kIOReturnSuccess;
}

IOReturn
IODTNVRAM::writeNVRAMPartition(const OSSymbol *partitionID,
    IOByteCount offset, UInt8 *buffer,
    IOByteCount length)
{
	OSNumber *partitionOffsetNumber, *partitionLengthNumber;
	UInt32   partitionOffset, partitionLength, end;

	partitionOffsetNumber =
	    (OSNumber *)_nvramPartitionOffsets->getObject(partitionID);
	partitionLengthNumber =
	    (OSNumber *)_nvramPartitionLengths->getObject(partitionID);

	if ((partitionOffsetNumber == nullptr) || (partitionLengthNumber == nullptr)) {
		return kIOReturnNotFound;
	}

	partitionOffset = partitionOffsetNumber->unsigned32BitValue();
	partitionLength = partitionLengthNumber->unsigned32BitValue();

	if (os_add_overflow(offset, length, &end)) {
		return kIOReturnBadArgument;
	}
	if ((buffer == nullptr) || (length == 0) || (end > partitionLength)) {
		return kIOReturnBadArgument;
	}

	bcopy(buffer, _nvramImage + partitionOffset + offset, length);

	if (_nvramController != nullptr) {
		_nvramController->write(0, _nvramImage, _nvramSize);
	}

	return kIOReturnSuccess;
}

IOByteCount
IODTNVRAM::savePanicInfo(UInt8 *buffer, IOByteCount length)
{
	return 0;
}

// Private methods

UInt8
IODTNVRAM::calculatePartitionChecksum(UInt8 *partitionHeader)
{
	UInt8 cnt, isum, csum = 0;

	for (cnt = 0; cnt < 0x10; cnt++) {
		isum = csum + partitionHeader[cnt];
		if (isum < csum) {
			isum++;
		}
		csum = isum;
	}

	return csum;
}

IOReturn
IODTNVRAM::initVariables(void)
{
	UInt32                      cnt;
	UInt8                       *propName, *propData;
	UInt32                      propNameLength, propDataLength, regionIndex;
	OSSharedPtr<const OSSymbol> propSymbol;
	OSSharedPtr<OSObject>       propObject;
	NVRAMRegionInfo             *currentRegion;
	NVRAMRegionInfo             variableRegions[] = { { kIONVRAMPartitionCommon, _commonPartitionOffset, _commonPartitionSize, _commonDict, _commonImage},
							  { kIONVRAMPartitionSystem, _systemPartitionOffset, _systemPartitionSize, _systemDict, _systemImage} };

	DEBUG_INFO("...\n");

	for (regionIndex = 0; regionIndex < ARRAY_SIZE(variableRegions); regionIndex++) {
		currentRegion = &variableRegions[regionIndex];

		if (currentRegion->size == 0) {
			continue;
		}

		currentRegion->dict = OSDictionary::withCapacity(1);

		DEBUG_INFO("region = %d\n", currentRegion->type);
		cnt = 0;
		while (cnt < currentRegion->size) {
			// Break if there is no name.
			if (currentRegion->image[cnt] == '\0') {
				break;
			}

			// Find the length of the name.
			propName = currentRegion->image + cnt;
			for (propNameLength = 0; (cnt + propNameLength) < currentRegion->size;
			    propNameLength++) {
				if (currentRegion->image[cnt + propNameLength] == '=') {
					break;
				}
			}

			// Break if the name goes past the end of the partition.
			if ((cnt + propNameLength) >= currentRegion->size) {
				break;
			}
			cnt += propNameLength + 1;

			propData = currentRegion->image + cnt;
			for (propDataLength = 0; (cnt + propDataLength) < currentRegion->size;
			    propDataLength++) {
				if (currentRegion->image[cnt + propDataLength] == '\0') {
					break;
				}
			}

			// Break if the data goes past the end of the partition.
			if ((cnt + propDataLength) >= currentRegion->size) {
				break;
			}
			cnt += propDataLength + 1;

			if (convertPropToObject(propName, propNameLength,
			    propData, propDataLength,
			    propSymbol, propObject)) {
				DEBUG_INFO("adding %s, dataLength=%u\n", propSymbol.get()->getCStringNoCopy(), (unsigned int)propDataLength);
				currentRegion->dict.get()->setObject(propSymbol.get(), propObject.get());
			}
		}
	}

	// Create the boot-args property if it is not in the dictionary.
	if (_systemDict != nullptr) {
		if (_systemDict->getObject(kIONVRAMBootArgsKey) == nullptr) {
			propObject = OSString::withCStringNoCopy("");
			if (propObject != nullptr) {
				_systemDict->setObject(kIONVRAMBootArgsKey, propObject.get());
			}
		}
	} else if (_commonDict != nullptr) {
		if (_commonDict->getObject(kIONVRAMBootArgsKey) == nullptr) {
			propObject = OSString::withCStringNoCopy("");
			if (propObject != nullptr) {
				_commonDict->setObject(kIONVRAMBootArgsKey, propObject.get());
			}
		}
	}

	DEBUG_INFO("%s _commonDict=%p _systemDict=%p\n", __FUNCTION__, _commonDict ? _commonDict.get() : nullptr, _systemDict ? _systemDict.get() : nullptr);

	return kIOReturnSuccess;
}

IOReturn
IODTNVRAM::syncOFVariables(void)
{
	return kIOReturnUnsupported;
}

IOReturn
IODTNVRAM::serializeVariables(void)
{
	IOReturn                          ret;
	bool                              ok;
	UInt32                            length, maxLength, regionIndex;
	UInt8                             *buffer, *tmpBuffer;
	const OSSymbol                    *tmpSymbol;
	OSObject                          *tmpObject;
	OSSharedPtr<OSCollectionIterator> iter;
	OSSharedPtr<OSNumber>             sizeUsed;
	UInt32                            systemUsed = 0;
	UInt32                            commonUsed = 0;
	OSSharedPtr<OSData>               nvramImage;
	NVRAMRegionInfo                   *currentRegion;
	NVRAMRegionInfo                   variableRegions[] = { { kIONVRAMPartitionCommon, _commonPartitionOffset, _commonPartitionSize, _commonDict, _commonImage},
								{ kIONVRAMPartitionSystem, _systemPartitionOffset, _systemPartitionSize, _systemDict, _systemImage} };

	if (_systemPanicked) {
		return kIOReturnNotReady;
	}

	if (_nvramController == nullptr) {
		DEBUG_ERROR("No _nvramController\n");
		return kIOReturnNotReady;
	}

	DEBUG_INFO("...\n");

	NVRAMREADLOCK();

	for (regionIndex = 0; regionIndex < ARRAY_SIZE(variableRegions); regionIndex++) {
		currentRegion = &variableRegions[regionIndex];

		if (currentRegion->size == 0) {
			continue;
		}

		DEBUG_INFO("region = %d\n", currentRegion->type);
		buffer = tmpBuffer = IONew(UInt8, currentRegion->size);
		if (buffer == nullptr) {
			ok = false;
			ret = kIOReturnNoMemory;
			break;
		}
		bzero(buffer, currentRegion->size);

		ok = true;
		maxLength = currentRegion->size;

		iter = OSCollectionIterator::withCollection(currentRegion->dict.get());
		if (iter == nullptr) {
			ok = false;
		}

		while (ok) {
			tmpSymbol = OSDynamicCast(OSSymbol, iter->getNextObject());
			if (tmpSymbol == nullptr) {
				break;
			}

			DEBUG_INFO("adding variable %s\n", tmpSymbol->getCStringNoCopy());

			tmpObject = currentRegion->dict->getObject(tmpSymbol);

			length = maxLength;
			ok = convertObjectToProp(tmpBuffer, &length, tmpSymbol, tmpObject);
			if (ok) {
				tmpBuffer += length;
				maxLength -= length;
			}
		}

		if (ok) {
			bcopy(buffer, currentRegion->image, currentRegion->size);
		}

		if ((currentRegion->type == kIONVRAMPartitionSystem) &&
		    (_systemService != nullptr)) {
			_systemService->setVariables(_systemDict.get());
			systemUsed = (uint32_t)(tmpBuffer - buffer);
		} else if ((currentRegion->type == kIONVRAMPartitionCommon) &&
		    (_commonService != nullptr)) {
			_commonService->setVariables(_commonDict.get());
			commonUsed = (uint32_t)(tmpBuffer - buffer);
		}

		IODelete(buffer, UInt8, currentRegion->size);

		if (!ok) {
			ret = kIOReturnBadArgument;
			break;
		}
	}

	NVRAMUNLOCK();

	DEBUG_INFO("ok=%d\n", ok);

	if (ok) {
		nvramImage = OSData::withBytes(_nvramImage, _nvramSize);
		CONTROLLERLOCK();

		if (_systemService) {
			sizeUsed = OSNumber::withNumber(systemUsed, 32);
			_nvramController->setProperty("SystemUsed", sizeUsed.get());
			DEBUG_INFO("SystemUsed=%u\n", (unsigned int)commonUsed);
			sizeUsed.reset();
		}

		if (_commonService) {
			sizeUsed = OSNumber::withNumber(commonUsed, 32);
			_nvramController->setProperty("CommonUsed", sizeUsed.get());
			DEBUG_INFO("CommonUsed=%u\n", (unsigned int)commonUsed);
			sizeUsed.reset();
		}

		ret = _nvramController->write(0, (uint8_t *)nvramImage->getBytesNoCopy(), nvramImage->getLength());

		CONTROLLERUNLOCK();
	}

	return ret;
}

UInt32
IODTNVRAM::getOFVariableType(const char *propName) const
{
	return 0;
}

UInt32
IODTNVRAM::getOFVariableType(const OSSymbol *propSymbol) const
{
	return 0;
}


UInt32
IODTNVRAM::getOFVariablePerm(const char *propName) const
{
	return 0;
}

UInt32
IODTNVRAM::getOFVariablePerm(const OSSymbol *propSymbol) const
{
	return 0;
}

bool
IODTNVRAM::getOWVariableInfo(UInt32 variableNumber, const OSSymbol **propSymbol,
    UInt32 *propType, UInt32 *propOffset)
{
	/* UNSUPPORTED */
	return false;
}
bool
IODTNVRAM::convertPropToObject(UInt8 *propName, UInt32 propNameLength,
    UInt8 *propData, UInt32 propDataLength,
    const OSSymbol **propSymbol,
    OSObject **propObject)
{
	OSSharedPtr<const OSSymbol> tmpSymbol;
	OSSharedPtr<OSNumber>       tmpNumber;
	OSSharedPtr<OSString>       tmpString;
	OSSharedPtr<OSObject>       tmpObject = nullptr;

	propName[propNameLength] = '\0';
	tmpSymbol = OSSymbol::withCString((const char *)propName);
	propName[propNameLength] = '=';
	if (tmpSymbol == nullptr) {
		return false;
	}

	switch (getVariableType(tmpSymbol.get())) {
	case kOFVariableTypeBoolean:
		if (!strncmp("true", (const char *)propData, propDataLength)) {
			tmpObject.reset(kOSBooleanTrue, OSRetain);
		} else if (!strncmp("false", (const char *)propData, propDataLength)) {
			tmpObject.reset(kOSBooleanFalse, OSRetain);
		}
		break;

	case kOFVariableTypeNumber:
		tmpNumber = OSNumber::withNumber(strtol((const char *)propData, nullptr, 0), 32);
		if (tmpNumber != nullptr) {
			tmpObject = tmpNumber;
		}
		break;

	case kOFVariableTypeString:
		tmpString = OSString::withCString((const char *)propData);
		if (tmpString != nullptr) {
			tmpObject = tmpString;
		}
		break;

	case kOFVariableTypeData:
		tmpObject = unescapeBytesToData(propData, propDataLength);
		break;

	default:
		break;
	}

	if (tmpObject == nullptr) {
		tmpSymbol.reset();
		return false;
	}

	*propSymbol = tmpSymbol.detach();
	*propObject = tmpObject.detach();

	return true;
}

bool
IODTNVRAM::convertPropToObject(UInt8 *propName, UInt32 propNameLength,
    UInt8 *propData, UInt32 propDataLength,
    OSSharedPtr<const OSSymbol>& propSymbol,
    OSSharedPtr<OSObject>& propObject)
{
	const OSSymbol* propSymbolRaw = nullptr;
	OSObject* propObjectRaw = nullptr;
	bool ok = convertPropToObject(propName, propNameLength, propData, propDataLength,
	    &propSymbolRaw, &propObjectRaw);
	propSymbol.reset(propSymbolRaw, OSNoRetain);
	propObject.reset(propObjectRaw, OSNoRetain);
	return ok;
}

bool
IODTNVRAM::convertObjectToProp(UInt8 *buffer, UInt32 *length,
    const OSSymbol *propSymbol, OSObject *propObject)
{
	const UInt8          *propName;
	UInt32               propNameLength, propDataLength, remaining;
	IONVRAMVariableType  propType;
	OSBoolean            *tmpBoolean = nullptr;
	OSNumber             *tmpNumber = nullptr;
	OSString             *tmpString = nullptr;
	OSSharedPtr<OSData>  tmpData;

	propName = (const UInt8 *)propSymbol->getCStringNoCopy();
	propNameLength = propSymbol->getLength();
	propType = getVariableType(propSymbol);

	// Get the size of the data.
	propDataLength = 0xFFFFFFFF;
	switch (propType) {
	case kOFVariableTypeBoolean:
		tmpBoolean = OSDynamicCast(OSBoolean, propObject);
		if (tmpBoolean != nullptr) {
			propDataLength = 5;
		}
		break;

	case kOFVariableTypeNumber:
		tmpNumber = OSDynamicCast(OSNumber, propObject);
		if (tmpNumber != nullptr) {
			propDataLength = 10;
		}
		break;

	case kOFVariableTypeString:
		tmpString = OSDynamicCast(OSString, propObject);
		if (tmpString != nullptr) {
			propDataLength = tmpString->getLength();
		}
		break;

	case kOFVariableTypeData:
		tmpData.reset(OSDynamicCast(OSData, propObject), OSNoRetain);
		if (tmpData != nullptr) {
			tmpData = escapeDataToData(tmpData.detach());
			propDataLength = tmpData->getLength();
		}
		break;

	default:
		break;
	}

	// Make sure the propertySize is known and will fit.
	if (propDataLength == 0xFFFFFFFF) {
		return false;
	}
	if ((propNameLength + propDataLength + 2) > *length) {
		return false;
	}

	// Copy the property name equal sign.
	buffer += snprintf((char *)buffer, *length, "%s=", propName);
	remaining = *length - propNameLength - 1;

	switch (propType) {
	case kOFVariableTypeBoolean:
		if (tmpBoolean->getValue()) {
			strlcpy((char *)buffer, "true", remaining);
		} else {
			strlcpy((char *)buffer, "false", remaining);
		}
		break;

	case kOFVariableTypeNumber:
	{
		uint32_t tmpValue = tmpNumber->unsigned32BitValue();
		if (tmpValue == 0xFFFFFFFF) {
			strlcpy((char *)buffer, "-1", remaining);
		} else if (tmpValue < 1000) {
			snprintf((char *)buffer, remaining, "%d", (uint32_t)tmpValue);
		} else {
			snprintf((char *)buffer, remaining, "%#x", (uint32_t)tmpValue);
		}
	}
	break;

	case kOFVariableTypeString:
		strlcpy((char *)buffer, tmpString->getCStringNoCopy(), remaining);
		break;

	case kOFVariableTypeData:
		bcopy(tmpData->getBytesNoCopy(), buffer, propDataLength);
		tmpData.reset();
		break;

	default:
		break;
	}

	propDataLength = ((UInt32) strlen((const char *)buffer));

	*length = propNameLength + propDataLength + 2;

	return true;
}


UInt16
IODTNVRAM::generateOWChecksum(UInt8 *buffer)
{
	UInt32 cnt, checksum = 0;
	UInt16 *tmpBuffer = (UInt16 *)buffer;

	for (cnt = 0; cnt < _commonPartitionSize / 2; cnt++) {
		checksum += tmpBuffer[cnt];
	}

	return checksum % 0x0000FFFF;
}

bool
IODTNVRAM::validateOWChecksum(UInt8 *buffer)
{
	UInt32 cnt, checksum, sum = 0;
	UInt16 *tmpBuffer = (UInt16 *)buffer;

	for (cnt = 0; cnt < _commonPartitionSize / 2; cnt++) {
		sum += tmpBuffer[cnt];
	}

	checksum = (sum >> 16) + (sum & 0x0000FFFF);
	if (checksum == 0x10000) {
		checksum--;
	}
	checksum = (checksum ^ 0x0000FFFF) & 0x0000FFFF;

	return checksum == 0;
}

void
IODTNVRAM::updateOWBootArgs(const OSSymbol *key, OSObject *value)
{
	/* UNSUPPORTED */
}

bool
IODTNVRAM::searchNVRAMProperty(IONVRAMDescriptor *hdr, UInt32 *where)
{
	return false;
}

IOReturn
IODTNVRAM::readNVRAMPropertyType0(IORegistryEntry *entry,
    const OSSymbol **name,
    OSData **value)
{
	return kIOReturnUnsupported;
}


IOReturn
IODTNVRAM::writeNVRAMPropertyType0(IORegistryEntry *entry,
    const OSSymbol *name,
    OSData *value)
{
	return kIOReturnUnsupported;
}


OSSharedPtr<OSData>
IODTNVRAM::unescapeBytesToData(const UInt8 *bytes, UInt32 length)
{
	OSSharedPtr<OSData> data;
	UInt32              totalLength = 0;
	UInt32              cnt, cnt2;
	UInt8               byte;
	bool                ok;

	// Calculate the actual length of the data.
	ok = true;
	totalLength = 0;
	for (cnt = 0; cnt < length;) {
		byte = bytes[cnt++];
		if (byte == 0xFF) {
			byte = bytes[cnt++];
			if (byte == 0x00) {
				ok = false;
				break;
			}
			cnt2 = byte & 0x7F;
		} else {
			cnt2 = 1;
		}
		totalLength += cnt2;
	}

	if (ok) {
		// Create an empty OSData of the correct size.
		data = OSData::withCapacity(totalLength);
		if (data != nullptr) {
			for (cnt = 0; cnt < length;) {
				byte = bytes[cnt++];
				if (byte == 0xFF) {
					byte = bytes[cnt++];
					cnt2 = byte & 0x7F;
					byte = (byte & 0x80) ? 0xFF : 0x00;
				} else {
					cnt2 = 1;
				}
				data->appendByte(byte, cnt2);
			}
		}
	}

	return data;
}

OSSharedPtr<OSData>
IODTNVRAM::escapeDataToData(OSData * value)
{
	OSSharedPtr<OSData> result;
	const UInt8         *startPtr;
	const UInt8         *endPtr;
	const UInt8         *wherePtr;
	UInt8               byte;
	bool                ok = true;

	wherePtr = (const UInt8 *) value->getBytesNoCopy();
	endPtr = wherePtr + value->getLength();

	result = OSData::withCapacity((unsigned int) (endPtr - wherePtr));
	if (!result) {
		return result;
	}

	while (wherePtr < endPtr) {
		startPtr = wherePtr;
		byte = *wherePtr++;
		if ((byte == 0x00) || (byte == 0xFF)) {
			for (;
			    ((wherePtr - startPtr) < 0x80) && (wherePtr < endPtr) && (byte == *wherePtr);
			    wherePtr++) {
			}
			ok &= result->appendByte(0xff, 1);
			byte = (byte & 0x80) | ((UInt8)(wherePtr - startPtr));
		}
		ok &= result->appendByte(byte, 1);
	}
	ok &= result->appendByte(0, 1);

	if (!ok) {
		result.reset();
	}

	return result;
}

static bool
IsApplePropertyName(const char * propName)
{
	char c;
	while ((c = *propName++)) {
		if ((c >= 'A') && (c <= 'Z')) {
			break;
		}
	}

	return c == 0;
}

IOReturn
IODTNVRAM::readNVRAMPropertyType1(IORegistryEntry *entry,
    const OSSymbol **name,
    OSData **value)
{
	IOReturn    err = kIOReturnNoResources;
	OSData      *data;
	const UInt8 *startPtr;
	const UInt8 *endPtr;
	const UInt8 *wherePtr;
	const UInt8 *nvPath = nullptr;
	const char  *nvName = nullptr;
	const char  *resultName = nullptr;
	const UInt8 *resultValue = nullptr;
	UInt32       resultValueLen = 0;
	UInt8       byte;

	NVRAMREADLOCK();
	data = OSDynamicCast(OSData, _commonDict->getObject(_registryPropertiesKey.get()));
	NVRAMUNLOCK();

	if (data == nullptr) {
		return err;
	}

	startPtr = (const UInt8 *) data->getBytesNoCopy();
	endPtr = startPtr + data->getLength();

	wherePtr = startPtr;
	while (wherePtr < endPtr) {
		byte = *(wherePtr++);
		if (byte) {
			continue;
		}

		if (nvPath == nullptr) {
			nvPath = startPtr;
		} else if (nvName == nullptr) {
			nvName = (const char *) startPtr;
		} else {
			OSSharedPtr<IORegistryEntry> compareEntry = IORegistryEntry::fromPath((const char *) nvPath, gIODTPlane);
			if (entry == compareEntry) {
				bool appleProp = IsApplePropertyName(nvName);
				if (!appleProp || !resultName) {
					resultName     = nvName;
					resultValue    = startPtr;
					resultValueLen = (UInt32) (wherePtr - startPtr - 1);  // OSData getLength() is 32b
				}
				if (!appleProp) {
					break;
				}
			}
			nvPath = nullptr;
			nvName = nullptr;
		}
		startPtr = wherePtr;
	}
	if (resultName) {
		*name = OSSymbol::withCString(resultName).detach();
		*value = unescapeBytesToData(resultValue, resultValueLen).detach();
		if ((*name != nullptr) && (*value != nullptr)) {
			err = kIOReturnSuccess;
		} else {
			err = kIOReturnNoMemory;
		}
	}
	return err;
}

IOReturn
IODTNVRAM::writeNVRAMPropertyType1(IORegistryEntry *entry,
    const OSSymbol *propName,
    OSData *value)
{
	OSSharedPtr<OSData> data, oldData;
	const UInt8         *startPtr;
	const UInt8         *propStart;
	const UInt8         *endPtr;
	const UInt8         *wherePtr;
	const UInt8         *nvPath = nullptr;
	const char          *nvName = nullptr;
	const char          *comp;
	const char          *name;
	UInt8               byte;
	bool                ok = true;
	bool                settingAppleProp;

	settingAppleProp = IsApplePropertyName(propName->getCStringNoCopy());

	// copy over existing properties for other entries

	NVRAMWRITELOCK();

	oldData.reset(OSDynamicCast(OSData, _commonDict->getObject(_registryPropertiesKey.get())), OSRetain);
	if (oldData) {
		startPtr = (const UInt8 *) oldData->getBytesNoCopy();
		endPtr = startPtr + oldData->getLength();

		propStart = startPtr;
		wherePtr = startPtr;
		while (wherePtr < endPtr) {
			byte = *(wherePtr++);
			if (byte) {
				continue;
			}
			if (nvPath == nullptr) {
				nvPath = startPtr;
			} else if (nvName == nullptr) {
				nvName = (const char *) startPtr;
			} else {
				OSSharedPtr<IORegistryEntry> compareEntry = IORegistryEntry::fromPath((const char *) nvPath, gIODTPlane);

				if (entry == compareEntry) {
					if ((settingAppleProp && propName->isEqualTo(nvName))
					    || (!settingAppleProp && !IsApplePropertyName(nvName))) {
						// delete old property (nvPath -> wherePtr) source OSData len is 32b
						data = OSData::withBytes(propStart, (UInt32)(nvPath - propStart));
						if (data) {
							ok &= data->appendBytes(wherePtr, (UInt32)(endPtr - wherePtr));
						}
						break;
					}
				}
				nvPath = nullptr;
				nvName = nullptr;
			}

			startPtr = wherePtr;
		}
	}

	// make the new property

	if (!data) {
		if (oldData) {
			data = OSData::withData(oldData.get());
		} else {
			data = OSData::withCapacity(16);
		}
		if (!data) {
			ok = false;
		}
	}

	if (ok && value && value->getLength()) {
		do {
			// get entries in path
			OSSharedPtr<OSArray> array = OSArray::withCapacity(5);
			if (!array) {
				ok = false;
				break;
			}
			do{
				array->setObject(entry);
			} while ((entry = entry->getParentEntry(gIODTPlane)));

			// append path
			for (int i = array->getCount() - 3;
			    (entry = (IORegistryEntry *) array->getObject(i));
			    i--) {
				name = entry->getName(gIODTPlane);
				comp = entry->getLocation(gIODTPlane);
				if (comp) {
					ok &= data->appendBytes("/@", 2);
				} else {
					if (!name) {
						continue;
					}
					ok &= data->appendByte('/', 1);
					comp = name;
				}
				ok &= data->appendBytes(comp, (unsigned int) strnlen(comp, UINT16_MAX));
			}
			ok &= data->appendByte(0, 1);
			// append prop name
			ok &= data->appendBytes(propName->getCStringNoCopy(), propName->getLength() + 1);

			// append escaped data
			OSSharedPtr<OSData> escapedData = escapeDataToData(value);
			ok &= (escapedData != nullptr);
			if (ok) {
				ok &= data->appendBytes(escapedData.get());
			}
		} while (false);
	}

	if (ok) {
		ok = _commonDict->setObject(_registryPropertiesKey.get(), data.get());
	}

	NVRAMUNLOCK();

	if (ok) {
		if (serializeVariables() != kIOReturnSuccess) {
			NVRAMWRITELOCK();
			if (oldData) {
				_commonDict->setObject(_registryPropertiesKey.get(), oldData.get());
			} else {
				_commonDict->removeObject(_registryPropertiesKey.get());
			}
			NVRAMUNLOCK();

			(void) serializeVariables();
			ok = false;
		}
	}

	oldData.reset();

	return ok ? kIOReturnSuccess : kIOReturnNoMemory;
}

bool
IODTNVRAM::safeToSync(void)
{
	AbsoluteTime delta;
	UInt64       delta_ns;
	SInt32       delta_secs;

	// delta interval went by
	clock_get_uptime(&delta);

	// Figure it in seconds.
	absolutetime_to_nanoseconds(delta, &delta_ns);
	delta_secs = (SInt32)(delta_ns / NSEC_PER_SEC);

	if ((delta_secs > (_lastDeviceSync + MIN_SYNC_NOW_INTERVAL)) || _freshInterval) {
		_lastDeviceSync = delta_secs;
		_freshInterval = FALSE;
		return TRUE;
	}

	return FALSE;
}
