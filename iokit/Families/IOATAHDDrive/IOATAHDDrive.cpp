/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IOATAHDDrive.cpp - Generic ATA disk driver.
 *
 * HISTORY
 * Aug 27, 1999	jliu - Ported from AppleATADrive.
 */

#include <IOKit/assert.h>
#include <IOKit/storage/ata/IOATAHDDrive.h>
#include <IOKit/storage/ata/IOATAHDDriveNub.h>

#define	super IOService
OSDefineMetaClassAndStructors( IOATAHDDrive, IOService )

//---------------------------------------------------------------------------
// C to C++ glue.

void
IOATAHDDrive::sHandleConfigureDevice(IOATAHDDrive * self)
{
	self->configureDevice(self->_ataDevice);
}

//---------------------------------------------------------------------------
// init() method.

bool
IOATAHDDrive::init(OSDictionary * properties)
{
    return (super::init(properties));
}

//---------------------------------------------------------------------------
// Override probe() method inherited from IOService.

IOService * 
IOATAHDDrive::probe(IOService * provider, SInt32 * score)
{
    if (!super::probe(provider, score))
        return 0;

	// Our provider must be a IOATADevice nub, most likely created
	// by an IOATAController instance.
	//
	IOATADevice * device = OSDynamicCast(IOATADevice, provider);
	if (device == 0)
		return 0;	// Provider is not an IOATADevice.

	// Do ATA device type matching. Does the nub match my device type?
	//
	if (device->getDeviceType() != reportATADeviceType())
		return 0;	// error, type mismatch (probably ATAPI).

	// Cache the drive unit number (master/slave assignment).
	//
	_unit = device->getUnit();

	return this;	// probe successful.
}

//---------------------------------------------------------------------------
// Starts up the driver and spawn a nub.

bool
IOATAHDDrive::start(IOService * provider)
{    
	// First call start() in our superclass.
	//
	if (super::start(provider) == false)
		return false;

	_configThreadCall = (void *) thread_call_allocate(
	                             (thread_call_func_t)  sHandleConfigureDevice,
                                 (thread_call_param_t) this);
	if (!_configThreadCall)
		return false;
												 
	// Cache our provider.
	//
	_ataDevice = OSDynamicCast(IOATADevice, provider);
	if (_ataDevice == 0)
		return false;

	// Open our provider.
	//
    _ataDevice->retain();
	if (_ataDevice->open(this) == false)
        return false;

	// Inspect the provider.
	//
	if (inspectDevice(_ataDevice) == false)
        return false;

	// Select ATA timing.
	//
    _logSelectedTimingProtocol = true;

	if (selectTimingProtocol() == false)
		return false;

    // Create an IOCommandGate (for power management support) and attach
    // this event source to the provider's workloop.
    //
	_cmdGate = IOCommandGate::commandGate(this);
	if (_cmdGate == 0)
		return false;

    IOWorkLoop * workloop = _ataDevice->getWorkLoop();
    if ((workloop == 0) ||
        (workloop->addEventSource(_cmdGate) != kIOReturnSuccess))
        return false;

    // Starts up in the active state.
    //
    _currentATAPowerState = kIOATAPowerStateActive;

    // A policy-maker must make these calls to join the PM tree,
    // and to initialize its state.
    //
    PMinit();                    /* initialize power management variables */
    provider->joinPMtree(this);  /* join power management tree */
	setIdleTimerPeriod(300);     /* 300 sec inactivity timer */

    if (_supportedFeatures & kIOATAFeaturePowerManagement)
        initForPM();

	return (createNub(provider));
}

//---------------------------------------------------------------------------
// Stop the driver.

void
IOATAHDDrive::stop(IOService * provider)
{
    PMstop();

    super::stop(provider);
}   

//---------------------------------------------------------------------------
// Release allocated resources.

void
IOATAHDDrive::free()
{
    if (_configThreadCall) {
        thread_call_cancel((thread_call_t) _configThreadCall);
        thread_call_free((thread_call_t) _configThreadCall);    
    }

	if (_cmdGate) {
        if (_ataDevice && (_ataDevice->getWorkLoop()))
            _ataDevice->getWorkLoop()->removeEventSource(_cmdGate);
		_cmdGate->release();
    }

	if (_ataDevice)
		_ataDevice->release();

	super::free();
}

//---------------------------------------------------------------------------
// Fetch information about the ATA device nub.

bool
IOATAHDDrive::inspectDevice(IOATADevice * ataDevice)
{
	OSString *    string;
    ATAIdentify * identify;

	// Fetch ATA device information from the nub.
	//
	string = OSDynamicCast(OSString,
                           ataDevice->getProperty(kATAPropertyModelNumber));
	if (string) {		
		strncpy(_model, string->getCStringNoCopy(), 40);
		_model[40] = '\0';
	}

	string = OSDynamicCast(OSString,
                           ataDevice->getProperty(kATAPropertyFirmwareRev));
	if (string) {
		strncpy(_revision, string->getCStringNoCopy(), 8);
		_revision[8] = '\0';
	}

    // Fetch Word 82 (commandSetsSupported1) in Identify data.
    //
    identify = (ATAIdentify *) IOMalloc(sizeof(*identify));
    if (!identify)
        return false;

    ataDevice->getIdentifyData(identify);

    if (identify->commandSetsSupported1 & 0x8)
        _supportedFeatures |= kIOATAFeaturePowerManagement;

    if (identify->commandSetsSupported1 & 0x20)
        _supportedFeatures |= kIOATAFeatureWriteCache;
    
    IOFree(identify, sizeof(*identify));

    // Add an OSNumber property indicating the supported features.
    //
    setProperty(kIOATASupportedFeaturesKey,
                _supportedFeatures,
                sizeof(_supportedFeatures) * 8);

    return true;
}

//---------------------------------------------------------------------------
// Report the type of ATA device (ATA vs. ATAPI).

ATADeviceType
IOATAHDDrive::reportATADeviceType() const
{
	return kATADeviceATA;
}

//---------------------------------------------------------------------------
// Returns the device type.

const char *
IOATAHDDrive::getDeviceTypeName()
{
	return kIOBlockStorageDeviceTypeGeneric;
}

//---------------------------------------------------------------------------
// Instantiate an ATA specific subclass of IOBlockStorageDevice.

IOService * IOATAHDDrive::instantiateNub()
{
    IOService * nub = new IOATAHDDriveNub;
    return nub;
}

//---------------------------------------------------------------------------
// Returns an IOATAHDDriveNub.

bool IOATAHDDrive::createNub(IOService * provider)
{
    IOService * nub;

	// Instantiate a generic hard disk nub so a generic driver
	// can match above us.
	//
    nub = instantiateNub();

    if (nub == 0) {
        IOLog("%s: instantiateNub() failed\n", getName());
        return false;
    }

    nub->init();
    
    if (!nub->attach(this))
        IOPanic("IOATAHDDrive::createNub() unable to attach nub");

    nub->registerService();

    return true;
}

//---------------------------------------------------------------------------
// Handles read/write requests.

IOReturn IOATAHDDrive::doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                        UInt32               block,
                                        UInt32               nblks,
                                        IOStorageCompletion  completion)
{
	IOReturn       ret;
	IOATACommand * cmd = ataCommandReadWrite(buffer, block, nblks);

	if (cmd == 0)
		return kIOReturnNoMemory;

    ret = asyncExecute(cmd, completion);

	cmd->release();

	return ret;
}

IOReturn IOATAHDDrive::doSyncReadWrite(IOMemoryDescriptor * buffer,
                                       UInt32               block,
                                       UInt32               nblks)
{
	IOReturn       ret;
	IOATACommand * cmd = ataCommandReadWrite(buffer, block, nblks);

	if (cmd == 0)
		return kIOReturnNoMemory;

    ret = syncExecute(cmd);

	cmd->release();

	return ret;
}

//---------------------------------------------------------------------------
// Eject the media in the drive.

IOReturn IOATAHDDrive::doEjectMedia()
{
	return kIOReturnUnsupported;	// No support for removable ATA devices.
}

//---------------------------------------------------------------------------
// Format the media in the drive.
// ATA devices does not support low level formatting.

IOReturn IOATAHDDrive::doFormatMedia(UInt64 byteCapacity)
{
	return kIOReturnUnsupported;
}

//---------------------------------------------------------------------------
// Returns disk capacity.

UInt32 IOATAHDDrive::doGetFormatCapacities(UInt64 * capacities,
                                           UInt32   capacitiesMaxCount) const
{
	UInt32  blockCount = 0;
	UInt32  blockSize  = 0;

	assert(_ataDevice);

	if (_ataDevice->getDeviceCapacity(&blockCount, &blockSize) &&
		(capacities != NULL) && (capacitiesMaxCount > 0))
    {
		UInt64 count = blockCount;
		UInt64 size  = blockSize;

		*capacities = size * (count + 1);
		
		return 1;
	}
	
	return 0;
}

//---------------------------------------------------------------------------
// Lock the media and prevent a user-initiated eject.

IOReturn IOATAHDDrive::doLockUnlockMedia(bool doLock)
{
	return kIOReturnUnsupported;	// No removable ATA device support.
}

//---------------------------------------------------------------------------
// Flush the write-cache to the physical media.

IOReturn IOATAHDDrive::doSynchronizeCache()
{
	IOReturn       ret;
	IOATACommand * cmd = ataCommandFlushCache();

	if (cmd == 0)
		return kIOReturnNoMemory;

    ret = syncExecute(cmd, 60000);

	cmd->release();

	return ret;
}

//---------------------------------------------------------------------------
// Handle a Start Unit command.

IOReturn
IOATAHDDrive::doStart()
{
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Handle a Stop Unit command.

IOReturn
IOATAHDDrive::doStop()
{
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Return device identification strings.

char * IOATAHDDrive::getAdditionalDeviceInfoString()
{
    return ("[ATA]");
}

char * IOATAHDDrive::getProductString()
{
    return _model;
}

char * IOATAHDDrive::getRevisionString()
{
    return _revision;
}

char * IOATAHDDrive::getVendorString()
{
    return NULL;
}

//---------------------------------------------------------------------------
// Report the device block size in bytes. We ask the device nub for the
// block size. We expect this to be 512-bytes.

IOReturn IOATAHDDrive::reportBlockSize(UInt64 * blockSize)
{
	UInt32  blkCount = 0;
	UInt32  blkSize  = 0;

	assert(_ataDevice);

	if (!_ataDevice->getDeviceCapacity(&blkCount, &blkSize))
		return kIOReturnNoDevice;

	*blockSize = blkSize;
    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report the media in the ATA device as non-ejectable.

IOReturn IOATAHDDrive::reportEjectability(bool * isEjectable)
{
	*isEjectable = false;
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Fixed media, locking is invalid.

IOReturn IOATAHDDrive::reportLockability(bool * isLockable)
{
    *isLockable = false;
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report the polling requirements for a removable media.

IOReturn IOATAHDDrive::reportPollRequirements(bool * pollRequired,
                                              bool * pollIsExpensive)
{
    *pollIsExpensive = false;
    *pollRequired    = false;

    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report the max number of bytes transferred for an ATA read command.

IOReturn IOATAHDDrive::reportMaxReadTransfer(UInt64 blocksize, UInt64 * max)
{
    *max = blocksize * kIOATAMaxBlocksPerXfer;
    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report the max number of bytes transferred for an ATA write command.

IOReturn IOATAHDDrive::reportMaxWriteTransfer(UInt64 blocksize, UInt64 * max)
{
	// Same as read transfer limits.
	//
    return reportMaxReadTransfer(blocksize, max);
}

//---------------------------------------------------------------------------
// Returns the maximum addressable sector number.

IOReturn IOATAHDDrive::reportMaxValidBlock(UInt64 * maxBlock)
{
	UInt32  blockCount = 0;
	UInt32  blockSize  = 0;

	assert(_ataDevice && maxBlock);

	if (!_ataDevice->getDeviceCapacity(&blockCount, &blockSize))
		return kIOReturnNoDevice;

    *maxBlock = blockCount;

    return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report whether the media is currently present, and whether a media
// change has been registered since the last reporting.

IOReturn IOATAHDDrive::reportMediaState(bool * mediaPresent, bool * changed)
{
	*mediaPresent = true;
	*changed      = true;
	
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report whether the media is removable.

IOReturn IOATAHDDrive::reportRemovability(bool * isRemovable)
{
	*isRemovable = false;
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Report if the media is write-protected.

IOReturn IOATAHDDrive::reportWriteProtection(bool * isWriteProtected)
{
	*isWriteProtected = false;
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Handles messages from our provider.

IOReturn
IOATAHDDrive::message(UInt32 type, IOService * provider, void * argument)
{
	IOReturn ret = kIOReturnSuccess;

//  IOLog("IOATAHDDrive::message %p %lx\n", this, type);

	switch (type)
	{
		case kATAClientMsgBusReset:
            _ataDevice->holdQueue(kATAQTypeNormalQ);
			break;

		case kATAClientMsgBusReset | kATAClientMsgDone:
            configureDevice( _ataDevice );
			break;

        case kATAClientMsgSelectTiming | kATAClientMsgDone:
            _ataDevice->releaseQueue(kATAQTypeNormalQ);
            break;

		default:
			ret = super::message(type, provider, argument);
			break;
	}

	return ret;
}
