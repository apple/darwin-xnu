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
 * IOATAPIHDDrive.h - Generic ATAPI Direct-Access driver.
 *
 * HISTORY
 * Sep 2, 1999	jliu - Ported from AppleATAPIDrive.
 */

#ifndef	_IOATAPIHDDRIVE_H
#define	_IOATAPIHDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/storage/ata/IOATAHDDrive.h>

// ATAPI (inquiry) device type.
//
enum IOATAPIDeviceType
{
	kIOATAPIDeviceTypeDirectAccess  = 0x00
};

// ATAPI packet commands.
//
enum {
	kIOATAPICommandTestUnitReady    = 0x00,
	kIOATAPICommandFormatUnit       = 0x04,
	kIOATAPICommandStartStopUnit    = 0x1b,
	kIOATAPICommandPreventAllow     = 0x1e,
	kIOATAPICommandSynchronizeCache = 0x35,
	kIOATAPICommandModeSelect       = 0x55,
	kIOATAPICommandModeSense        = 0x5a,
	kIOATAPICommandRead             = 0xa8,
	kIOATAPICommandWrite            = 0xaa
};

// ATAPI feature register flags.
//
enum {
	kIOATAPIFeaturesDMA             = 0x01,
	kIOATAPIFeaturesOverlay         = 0x02,
};

#define kIOATAPIMaxTransfer   65534


//===========================================================================
// IOATAPIHDDrive
//===========================================================================

class IOATAPIHDDrive : public IOATAHDDrive
{
    OSDeclareDefaultStructors(IOATAPIHDDrive)

protected:
	char                   _vendor[9];
	char                   _product[17];
	bool                   _mediaPresent;
	bool                   _isRemovable;
	ATAProtocol            _atapiProtocol;
    bool                   _isLocked;

	//-----------------------------------------------------------------------
	// Selects a command protocol to use. The argument specifies whether
	// the device supports DMA mode.

	virtual bool           selectCommandProtocol(bool isDMA);

	//-----------------------------------------------------------------------
	// Issues an ATAPI Start/Stop Unit command.

	virtual IOReturn       doStartStop(bool doStart);

	//-----------------------------------------------------------------------
	// Given the device type from the ATAPI Inquiry data, returns true if
	// the device type is supported by this driver.

	virtual bool           matchATAPIDeviceType(UInt8 type, SInt32 * score);

	//-----------------------------------------------------------------------
	// Setup a ATATaskFile for an ATAPI packet command from the parameters 
	// given.
	
	virtual void           setupPacketTaskFile(ATATaskfile * taskfile,
                                               ATAProtocol   protocol,
                                               UInt16        byteCount);

	//-----------------------------------------------------------------------
	// Create a generic ATAPI command object.

	virtual IOATACommand * atapiCommand(ATACDBInfo *   packetCommand,
                                IOMemoryDescriptor * transferBuffer = 0);

	//-----------------------------------------------------------------------
	// Allocates and return an IOATACommand to perform a read/write operation.

	virtual IOATACommand * atapiCommandReadWrite(IOMemoryDescriptor * buffer,
                                                 UInt32               block,
                                                 UInt32               nblks);

	//-----------------------------------------------------------------------
	// ATAPI Start/Stop Unit command (1B).

	virtual IOATACommand * atapiCommandStartStopUnit(bool doStart,
                                                     bool doLoadEject,
                                                     bool immediate);

	//-----------------------------------------------------------------------
	// ATAPI Format Unit command (04).

    virtual IOATACommand * atapiCommandFormatUnit(
                                       UInt16               interleave,
                                       UInt8                flagBits,
                                       UInt8                vendorBits,
                                       IOMemoryDescriptor * formatData);

	//-----------------------------------------------------------------------
	// ATAPI Synchronize Cache command (35).

    virtual IOATACommand * atapiCommandSynchronizeCache();
    
	//-----------------------------------------------------------------------
	// ATAPI Prevent/Allow medium removal command (1E).

	virtual IOATACommand * atapiCommandPreventAllowRemoval(bool doLock);

	//-----------------------------------------------------------------------
	// ATAPI Test Unit Ready command (00).

	virtual IOATACommand * atapiCommandTestUnitReady();

    //----------------------------------------------------------------------
    // ATAPI Mode Sense command (5a).

    virtual IOATACommand * atapiCommandModeSense(
                                       IOMemoryDescriptor * buffer,
                                       UInt8                pageCode,
                                       UInt8                pageControl);

    //----------------------------------------------------------------------
    // ATAPI Mode Select command (55).

    virtual IOATACommand * atapiCommandModeSelect(
                            IOMemoryDescriptor * buffer);

	//-----------------------------------------------------------------------
	// Overrides the method in IOATAHDDrive and returns an IOATAPIHDDriveNub
	// instance.

    virtual IOService *	   instantiateNub();

	//-----------------------------------------------------------------------
	// Overrides the method in IOATAHDDrive. Inspect the ATAPI device.

	virtual bool           inspectDevice(IOATADevice * device);

	//-----------------------------------------------------------------------
	// Overrides the method in IOATAHDDrive. Add ATAPI wakeup handler.

    virtual void           handleActiveStateTransition( UInt32 stage,
                                                        IOReturn status );

public:
    /*
	 * IOATAHDDrive overrides.
	 */
    virtual bool           init(OSDictionary * properties);
	virtual IOService *    probe(IOService * provider, SInt32 * score);

	virtual ATADeviceType  reportATADeviceType() const;

	virtual IOReturn       doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                            UInt32               block,
                                            UInt32               nblks,
                                            IOStorageCompletion  completion);

    virtual IOReturn       doSyncReadWrite(IOMemoryDescriptor * buffer,
                                           UInt32               block,
                                           UInt32               nblks);

	virtual IOReturn       doEjectMedia();

	virtual IOReturn       doFormatMedia(UInt64               byteCapacity,
                                         IOMemoryDescriptor * formatData = 0);

	virtual IOReturn       doLockUnlockMedia(bool doLock);
	
	virtual IOReturn       doSynchronizeCache();

	virtual IOReturn       doStart();
	virtual IOReturn       doStop();

    virtual char *         getVendorString();
    virtual char *         getProductString();
    virtual char *         getRevisionString();
    virtual char *         getAdditionalDeviceInfoString();

	virtual IOReturn       reportEjectability(bool * isEjectable);
	virtual IOReturn       reportLockability(bool * isLockable);
	virtual IOReturn       reportPollRequirements(bool * pollRequired,
                                                  bool * pollIsExpensive);

	virtual IOReturn       reportMediaState(bool * mediaPresent, 
                                            bool * changed);

	virtual IOReturn       reportRemovability(bool * isRemovable);

	virtual IOReturn       reportWriteProtection(bool * isWriteProtected);
};

#endif /* !_IOATAPIHDDRIVE_H */
