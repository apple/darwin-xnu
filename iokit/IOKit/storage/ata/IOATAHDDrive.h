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
 * IOATAHDDrive.h
 *
 * HISTORY
 * Aug 27, 1999    jliu - Ported from AppleATADrive.
 */

#ifndef _IOATAHDDRIVE_H
#define _IOATAHDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/ata/IOATADeviceInterface.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/storage/IOStorage.h>

class IOSyncer;

// ATA parameters.
//
#define kIOATASectorSize          512
#define kIOATAMaxBlocksPerXfer    256

// ATA commands.
//
enum {
    kIOATACommandReadPIO            = 0x20,
    kIOATACommandWritePIO           = 0x30,
    kIOATACommandReadDMA            = 0xc8,
    kIOATACommandWriteDMA           = 0xca,
    kIOATACommandReadDMAQueued      = 0xc7,
    kIOATACommandWriteDMAQueued     = 0xcc,
    kIOATACommandStandbyImmediate   = 0xe0,
    kIOATACommandSleep              = 0xe6,
    kIOATACommandFlushCache         = 0xe7,
    kIOATACommandSetFeatures        = 0xef,
};

// ATA power states, from lowest to highest power usage.
//
typedef enum {
    kIOATAPowerStateSleep = 0,
    kIOATAPowerStateStandby,
    kIOATAPowerStateIdle,
    kIOATAPowerStateActive
} IOATAPowerState;

// ATA supported features.
//
enum {
    kIOATAFeaturePowerManagement  = 0x01,
    kIOATAFeatureWriteCache       = 0x02
};

// Stages to transition into each power state.
//
enum {
    kIOATAStandbyStage0,  /* hold the queue */
    kIOATAStandbyStage1,  /* flush disk write cache */
    kIOATAStandbyStage2,  /* issue ATA STANDBY IMMEDIATE command */
    kIOATAStandbyStage3   /* finalize state transition */
};

enum {
    kIOATAActiveStage0,   /* issue a software reset */
    kIOATAActiveStage1,   /* spin up the drive */
    kIOATAActiveStage2,   /* release the queue */
	kIOATAActiveStage3    /* finalize state transition */
};

// Property table keys.
//
#define kIOATASupportedFeaturesKey   "ATA Features"
#define kIOATAEnableWriteCacheKey    "Enable Write Cache"

//===========================================================================
// IOATAClientData - This structure is stored on the IOATACommand's
// driver private area.
//===========================================================================

struct IOATAClientData
{
    IOATACommand *          command;     // back pointer to command object.
    IOMemoryDescriptor *    buffer;      // transfer buffer descriptor.
    union {
        IOStorageCompletion async;       // completion target/action/param.
        IOSyncer *          syncLock;    // used by sync commands.
    } completion;
    bool                    isSync;      // command is synchronous.
    SInt32                  maxRetries;  // max retry attempts (0 = no retry).
    IOReturn                returnCode;  // sync command return code.
};

// Get driver private data (IOATAClientData) from an IOATACommand object.
//
#define ATA_CLIENT_DATA(x)    ((IOATAClientData *)((x)->getClientData()))

//===========================================================================
// IOATAHDDrive
//===========================================================================

class IOATAHDDrive : public IOService
{
    OSDeclareDefaultStructors(IOATAHDDrive)

protected:
    IOATADevice *         _ataDevice;
    IOCommandGate *       _cmdGate;
    UInt                  _unit;
    ATATimingProtocol     _timingProtocol;
    ATAProtocol           _ataProtocol;
    UInt8                 _ataReadCmd;
    UInt8                 _ataWriteCmd;
    char                  _revision[9];
    char                  _model[41];
    bool                  _powerStateChanging;
    bool                  _setPowerAckPending;
    bool                  _logSelectedTimingProtocol;
    IOOptionBits          _supportedFeatures;
    IOATAPowerState       _currentATAPowerState;
    IOATAPowerState       _proposedATAPowerState;
    void *                _configThreadCall;
    bool                  _pmReady;

    //-----------------------------------------------------------------------
    // Default timeout (in milliseconds) for async and sync commands.
    
    static const UInt kATADefaultTimeout = 30000;        // 30 seconds

    //-----------------------------------------------------------------------
    // Default retry count for async and sync commands.

    static const UInt kATADefaultRetries = 4;
    static const UInt kATAZeroRetry      = 0;

    //-----------------------------------------------------------------------
    // Static member functions called by IOCommandGate, or registered
    // as completion routines.

    static void sHandleCommandCompletion(IOATAHDDrive * self,
                                         IOATACommand * cmd);

    static void sHandleSetPowerState(IOATAHDDrive * self,
                                     UInt32         powerStateOrdinal,
                                     IOService *    whatDevice,
                                     IOReturn *     handlerReturn);
    
    static void sHandleSleepStateTransition(IOATAHDDrive * self,
                                            void *         stage,
                                            IOReturn       status,
                                            UInt64         bytesTransferred);
    
    static void sHandleActiveStateTransition(IOATAHDDrive * self,
                                             void *         stage,
                                             IOReturn       status,
                                             UInt64         bytesTransferred);

    static void sHandleIdleStateTransition(IOATAHDDrive * self,
                                           void *         stage,
                                           IOReturn       status,
                                           UInt64         bytesTransferred);
                                             
    static void sHandleStandbyStateTransition(IOATAHDDrive * self,
                                              void *         stage,
                                              IOReturn       status,
                                              UInt64         bytesTransferred);
                                
    static void sHandleInitialPowerStateForDomainState(
                                              IOATAHDDrive * self,
                                              IOPMPowerFlags domainState,
                                              UInt32 *       state);

    static void sHandleConfigureDevice(IOATAHDDrive * self);
    
    //-----------------------------------------------------------------------
    // Release all allocated resource before calling super::free().

    virtual void free();

    //-----------------------------------------------------------------------
    // Select the device timing protocol.

    virtual bool selectTimingProtocol();

    //-----------------------------------------------------------------------
    // Select the ATA protocol.
    
    virtual bool selectCommandProtocol(bool isDMA);

    //-----------------------------------------------------------------------
    // Setup an ATATaskFile from the parameters given, and write the taskfile
    // to the ATATaskfile structure pointer provided.

    virtual void setupReadWriteTaskFile(ATATaskfile * taskfile,
                                        ATAProtocol   protocol,
                                        UInt8         command,
                                        UInt32        block,
                                        UInt32        nblks);

    //-----------------------------------------------------------------------
    // Return an IOATACommand initialized to perform a read/write operation.

    virtual IOATACommand * ataCommandReadWrite(IOMemoryDescriptor * buffer,
                                               UInt32               block,
                                               UInt32               nblks);

    //-----------------------------------------------------------------------
    // Return a ATA Set Features command.

    virtual IOATACommand * ataCommandSetFeatures(UInt8 features,
                                                 UInt8 SectorCount   = 0,
                                                 UInt8 SectorNumber  = 0,
                                                 UInt8 CylinderLow   = 0,
                                                 UInt8 CyclinderHigh = 0);

    //-----------------------------------------------------------------------
    // Return a ATA Flush Cache command.
    
    virtual IOATACommand * ataCommandFlushCache();
    
    //-----------------------------------------------------------------------
    // Return a ATA Standby Immediate command.
    
    virtual IOATACommand * ataCommandStandby();
    
    //-----------------------------------------------------------------------
    // Issue a synchronous ATA command.

    virtual IOReturn syncExecute(IOATACommand * cmd,
                                 UInt32         timeout = kATADefaultTimeout,
                                 UInt           retries = kATADefaultRetries,
                                 IOMemoryDescriptor * senseData = 0);

    //-----------------------------------------------------------------------
    // Issue an asynchronous ATA command.

    virtual IOReturn asyncExecute(
                          IOATACommand *      cmd,
                          IOStorageCompletion completion,
                          UInt32              timeout = kATADefaultTimeout,
                          UInt                retries = kATADefaultRetries);

    //-----------------------------------------------------------------------
    // Allocate an IOATACommand object.

    virtual IOATACommand * allocateCommand();

    //-----------------------------------------------------------------------
    // Inspect the ATA device.

    virtual bool inspectDevice(IOATADevice * device);

    //-----------------------------------------------------------------------
    // Configure the ATA device.

    virtual bool configureDevice(IOATADevice * device);
    
    //-----------------------------------------------------------------------
    // Returns an IOATAHDDriveNub instance.

    virtual IOService * instantiateNub();

    //-----------------------------------------------------------------------
    // Calls instantiateNub() then initialize, attach, and register the
    // drive nub.

    virtual bool createNub(IOService * provider);

    //-----------------------------------------------------------------------
    // Power management support. Subclasses can override these functions
    // to replace/enhance the default power management support.

    virtual void initForPM();

    virtual UInt32 handleInitialPowerStateForDomainState(
                                             IOPMPowerFlags domainState);

    virtual IOReturn handleSetPowerState(UInt32      powerStateOrdinal,
                                         IOService * whatDevice);

    virtual IOATAPowerState getATAPowerStateForStateOrdinal(
                                               UInt32 stateOrdinal);

    virtual void startATAPowerStateTransition(IOATAPowerState ataPowerState);

    virtual void endATAPowerStateTransition(IOATAPowerState ataPowerState);

    virtual void abortATAPowerStateTransition();

    virtual void handleSleepStateTransition(UInt32 stage, IOReturn status);

    virtual void handleActiveStateTransition(UInt32 stage, IOReturn status);

    virtual void handleIdleStateTransition(UInt32 stage, IOReturn status);

    virtual void handleStandbyStateTransition( UInt32 stage, IOReturn status);

    virtual IOReturn readSector(IOStorageCompletion completion,
                                UInt32              sector = 0);
    
    static void acknowledgeATAPowerStateTransition(void *castMeToIOATAHDDrive, void*);
    
public:
    /*
     * Overrides from IOService.
     */
    virtual bool        init(OSDictionary * properties);
    virtual IOService * probe(IOService * provider, SInt32 * score);
    virtual bool        start(IOService * provider);
    virtual void        stop(IOService * provider);

    //-----------------------------------------------------------------------
    // Report the type of ATA device (ATA vs. ATAPI).

    virtual ATADeviceType reportATADeviceType() const;

    //-----------------------------------------------------------------------
    // Handles read/write requests.

    virtual IOReturn doAsyncReadWrite(IOMemoryDescriptor * buffer,
                                      UInt32               block,
                                      UInt32               nblks,
                                      IOStorageCompletion  completion);

    virtual IOReturn doSyncReadWrite(IOMemoryDescriptor * buffer,
                                     UInt32               block,
                                     UInt32               nblks);

    //-----------------------------------------------------------------------
    // Eject the media in the drive.

    virtual IOReturn doEjectMedia();

    //-----------------------------------------------------------------------
    // Format the media in the drive.

    virtual IOReturn doFormatMedia(UInt64 byteCapacity);

    //-----------------------------------------------------------------------
    // Returns disk capacity in bytes.

    virtual UInt32 doGetFormatCapacities(UInt64 * capacities,
                                         UInt32   capacitiesMaxCount) const;

    //-----------------------------------------------------------------------
    // Lock the media and prevent a user-initiated eject.
    
    virtual IOReturn doLockUnlockMedia(bool doLock);

    //-----------------------------------------------------------------------
    // Flush the write-cache to the physical media.

    virtual IOReturn doSynchronizeCache();

    //-----------------------------------------------------------------------
    // Start/stop the drive.

    virtual IOReturn doStart();
    virtual IOReturn doStop();

    //-----------------------------------------------------------------------
    // Return device identification strings

    virtual char * getAdditionalDeviceInfoString();
    virtual char * getProductString();
    virtual char * getRevisionString();
    virtual char * getVendorString();

    //-----------------------------------------------------------------------
    // Report the device block size in bytes.

    virtual IOReturn reportBlockSize(UInt64 * blockSize);

    //-----------------------------------------------------------------------
    // Report whether the media in the ATA device is ejectable.

    virtual IOReturn reportEjectability(bool * isEjectable);

    //-----------------------------------------------------------------------
    // Report whether the media can be locked.

    virtual IOReturn reportLockability(bool * isLockable);

    //-----------------------------------------------------------------------
    // Report the polling requirements for a removable media.

    virtual IOReturn reportPollRequirements(bool * pollRequired,
                                                  bool * pollIsExpensive);

    //-----------------------------------------------------------------------
    // Report the max number of bytes transferred for an ATA read command.

    virtual IOReturn reportMaxReadTransfer(UInt64   blocksize,
                                           UInt64 * max);

    //-----------------------------------------------------------------------
    // Report the max number of bytes transferred for an ATA write command.

    virtual IOReturn reportMaxWriteTransfer(UInt64   blocksize,
                                            UInt64 * max);

    //-----------------------------------------------------------------------
    // Returns the maximum addressable sector number.

    virtual IOReturn reportMaxValidBlock(UInt64 * maxBlock);

    //-----------------------------------------------------------------------
    // Report whether the media is currently present, and whether a media
    // change has been registered since the last reporting.

    virtual IOReturn reportMediaState(bool * mediaPresent, 
                                      bool * changed);
    
    //-----------------------------------------------------------------------
    // Report whether the media is removable.
    
    virtual IOReturn reportRemovability(bool * isRemovable);
    
    //-----------------------------------------------------------------------
    // Report if the media is write-protected.

    virtual IOReturn reportWriteProtection(bool * isWriteProtected);

    //-----------------------------------------------------------------------
    // Handles messages (notifications) from our provider.

    virtual IOReturn message(UInt32      type,
                             IOService * provider,
                             void *      argument);

    //-----------------------------------------------------------------------
    // Returns the device type.

    virtual const char * getDeviceTypeName();

    //-----------------------------------------------------------------------
    // Power management support. Functions inherited from IOService.

    virtual IOReturn setAggressiveness(UInt32 type, UInt32 minutes);

    virtual UInt32 initialPowerStateForDomainState(IOPMPowerFlags domainState);
	
    virtual IOReturn setPowerState(UInt32      powerStateOrdinal,
                                   IOService * whatDevice);    
};

#endif /* !_IOATAHDDRIVE_H */
