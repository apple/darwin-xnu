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
 * IOSCSIHDDrive.h
 *
 * This class implements SCSI hard disk functionality.
 *
 * Subclasses may modify the operations to handle device-specific variations.
 */

#ifndef	_IOSCSIHDDRIVE_H
#define	_IOSCSIHDDRIVE_H

#include <IOKit/IOTypes.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/scsi/IOBasicSCSI.h>

/* SCSI (inquiry) device type. */

enum {
    kIOSCSIDeviceTypeDirectAccess  = 0x00
};

/* SCSI commands. */

enum {
    kIOSCSICommandTestUnitReady    = 0x00,
    kIOSCSICommandFormatUnit       = 0x04,
    kIOSCSICommandStartStopUnit    = 0x1b,
    kIOSCSICommandPreventAllow     = 0x1e,
    kIOSCSICommandSynchronizeCache = 0x35,
    kIOSCSICommandModeSelect       = 0x55,
    kIOSCSICommandModeSense        = 0x5a,
    kIOSCSICommandRead             = 0xa8,
    kIOSCSICommandWrite            = 0xaa
};

struct IOFormatcdb {
    UInt8	opcode;			/* 0x12 */
    UInt8	lunbits;		/* lun and control bits */
    UInt8	vendor;
    UInt8	interleave_msb;
    UInt8	interleave_lsb;
    UInt8	ctlbyte;
};

struct IOPrevAllowcdb {
    UInt8	opcode;
    UInt8	lunbits;
    UInt8	reserved1;
    UInt8	reserved2;
    UInt8	prevent;
    UInt8	ctlbyte;
};

struct IOStartStopcdb {
    UInt8	opcode;
    UInt8	lunImmed;
    UInt8	reserved1;
    UInt8	reserved2;

    /* Control bits: */
                                        /* Power Conditions */
static const UInt8	P_NOCHANGE	= 0x00;	/*  0 - no change */
static const UInt8	P_ACTIVE	= 0x10;	/*  1 - change to Active */
static const UInt8	P_IDLE		= 0x20;	/*  2 - change to Idle */
static const UInt8	P_STANDBY	= 0x30;	/*  3 - change to Standby */
static const UInt8	P_RESERVED4	= 0x40;	/*  4 - reserved */
static const UInt8	P_SLEEP		= 0x50;	/*  5 - change to Sleep */
static const UInt8	P_RESERVED6	= 0x60;	/*  6 - reserved */
static const UInt8	P_LUNCONTROL	= 0x70;	/*  7 - give pwr ctl to LUN */
static const UInt8	P_RESERVED8	= 0x80;	/*  8 - reserved */
static const UInt8	P_RESERVED9	= 0x90;	/*  9 - reserved */
static const UInt8	P_TIDLEZERO	= 0xa0;	/*  a - force Idle Cond Timer = 0 */
static const UInt8	P_TSTDBYZERO	= 0xb0;	/*  b - force Stby Cond Timer = 0 */

static const UInt8	C_LOEJ		= 0x02;	/* load on start/eject on stop */
static const UInt8	C_SPINUP	= 0x01;
static const UInt8	C_SPINDOWN	= 0x00;

    UInt8	controls;
    UInt8	ctlbyte;
};

struct IOSyncCachecdb {
    UInt8	opcode;
    UInt8	lunbits;
    UInt8	lba_3;			/* msb */
    UInt8	lba_2;
    UInt8	lba_1;
    UInt8	lba_0;			/* lsb */
    UInt8	reserved;
    UInt8	nblks_msb;
    UInt8	nblks_lsb;
    UInt8	ctlbyte;
};

/*!
 * @enum Power States
 * @discussion
 * We define and understand three basic, generic power states. A subclass may change
 * the power management logic, but all power-management routines should be examined
 * if anything is changed. The only routines that deal directly with these values
 * are directly related to power management. All other functions merely ask for and
 * pass along power state values.
 * @constant kAllOff
 * The power state for an all-off condition.
 * @constant kElectronicsOn
 * The power state for the electronics on, but the media off.
 * @constant kAllOn
 * The power state for the electronics and media on.
 * @constant kNumberOfPowerStates
 * The maximum enum value.
 */
enum {					/* electronics		mechanical	*/
    kAllOff		= 0,		/*	OFF		OFF		*/
    kElectronicsOn	= 1,		/* 	 ON		OFF		*/
    kAllOn		= 2,		/*	 ON		 ON		*/

    kNumberOfPowerStates = 3
};

/*!
 * @class
 * IOSCSIHDDrive : public IOBasicSCSI
 * @abstract
 * SCSI Hard Disk driver.
 * @discussion
 * IOSCSIHDDrive derives from IOBasicSCSI and adds all functionality
 * needed to support removable or fixed hard disk drives.
 */

class IOSCSIHDDrive : public IOBasicSCSI {

    OSDeclareDefaultStructors(IOSCSIHDDrive)

public:

    /* Overrides from IOService: */

    virtual bool	init(OSDictionary * properties);

    /*!
     * @function start
     * @abstract
     * Start the driver.
     * @discussion
     * We override IOBasicSCSI::start so we can initialize Power Management,
     * then we call createNub to create an IOSCSIHDDriveNub.
     */
    virtual bool	start(IOService * provider);

    /* Overrides from IOBasicSCSI: */
    
    /*!
     * @function deviceTypeMatches
     * @abstract
     * Determine if device type matches expected type.
     * @discussion
     * We implement this function so we can return a match
     * on the hard disk device type.
     */
    virtual bool	deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 *score);

    /*!
     * @function constructDeviceProperties
     * @abstract
     * Construct a set of properties about the device.
     * @discussion
     * This function creates a set of properties reflecting information
     * about the device.
     * 
     * This function is presently not used.
     * @result
     * A pointer to an OSDictionary containing the properties. The caller
     * is responsible for releasing the OSDictionary.
     */
    virtual OSDictionary *constructDeviceProperties(void);

    /*!
     * @function RWCompletion
     * @abstract
     * Asynchronous read/write completion routine.
     * @discussion
     * We implement this function in this class. It is called from the base
     * class when an IO operation completes.
     */
    virtual void	RWCompletion(struct context *cx);

    /* End of IOBasicSCSI overrides */
    
    /* Additional API added to IOBasicSCSI: */

    /*!
     * @function doAsyncReadWrite
     * @abstract
     * Start an asynchronous read or write operation.
     * @discussion
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion);

    /*!
     * @function doSyncReadWrite
     * @abstract
     * Perform a synchronous read or write operation.
     * @discussion
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks);

    /*!
     * @function doEjectMedia
     * @abstract
     * Eject the media.
     * @discussion
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doEjectMedia(void);

    /*!
     * @function doFormatMedia
     * @abstract
     * Format the media to the specified byte capacity.
     * @discussion
     * The default implementation calls standardFormatMedia.
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doFormatMedia(UInt64 byteCapacity);  

    /*!
     * @function doGetFormatCapacities
     * @abstract
     * Return the allowable formatting byte capacities.
     * @discussion
     * The default implementation of this method returns a value of block
     * size * max block, and a capacities count of 1.
     * See IOBlockStorageDevice for details.
     */    
    virtual UInt32	doGetFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const;   

    /*!
     * @function doLockUnlockMedia
     * @abstract
     * Lock or unlock the (removable) media in the drive.
     * @discussion
     * This method issues a standard SCSI Prevent/Allow command to lock
     * or unlock the media in the drive.
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doLockUnlockMedia(bool doLock);

    /*!
     * @function doSynchronizeCache
     * @abstract
     * Force data blocks in the drive's buffer to be flushed to the media.
     * @discussion
     * This method issues a SCSI Synchronize Cache command, to ensure that
     * all blocks in the device cache are written to the media.
     * See IOBlockStorageDevice for details.
     */    
    virtual IOReturn	doSynchronizeCache(void);

    /*!
     * @function reportMediaState
     * @abstract
     * Report the device's media state.
     * @discussion
     * This method reports whether media is present or not, and also
     * whether the media state has changed since the last call to
     * reportMediaState.  The default implementation issues a SCSI Test
     * Unit Ready command: depending on the result of that command, the
     * following cases are reported:
     * 
     * 1. TUR status == good completion: we report media present and return
     * kIOReturnSuccess.
     * 
     * 2. TUR status != good completion, but good autosense returned:
     * 
     * 2a: sense key says not ready: we report media not present
     * and return kIOReturnSuccess.
     * 
     * 2b: sense key is anything else: we report media not present
     * and return kIOReturnIOError.
     * 
     * 3. TUR status != good completion, and no autosense data: we do not
     * set mediaPresent or changedState, and we return whatever result
     * came back from the SCSI operation.
     */    
    virtual IOReturn	reportMediaState(bool *mediaPresent,bool *changed);
    
    /* --- end of additional API --- */

protected:
        
    /*!
     * @function createFormatCdb
     * @abstract
     * Create a SCSI CDB for a format operation.
     * @discussion
     * Override this to control the cdb created for a format operation.
     * The default implementation creates a 6-byte format command with
     * no data buffer, disconnect allowed, 8-byte autosense, and a 15-minute timeout.
     * 
     * See also: allocateFormatBuffer, deleteFormatBuffer, composeFormatBuffer.
     * @param byteCapacity
     * The requested byte capacity to which the media should be formatted. This value
     * should have been previously validated, otherwise the device may return an error.
     * @param cdb
     * A pointer to the CDB bytes.
     * @param cdbLength
     * The length of the CDB in bytes.
     * @param block
     * The device block to be written.
     * @param nblks
     * The number of blocks to be transferred.
     * @param maxAutoSenseLength
     * The maximum size of the autosense data, in bytes. A value of zero
     * will disable autosense.
     * @param timeoutSeconds
     * The command timeout in seconds.
     * @result
     * The IOSCSICommandOptions returned will be used to issue the command.
     */
    virtual UInt32	createFormatCdb(
                            UInt64 byteCapacity,	/* in  */
                            UInt8 *cdb,			/* in  */
                            UInt32 *cdbLength,		/* out */
                            UInt8 buf[],		/* in  */
                            UInt32 bufLen,		/* in  */
                            UInt32 *maxAutoSenseLength,	/* out */
                            UInt32 *timeoutSeconds);	/* out */


    /*!
     * @function allocateFormatBuffer
     * @abstract
     * Create a data buffer to be used for formatting the media.
     * @discussion
     * If a format buffer is to be used, then "allocateFormatBuffer" and
     * deleteFormatBuffer" must be overridden to manage the buffer. The
     * buffer must be prepared for IO upon return from allocateFormatBuffer.
     * The default implementations of these methods don't allocate a buffer.
     * @param buf
     * A pointer for the returned buffer pointer.
     * @param buflen
     * The desired length of the buffer, in bytes.
     */    
    virtual IOReturn	allocateFormatBuffer(UInt8 **buf,UInt32 *buflen);

    /*!
     * @function deleteFormatBuffer
     * @abstract
     * Delete the data buffer to be used for formatting the media.
     * @discussion
     * If a format buffer is to be used, then "allocateFormatBuffer" and
     * deleteFormatBuffer" must be overridden to manage the buffer.
     * The default implementation of this method does nothing.
     * @param buf
     * A pointer to the buffer to delete.
     * @param buflen
     * The size of the buffer, in bytes.
     */    
    virtual void	deleteFormatBuffer(UInt8 *buf,UInt32 buflen);

    /*!
     * @function composeFormatBuffer
     * @abstract
     * Compose the data in the buffer used for the format command.
     * @discussion
     * This method will be called to compose the data in the format buffer.
     * 
     * The default implementation of this method does nothing.
     * @param buf
     * A pointer to the format data buffer.
     * @param buflen
     * The size of the format data buffer, in bytes.
     * @result
     * The return value should be the desired values for the "CmpLst" and Defect
     * List Format bits in the CDB. The default implementation returns zero.
     */    
    virtual UInt8	composeFormatBuffer(UInt8 *buf,UInt32 buflen);

    /* Override these methods to save and restore the state of the device electronics
     * when power is turned off and on. The defaults do nothing and return kIOReturnSuccess.
     */

    /*!
     * @function restoreElectronicsState
     * @abstract
     * Restore the state of the device electronics when powering-up.
     * @discussion
     * This method is called just after the device transitions from a powered-off state.
     * 
     * The default implementation of this method does nothing and returns kIOReturnSuccess.
     */    
    virtual IOReturn	restoreElectronicsState(void);

    /*!
     * @function saveElectronicsState
     * @abstract
     * Save the state of the device electronics when powering-down.
     * @discussion
     * This method is called just before the device transitions to a powered-off state.
     * 
     * The default implementation of this method does nothing and returns kIOReturnSuccess.
     */    
    virtual IOReturn	saveElectronicsState(void);
                                                 
    /*!
     * @function initialPowerStateForDomainState
     * @abstract
     * Return the initial power state for the device.
     * @discussion
     * This method is called to obtain the initial power state for the device,
     * by calling getInitialPowerState.
     * @param domainState
     * Power domain state flags.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual unsigned long initialPowerStateForDomainState ( IOPMPowerFlags domainState );

    /*!
     * @function maxCapabilityForDomainState
     * @abstract
     * Return the maximum power level obtainable for the given state.
     * @discussion
     * This method is called to obtain the maximum power level obtainable for the
     * given state.
     * @param domainState
     * Power domain state flags.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual unsigned long  maxCapabilityForDomainState ( IOPMPowerFlags domainState );

    /*!
     * @function powerStateForDomainState
     * Return the maximum power level obtainable for the given state.
     * @discussion
     * This method is called to obtain the maximum power level obtainable for the
     * given state.
     * @param domainState
     * Power domain state flags.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual unsigned long powerStateForDomainState ( IOPMPowerFlags domainState );

    /*!
     * @function powerStateDidChangeTo
     * @abstract
     * React to a change in power state.
     * @discussion
     * This method is called when the power state changes. We call restoreElectronicsState
     * if necessary, then call dequeueCommands if we have changed to a state that has power.
     * @param stateOrdinal
     * The power level to which we have changed.
     */    
    virtual IOReturn powerStateDidChangeTo ( unsigned long, unsigned long stateOrdinal, IOService* );

    /*!
     * @function powerStateWillChangeTo
     * @abstract
     * Prepare for a power state change.
     * @discussion
     * This method is called when the power state will change. If we are powering-up from kAllOff,
     * we schedule a call to restoreElectronicsState. If, instead, we are powering-down from an "on" state,
     * we schedule a call to saveElectronicsState.
     * @param stateOrdinal
     * The power level to which we will change.
     */    
    virtual IOReturn powerStateWillChangeTo ( unsigned long, unsigned long stateOrdinal, IOService* );

    /*!
     * @function setPowerState
     * @abstract
     * Set the power state to the specified state.
     * @discussion
     * This method is called to cause a change in power state. We handle changes to and from
     * kAllOn and kElectronicsOn, which are done by spinning up and down the media.
     * @param powerStateOrdinal
     * The power level to which we must change.
     */    
    virtual IOReturn setPowerState ( unsigned long powerStateOrdinal, IOService* );

    /*!
     * @function powerTickle
     * Check for the device power state currently being in the desired state.
     * @discussion
     * This method simply "tickles"
     * the Power Management subsystem to ensure that the device transitions to the desired
     * state if necessary.
     */    
    virtual bool	powerTickle(UInt32 desiredState);

    /* Override this method to report the initial device power state when its domain is
     * powered up. The default implementation assumes the drive spins up.
     */

    /*!
     * @function getInitialPowerState
     * @abstract
     * Report the initial power state of the device.
     * @discussion
     * The default implementation of this method returns kAllOn, assuming that the
     * drive spindle spins up initially.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual unsigned long getInitialPowerState(void);	/* default = kAllOn */
                                                 
    /* Override these to change power level required to do various commands. */
                                                 
    /*!
     * @function getEjectPowerState
     * @abstract
     * Return the required device power level to determine eject the media.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getEjectPowerState(void);		/* default = kElectronicsOn */

    /*!
     * @function getExecuteCDBPowerState
     * @abstract
     * @discussion
     * @param
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getExecuteCDBPowerState(void);		/* default = kAllOn */

    /*!
     * @function getFormatMediaPowerState
     * @abstract
     * Return the required device power level to execute a client CDB.
     * @discussion
     * The default implementation of this method returns kAllOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getFormatMediaPowerState(void);		/* default = kAllOn */

    /*!
     * @function getInquiryPowerState
     * @abstract
     * Return the required device power level to execute an Inquiry command.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getInquiryPowerState(void);		/* default = kElectronicsOn */

    /*!
     * @function getLockUnlockMediaPowerState
     * @abstract
     * Return the required device power level to lock or unlock the media.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getLockUnlockMediaPowerState(void);	/* default = kElectronicsOn */

    /*!
     * @function getReadCapacityPowerState
     * @abstract
     * Return the required device power level to execute a Read-Capacity command.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getReadCapacityPowerState(void);	/* default = kElectronicsOn */

    /*!
     * @function getReadWritePowerState
     * @abstract
     * Return the required device power level to execute a Read or Write command.
     * @discussion
     * The default implementation of this method returns kAllOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getReadWritePowerState(void);		/* default = kAllOn */

    /*!
     * @function getReportWriteProtectionPowerState
     * @abstract
     * Return the required device power level to report media write protection.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getReportWriteProtectionPowerState(void); /* default = kElectronicsOn */

    /*!
     * @function getStartPowerState
     * @abstract
     * Return the required device power level to start (spin up) the media.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getStartPowerState(void);		/* default = kElectronicsOn */

    /*!
     * @function getStopPowerState
     * @abstract
     * Return the required device power level to stop (spin down) the media.
     * @discussion
     * The default implementation of this method returns kAllOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getStopPowerState(void);		/* default = kAllOn */

    /*!
     * @function getSynchronizeCachePowerState
     * @abstract
     * Return the required device power level to issue a Synchronize-Cache command.
     * @discussion
     * The default implementation of this method returns kAllOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getSynchronizeCachePowerState(void);	/* default = kAllOn */

    /*!
     * @function getTestUnitReadyPowerState
     * @abstract
     * Return the required device power level to issue a Test Unit Ready command.
     * @discussion
     * The default implementation of this method returns kElectronicsOn.
     * @result
     * The return value must be a valid power state value.
     */    
    virtual UInt32	getTestUnitReadyPowerState(void);	/* default = kElectronicsOn */
                                   
    /*
     * @group
     * Internally used methods.
     */

    /*!
     * @function createNub
     * @abstract
     * Create, init, attach, and register the device nub.
     * @discussion
     * This method calls instantiateNub, then init, attach, and register.
     * @result
     * A pointer to the nub or NULL if something failed.
     */    
    virtual IOService *	createNub(void);

    /*!
     * @function getDeviceTypeName
     * @abstract
     * Return a character string for the device type.
     * @discussion
     * The default implementation of this method returns 
     * kIOBlockStorageDeviceTypeGeneric.   
     */
    virtual const char * getDeviceTypeName(void);

    /*!
     * @function instantiateNub
     * @abstract
     * Create the device nub.
     * @discussion
     * A subclass will override this method to change the type of nub created.
     * A CD driver, for example, will instantiate an IOSCSICDDriveNub instead
     * of the default implementation's IOSCSIHDDriveNub.
     */    
    virtual IOService *	instantiateNub(void);

    /*!
     * @function doStart
     * @abstract
     * Start (spin up) the media.
     * @discussion
     * This method calls doStartStop.
     */    
    virtual IOReturn	doStart(void);

    /*!
     * @function doStartStop
     * @abstract
     * Perform the actual spin up/down command.
     * @discussion
     * This method issues a SCSI Start Stop Unit command to start or stop
     * the device. Because the powerCondition value is only for use with
     * SCSI-3 devices, the current implementation ignores powerCondition.
     * @param start
     * True to start (spin-up) the media; False to stop (spin-down) the media.
     * @param loadEject
     * True to eject; False to not eject. This parameter is applicable only to a stop
     * operation.
     * @param powerCondition
     * The power condition to which the drive should transition. This is a SCSI-3
     * capability; it is presently unused.
     */    
    virtual IOReturn	doStartStop(bool start,bool loadEject,UInt8 powerCondition);

    /*!
     * @function doStop
     * @abstract
     * Stop (spin down) the media.
     * @discussion
     * This method calls doStartStop.
     */    
    virtual IOReturn	doStop(void);

    /*!
     * @function standardFormatMedia
     * @abstract
     * Perform a standard media format operation.
     * @discussion
     * See doFormatMedia for further information.
     */
    virtual IOReturn	standardFormatMedia(UInt64 byteCapacity);

    /*!
     * @function standardSynchronizeCache
     * @abstract
     * Perform a standard Synchronize-Cache operation.
     * @discussion
     * See doFormatMedia for further information.
     */
    virtual IOReturn	standardSynchronizeCache(void);

                                   /*
     * @endgroup
     */
    
    /* Device information : */

    /*!
     * @var _mediaPresent
     * True if media is present; False if media is not present.
     */                                                
    bool		_mediaPresent;

    /*!
     * @var _startStopDisabled
     * True if the start/stop commands are disabled due to an error.
     */                                                
    bool		_startStopDisabled;

    /*!
     * @var _restoreState
     * True if we must restore the device electronics state after a power-up.
     */                                                
    bool		_restoreState;		/* true if we must restore after power-up */                                        };
#endif
