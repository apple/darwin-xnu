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

#include <IOKit/IOLib.h>
#include <IOKit/IOReturn.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/scsi/IOSCSIHDDrive.h>
#include <IOKit/storage/scsi/IOSCSIHDDriveNub.h>

#define	super	IOBasicSCSI
OSDefineMetaClassAndStructors(IOSCSIHDDrive,IOBasicSCSI)

IOReturn
IOSCSIHDDrive::allocateFormatBuffer(UInt8 **buf,UInt32 *len)
{
    /* The default implementation uses no buffer. */

    *buf = 0;
    *len = 0;
    return(kIOReturnSuccess);
}

UInt8
IOSCSIHDDrive::composeFormatBuffer(UInt8 * /* buf */,UInt32 /* buflen */)
{
    return(0);			/* default: no fmtdata buffer to transfer */
}

OSDictionary *
IOSCSIHDDrive::constructDeviceProperties(void)
{
    OSDictionary *propTable;
    OSData *prop;
    char *typeString;

    propTable = OSDictionary::withCapacity(6);
    
    if (propTable) {
        
        prop = OSData::withBytes((void *)(&_vendor),strlen(_vendor));
        if (prop) {
            propTable->setObject("vendor", prop);
        }

        prop = OSData::withBytes((void *)(&_product),strlen(_product));
        if (prop) {
            propTable->setObject("product", prop);
        }

        prop = OSData::withBytes((void *)(&_rev),strlen(_rev));
        if (prop) {
            propTable->setObject("revision", prop);
        }

        typeString = (char *)getDeviceTypeName();
        prop = OSData::withBytes((void *)(typeString),strlen(typeString));
        if (prop) {
            propTable->setObject("device-type", prop);            
        }

#ifdef xxx
        prop = OSData::withBytes((void *)(&_removable),sizeof(bool));
        if (prop) {
            propTable->setObject("removable", prop);
        }

        prop = OSData::withBytes((void *)(&_ejectable),sizeof(bool));
        if (prop) {
            propTable->setObject("ejectable", prop);
        }   
#endif //xxx

    }
    
    return(propTable);
}

UInt32
IOSCSIHDDrive::createFormatCdb(UInt64 /* byteCapacity */,
                            UInt8 *cdb,UInt32 *cdbLength,
                            UInt8 buf[],UInt32 bufLen,
                            UInt32 *maxAutoSenseLength,UInt32 *timeoutSeconds)
{
    struct IOFormatcdb *c;
    UInt8 formatControls;		/* CmpLst & Defect List Format bits */

    c = (struct IOFormatcdb *)cdb;
    
    c->opcode = kIOSCSICommandFormatUnit;
    c->lunbits = 0;
    c->vendor = 0;
    c->interleave_msb = 0;
    c->interleave_lsb = 0;
    c->ctlbyte = 0;

    *cdbLength = 6;

    /* If we are to use a format buffer, set it up: */
    
    if (buf != NULL) {
        formatControls = composeFormatBuffer(buf,bufLen);
        c->lunbits |= (formatControls | 0x10);	/* data transfer will occur */
    }
    
    *maxAutoSenseLength = sizeof(SCSISenseData);      	/* do the sense */
    *timeoutSeconds = 0;			/* infinitely long time */

    return(0);
}

IOService *
IOSCSIHDDrive::createNub(void)
{
    IOService *nub;

//    IOLog("%s[IOSCSIHDDrive]::createNub\n",getName());
    
    /* Instantiate a nub so a generic driver can match above us. */

    nub = instantiateNub();
    if (nub == NULL) {
        IOLog("%s[IOSCSIHDDrive]::createNub; nub didn't instantiate\n",getName());
        return(NULL);
    }

    nub->init();
    
    if (!nub->attach(this)) {
        IOPanic("IOSCSIHDDrive::createNub; couldn't attach IOSCSIHDDriveNub");
    }
    
    nub->registerService();
        
    return(nub);
}

void
IOSCSIHDDrive::deleteFormatBuffer(UInt8 * /* buf */, UInt32 /* buflen */)
{
    /* The default implementation has no buffer to free. */
}

bool
IOSCSIHDDrive::deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 * /*score*/)
{
    if ((_inqBuf[0] & 0x1f) == kIOSCSIDeviceTypeDirectAccess) {
        return(true);
    } else {
        return(false);			/* we don't handle other devices */        
    }
}

IOReturn
IOSCSIHDDrive::doAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{
    return(standardAsyncReadWrite(buffer,block,nblks,completion));
}

IOReturn
IOSCSIHDDrive::doEjectMedia(void)
{
    /* Spin down, eject, and leave power alone: */
    
    return(doStartStop(false,true,IOStartStopcdb::P_NOCHANGE));
}

IOReturn
IOSCSIHDDrive::doFormatMedia(UInt64 byteCapacity)
{
    return(standardFormatMedia(byteCapacity));
}

UInt32
IOSCSIHDDrive::doGetFormatCapacities(UInt64 * capacities,
                                            UInt32   capacitiesMaxCount) const
{
    if ((capacities != NULL) && (capacitiesMaxCount > 0)) {
        *capacities = _blockSize * (_maxBlock + 1);
        return(1);
    } else {
        return(0);        
    }
}

/* We issue a simple Prevent/Allow command to lock or unlock the media: */
IOReturn
IOSCSIHDDrive::doLockUnlockMedia(bool doLock)
{
    struct context *cx;
    struct IOPrevAllowcdb *c;
    IOSCSICommand *req;
    SCSICDBInfo   scsiCDB;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;
    
    bzero( &scsiCDB, sizeof(scsiCDB) );

    c = (struct IOPrevAllowcdb *)&scsiCDB.cdb;

    c->opcode = kIOSCSICommandPreventAllow;
    c->lunbits = 0;
    c->reserved1 = 0;
    c->reserved2 = 0;
    
    if (doLock) {
        c->prevent = 0x01;		/* prevent removal from device */
    } else {
        c->prevent = 0x00;		/* allow   removal from device */      
    }

    c->ctlbyte = 0;

    scsiCDB.cdbLength = 6;

    req->setCDB( &scsiCDB );    

    cx->memory = 0;
    
    req->setPointers( cx->memory, 0, false );
    
    queueCommand(cx,kSync,getLockUnlockMediaPowerState());	/* queue the operation, sleep awaiting power */

    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSIHDDrive::doStart(void)
{
    return(doStartStop(true,false,IOStartStopcdb::P_ACTIVE));
}

IOReturn
IOSCSIHDDrive::doStop(void)
{
    return(doStartStop(false,false,IOStartStopcdb::P_NOCHANGE));
}

IOReturn
IOSCSIHDDrive::doStartStop(bool start,bool loadEject,UInt8 powerCondition)
{
    struct context *cx;
    struct IOStartStopcdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;
    UInt32 powerLevel;			/* what power level we need to be in */

    /* Issue a Start/Stop Unit command. */

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    powerLevel = getStopPowerState();		/* assume we're spinning down */
    req = cx->scsireq;
    
    bzero( &scsiCDB, sizeof(SCSICDBInfo) );

    c = (struct IOStartStopcdb *)&scsiCDB.cdb;
    c->opcode = kIOSCSICommandStartStopUnit;
    c->lunImmed = 0;
    c->reserved1 = 0;
    c->reserved2 = 0;
    c->controls = powerCondition;
    c->controls = 0;			/* xxx powerCondition is a SCSI-3 thing */
    if (loadEject) {
        c->controls |= IOStartStopcdb::C_LOEJ;
        powerLevel = getEjectPowerState();	/* let subclass decide what we need */
    };
    if (start) {
        c->controls |= IOStartStopcdb::C_SPINUP;
        powerLevel = getStartPowerState();
    }
    c->ctlbyte = 0;

    scsiCDB.cdbLength = 6;

    req->setCDB( &scsiCDB );
    req->setTimeout( 30000 );

    cx->memory = 0;
    
    req->setPointers( cx->memory, 0, false );
    
    queueCommand(cx,kSync,powerLevel);	/* queue the operation, sleep awaiting power */

    result = simpleSynchIO(cx);

    deleteContext(cx);
    return(result);
}

IOReturn
IOSCSIHDDrive::doSynchronizeCache(void)
{
    return(standardSynchronizeCache());
}

IOReturn
IOSCSIHDDrive::doSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    return(standardSyncReadWrite(buffer,block,nblks));
}

const char *
IOSCSIHDDrive::getDeviceTypeName(void)
{
    return(kIOBlockStorageDeviceTypeGeneric);
}

UInt32
IOSCSIHDDrive::getEjectPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIHDDrive::getExecuteCDBPowerState(void)
{
    return(kAllOn);
}

UInt32
IOSCSIHDDrive::getFormatMediaPowerState(void)
{
    return(kAllOn);
}

UInt32
IOSCSIHDDrive::getInitialPowerState(void)
{
    return(kAllOn);
}

UInt32
IOSCSIHDDrive::getInquiryPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIHDDrive::getLockUnlockMediaPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIHDDrive::getReadCapacityPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIHDDrive::getReadWritePowerState(void)
{
    return(kAllOn);
}

UInt32
IOSCSIHDDrive::getReportWriteProtectionPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIHDDrive::getStartPowerState(void)
{
    return(kElectronicsOn);
}

UInt32
IOSCSIHDDrive::getStopPowerState(void)
{
    return(kElectronicsOn);		/* we don't have to be spinning to spin down */
}

UInt32
IOSCSIHDDrive::getSynchronizeCachePowerState(void)
{
    return(kAllOn);
}

UInt32
IOSCSIHDDrive::getTestUnitReadyPowerState(void)
{
    return(kElectronicsOn);
}

bool
IOSCSIHDDrive::init(OSDictionary * properties)
{
    _mediaPresent	= false;
    _startStopDisabled	= false;
    
    return(super::init(properties));
}

IOService *
IOSCSIHDDrive::instantiateNub(void)
{
    IOService *nub;

    /* Instantiate a nub so a generic driver can match above us. */
    
    nub = new IOSCSIHDDriveNub;
    return(nub);
}

bool
IOSCSIHDDrive::powerTickle(UInt32 desiredState)
{
    return(activityTickle(kIOPMSuperclassPolicy1,desiredState));
}

IOReturn
IOSCSIHDDrive::reportMediaState(bool *mediaPresent,bool *changed)
{
    struct context *cx;
    struct IOTURcdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    SCSIResults scsiResults;
    IOReturn result;
    UInt8 status;
    UInt8 senseKey;
    
    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;
    
    bzero( &scsiCDB, sizeof(scsiCDB) );

    c = (struct IOTURcdb *)&scsiCDB.cdb;
    c->opcode = kIOSCSICommandTestUnitReady;
    c->lunbits = 0;
    c->reserved1 = 0;
    c->reserved2 = 0;
    c->reserved3 = 0;
    c->ctlbyte = 0;

    scsiCDB.cdbLength = 6;

    req->setCDB( &scsiCDB );
    req->setPointers( cx->senseDataDesc, 255, false, true );

    req->setTimeout( 5000 );

    cx->memory = 0;

    req->setPointers( cx->memory, 0, false );

/**
    IOLog("IOSCSIHDDrive::reportMediaState: mp=%08x,ch=%08x\n",
          (int)mediaPresent,(int)changed);
    IOLog("IOSCSIHDDrive::reportMediaState: doing TUR\n");
**/

    queueCommand(cx,kSync,getTestUnitReadyPowerState());
    result = simpleSynchIO(cx);
  
    req->getResults( &scsiResults );
    
    status = scsiResults.scsiStatus;

/**
    IOLog("%s[IOSCSIHDDrive]::reportMediaState; result=%s, status=%02x,sense=%02x\n",
          getName(),stringFromReturn(result),status,cx->senseData->senseKey
          );
**/
    
    if (result == kIOReturnSuccess) {		/* TUR succeeded; device is ready */
        
        *mediaPresent = true;
        *changed = (*mediaPresent != _mediaPresent); /* report if it's changed */
        _mediaPresent = true;			/* remember current state */
        result = kIOReturnSuccess;

    } else {					/* TUR failed; check sense key */

        if ( scsiResults.requestSenseDone == true ) {
            senseKey = cx->senseData->senseKey;

            if (senseKey == 0x02) {			/* device says "not ready" */
                *mediaPresent = false;
                *changed = (*mediaPresent != _mediaPresent); /* report if it's changed */
                _mediaPresent = false;			/* remember current state */
                result = kIOReturnSuccess;

            } else {				/* funky sense key? forget it. */

                *mediaPresent = false;
                *changed = (*mediaPresent != _mediaPresent); /* report if it's changed */
                _mediaPresent = false;			/* remember current state */
                result = kIOReturnIOError;
/**
                IOLog("%s[IOSCSIHDDrive]:: reportMediaState; funky sense key %d\n",
                      getName(),senseKey);
 **/
            }
        } else {				/* autosense not done! */

            /* This condition has been observed with the Matsushita PD-2 DVD-RAM on the
             * Curio (external) bus on an 8500. I can't figure out why we get a good status
             * but no autosense (after going through Unit-Attention.) We ignore the current
             * media check and it'll operate normally on the next pass through.
             */
/**
            IOLog("%s[IOSCSIHDDrive]:: reportMediaState; autosense not done: ",getName());
            IOLog("result = '%s', status = %d, senseKey = %d\n",
                  stringFromReturn(result),status,cx->senseData->senseKey);
**/
            *mediaPresent = _mediaPresent;
            *changed = false;
            result = kIOReturnSuccess;
        }
    }

    if (*changed && *mediaPresent) {
        _readCapDone = false;
        _blockSize = 0;
        _maxBlock = 0;
    }

    deleteContext(cx);

#ifndef DISKPM
    if (*changed && *mediaPresent)
        doStart();
#endif

/**
    if (result != kIOReturnSuccess) {
        IOLog("%s[IOSCSIHDDrive]:: reportMediaState; returning %d %x '%s'\n",
            getName(),result,result,stringFromReturn(result));
    }
**/
    return(result);
}

IOReturn
IOSCSIHDDrive::restoreElectronicsState(void)
{
    return(kIOReturnSuccess);
}

/* The standard completion for a doAsyncReadWrite operation. We fire it
 * up to our target, the generic driver.
 */
void
IOSCSIHDDrive::RWCompletion(struct context *cx)
{
    SCSIResults scsiResults;

    cx->scsireq->getResults( &scsiResults );

    IOStorage::complete(cx->completion,  
                        scsiResults.returnCode,
                        scsiResults.bytesTransferred);


    /* Attempt to dequeue and execute any waiting commands: */

    dequeueCommands();
}

IOReturn
IOSCSIHDDrive::saveElectronicsState(void)
{
    return(kIOReturnSuccess);
}

static IOPMPowerState ourPowerStates[kNumberOfPowerStates] = {
    {1,IOPMNotAttainable,0,0,0,0,0,0,0,0,0,0},		/* state 00 kAllOff */
    {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0},		/* state 01 kElectronicsOn */
    {1,0,0,IOPMPowerOn,0,0,0,0,0,0,0,0}			/* state 02 kAllOn */
};

IOReturn
IOSCSIHDDrive::standardFormatMedia(UInt64 byteCapacity)
{
    struct context *cx;
    UInt8 *fmtbuf;
    IOReturn result;
    IOSCSICommand *req;
    SCSICDBInfo	scsiCDB;
    UInt32 transferLength;
    UInt32 senseLength;
    UInt32 timeoutSeconds;
    
    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }
    
    req = cx->scsireq;
    
    /* Allow a subclass to construct the cdb and return an optional
     * memory buffer address for defect lists, etc.
     */

    result = allocateFormatBuffer(&fmtbuf,&transferLength);
    if (result != kIOReturnSuccess) {
        return(result);
    }
    
    bzero( &scsiCDB, sizeof(scsiCDB) );

    scsiCDB.cdbFlags |= createFormatCdb(byteCapacity,(UInt8 *)&scsiCDB.cdb,&scsiCDB.cdbLength,
                    		fmtbuf,transferLength,
                    		&senseLength,
                    		&timeoutSeconds);

    req->setCDB( &scsiCDB );
    req->setPointers( cx->senseDataDesc, senseLength, false, true );
    req->setTimeout( timeoutSeconds * 1000 );  

    /* If we have a buffer to transfer, create a Memory Descriptor for it: */

    if ((fmtbuf != NULL) && (transferLength != 0)) {
        cx->memory = IOMemoryDescriptor::withAddress((void *)fmtbuf,
                                                     transferLength,
                                                     kIODirectionOut);
    }
    
    req->setPointers( cx->memory, transferLength, true ); 
    queueCommand(cx,kSync,getFormatMediaPowerState());	/* queue the operation, sleep awaiting power */

    result = simpleSynchIO(cx);		/* issue a simple command */
    
    /* Free the format buffer, if any: */
    
    deleteFormatBuffer(fmtbuf,transferLength);
    
    deleteContext(cx);

    return(result);
}

IOReturn
IOSCSIHDDrive::standardSynchronizeCache(void)
{
    struct context *cx;
    struct IOSyncCachecdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    IOReturn result;
    
    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    req = cx->scsireq;
    bzero( &scsiCDB, sizeof(scsiCDB) );    

    c = (struct IOSyncCachecdb *)&scsiCDB.cdb;

    c->opcode = kIOSCSICommandSynchronizeCache;
    c->lunbits = 0;
    c->lba_3 = 0;			/* if zero, start at block zero */
    c->lba_2 = 0;
    c->lba_1 = 0;
    c->lba_0 = 0;
    c->reserved = 0;
    c->nblks_msb = 0;			/* if zero, do all blocks */
    c->nblks_lsb = 0;
    c->ctlbyte = 0;
    
    scsiCDB.cdbLength = 10;

    req->setCDB( &scsiCDB );

    cx->memory = 0;

    req->setPointers( cx->memory, 0, false );

    /* We assume there will be some data in the drive's cache, so we force the
     * drive to be running before we issue this command.
     */

    queueCommand(cx,kSync,getSynchronizeCachePowerState());	/* queue the operation, sleep awaiting power */
    
    result = simpleSynchIO(cx);

    deleteContext(cx);

    return(result);    
}

bool
IOSCSIHDDrive::start(IOService *provider)
{
    IOService *nub;

    if (!super::start(provider)) {
        return(false);
    }

//    IOLog("%s[IOSCSIHDDrive]::start\n",getName());

    /* Initialize and set up to perform Power Management: */
    
    PMinit();
    _restoreState = false;
#ifdef notyet	// don't register for PM yet till we handle queuing requests!
    IOPMRegisterDevice(pm_vars->ourName,this);	// join the power management tree
#endif
    registerPowerDriver(this,ourPowerStates,kNumberOfPowerStates);	// export power states
    
    nub = createNub();
    if (nub == NULL) {
        return(false);
    } else {
        return(true);
    }
}

// **********************************************************************************
// maxCapabilityForDomainState
//
// This simple device needs only power.  If the power domain is supplying
// power, the disk can go to its highest state.  If there is no power
// it can only be in its lowest state, which is off.
// **********************************************************************************

unsigned long
IOSCSIHDDrive::maxCapabilityForDomainState(IOPMPowerFlags domainState)
{
    if (domainState &  IOPMPowerOn) {
        return(kAllOn);
    } else {
        return(kAllOff);
    }
}

// **********************************************************************************
// powerStateForDomainState
//
// The power domain may be changing state. If power is ON in its new
// state, we will be on, too. If domain power is OFF, we are off.
// **********************************************************************************
unsigned long
IOSCSIHDDrive::powerStateForDomainState(IOPMPowerFlags domainState)
{
    if (domainState & IOPMPowerOn) {
        return(kAllOn);		/* xxx might be kElectronicsOn if drive not spun up */
    } else {
        return(kAllOff);
    }
}

// **********************************************************************************
// initialPowerStateForDomainState
//
// Our parent wants to know what our initial power state is.  If power is ON in the
// domain, we are in state kElectronicsOn or kAllOn. If domain power is OFF, we are off.
// **********************************************************************************
unsigned long
IOSCSIHDDrive::initialPowerStateForDomainState(IOPMPowerFlags domainState)
{
    if (domainState & IOPMPowerOn) {
        return(getInitialPowerState());		/* report whether it's spinning on startup */
    } else {
        return(kAllOff);
    }
}

// **********************************************************************************
// setPowerState
//
// Someone has decided to change the disk state. We perform the change here.
// **********************************************************************************
IOReturn
IOSCSIHDDrive::setPowerState(unsigned long powerStateOrdinal,IOService *)
{
    IOReturn result;

    result = kIOReturnSuccess;
    
    /* All we do in the default implementation is spin up and down. If the drive reports an
     * error to a start/stop command, we don't bother attempting to issue those commands again.
     *
     * xxx Question: What should we return? Success? or an error meaning "we didn't do it!"
     */
    switch (powerStateOrdinal) {

        case kElectronicsOn :	/* spin down if necessary */
                                if (pm_vars->myCurrentState == kAllOn) {
                                    if (!_startStopDisabled) {
                                        result = doStop();
                                        if (result != kIOReturnSuccess) {
                                            _startStopDisabled = true;
                                            result = kIOReturnSuccess;
                                        }
                                    }
                                }
                                break;

        case kAllOn :		/* spin up if necessary */
                                if (pm_vars->myCurrentState == kElectronicsOn) {
                                    if (!_startStopDisabled) {
                                        result = doStart();
                                        if (result != kIOReturnSuccess) {
                                            _startStopDisabled = true;
                                            result = kIOReturnSuccess;
                                        }
                                    }
                                }
                                break;

        default:		/* we don't do other states */
                                result = kIOReturnSuccess;
                                break;

    }

    return(result);
}

// **********************************************************************************
/* We get called here as an advisory that the power state will change. If we are coming up
 * from the all-off state, remember to restore the electronics state when we later power up.
 * If we are powering-down the electronics, save any required state now.
 */
IOReturn
IOSCSIHDDrive::powerStateWillChangeTo(unsigned long,unsigned long stateOrdinal,IOService *)
{
    if ((pm_vars->myCurrentState == kAllOff) &&
        (stateOrdinal > kAllOff)) {			/* we're powering up from all-off */
        _restoreState = true;
    }
    
    if ((stateOrdinal == kAllOff) &&
        (pm_vars->myCurrentState > kAllOff)) {		/* we're powering down to all-off */
	saveElectronicsState();
    }
    
    return(IOPMAckImplied);
}

// **********************************************************************************
/* We get called here when power has successfully changed state. */
IOReturn
IOSCSIHDDrive::powerStateDidChangeTo(unsigned long,unsigned long stateOrdinal,IOService*)
{
    IOReturn result;
    
    /* If we must restore the electronics state, do it now. */
    
    if (_restoreState) {
        result = restoreElectronicsState();
        _restoreState = false;
    }

    /* If we have powered up into a state that can execute commands, release any queued
     * requests that were awaiting the power change.
     */

    if (stateOrdinal > kAllOff) {
        dequeueCommands();
    }
    
    return IOPMAckImplied;
}
