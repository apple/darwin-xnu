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
 *	IOATAStandardDevice.cpp
 *
 */

#include <IOKit/IOSyncer.h> 
#include <IOKit/ata/IOATAStandardInterface.h>
#include <IOKit/ata/ata-standard/ATAStandardPrivate.h>

#undef  super
#define super IOATADevice

#ifndef MIN
#define MIN(a,b) ((a <= b) ? a : b)
#endif

#define round(x,y) (((int)(x) + (y) - 1) & ~((y)-1))

extern EndianTable 		AppleIdentifyEndianTable[];

extern UInt32			AppleNumPIOModes;
extern ATAModeTable 		ApplePIOModes[];
extern UInt32			AppleNumDMAModes;
extern ATAModeTable		AppleDMAModes[];
extern UInt32			AppleNumUltraModes;
extern ATAModeTable		AppleUltraModes[];

OSDefineMetaClassAndAbstractStructors( IOATADevice, IOCDBDevice )
OSDefineMetaClassAndStructors( IOATAStandardDevice, IOATADevice )

/*
 *
 *
 *
 */ 
bool IOATAStandardDevice::init( IOATAStandardController *forController, ATAUnit forUnit )
{
    ATATaskfile		taskfile;
    ATACDBInfo		ataCDB;

    controller  = forController;     
    unit   = forUnit;

    target      = &controller->targets[unit];

    queue_init( &deviceList );     
    queue_init( &bypassList );       
    queue_init( &activeList );      
    queue_init( &abortList  );  
    queue_init( &cancelList ); 

    clientSem = IORWLockAlloc();
    if ( clientSem == 0 )
    {
        return false;
    }

    if ( super::init() == false )
    {
        return false;
    }

    if ( controller->controllerInfo.devicePrivateDataSize != 0 )
    {
        devicePrivateData = IOMallocContiguous( controller->controllerInfo.devicePrivateDataSize, 16, 0 );
        if ( devicePrivateData == 0 )
        {
            return false;
        }
    }

    bzero( &ataCDB, sizeof(ataCDB) );
    
    probeCmd = allocCommand(kIOATAStandardDevice, 0);
    if ( probeCmd == 0 )
    {
        return false;
    }

    abortCmd = allocCommand(kIOATAStandardDevice, 0);
    if ( abortCmd == 0 )
    {
        return false;
    }
    abortCmd->setTimeout( kATAAbortTimeoutmS );    
    
    cancelCmd = allocCommand(kIOATAStandardDevice, 0);
    if ( cancelCmd == 0 )
    {
        return false;
    }
    cancelCmd->setTimeout( 0 );    
    cancelCmd->cmdType = kATACommandCancel;

    reqSenseCmd = allocCommand(kIOATAStandardDevice, 0);
    if ( reqSenseCmd == 0 )
    {
        return false;
    }    

    bzero( &taskfile, sizeof(taskfile) );
    taskfile.protocol = kATAProtocolATAPIPIO;
    taskfile.tagType  = kATATagTypeNone;

    taskfile.resultmask = ATARegtoMask( kATARegStatus );

    taskfile.regmask    = ATARegtoMask( kATARegATAPIFeatures )  
                        | ATARegtoMask( kATARegATAPIByteCountLow )  	
                        | ATARegtoMask( kATARegATAPIByteCountHigh ) 	
                        | ATARegtoMask( kATARegATAPIDeviceSelect ) 	
                        | ATARegtoMask( kATARegATAPICommand );

    taskfile.ataRegs[kATARegATAPIFeatures]       = 0;
    taskfile.ataRegs[kATARegATAPIByteCountLow]   = 0xfe;
    taskfile.ataRegs[kATARegATAPIByteCountHigh]  = 0xff;
    taskfile.ataRegs[kATARegATAPIDeviceSelect]   = kATAModeLBA | (getUnit() << 4);
    taskfile.ataRegs[kATARegATAPICommand]        = kATACommandATAPIPacket;

    reqSenseCmd->setTaskfile( &taskfile );

    ataCDB.cdbLength = 12;
    ataCDB.cdb[0]    = kATAPICmdRequestSense;

    reqSenseCmd->setTimeout( kATAReqSenseTimeoutmS );    
    reqSenseCmd->cmdType = kATACommandReqSense;
    reqSenseCmd->setCDB( &ataCDB );

    deviceGate = IOCommandGate::commandGate( this, (IOCommandGate::Action) &IOATAStandardDevice::receiveCommand );
    if ( deviceGate == 0 )
    {
        return false;
    }    
    
    if ( controller->workLoop->addEventSource( deviceGate ) != kIOReturnSuccess )
    {
        return false;
    }

    commandLimitSave = commandLimit = 1;

    idleNotifyActive = false;

    normalQHeld  = 0;
    bypassQHeld  = 0;
     
    currentTiming = kATATimingPIO;

    return true;
}

IOReturn IOATAStandardDevice::probeDevice()
{
    OSDictionary		*propTable = 0;

    if ( doIdentify( (void **)&identifyData ) != kIOReturnSuccess )
    {
        goto probeDevice_error;
    }

    if ( deviceType == kATADeviceATA )
    {
        doSpinUp();
    }

    else if ( deviceType == kATADeviceATAPI )
    {
        atapiPktInt = ((identifyData->generalConfiguration & kATAPIPktProtocolIntDRQ) != 0);
      
        if ( doInquiry( (void **)&inquiryData ) != kIOReturnSuccess )
        {
            goto probeDevice_error;
        }
    }      

    if ( getATATimings() != true )
    {
        goto probeDevice_error;
    }
    
    if ( maxTags != 0 )
    {
        tagArraySize = round( maxTags, 32 ) / 8;
        tagArray = (UInt32 *)IOMalloc( tagArraySize );
        if ( tagArray == 0 )
        {
            goto probeDevice_error;
        }
        bzero( tagArray, tagArraySize );
    }
    
    propTable = createProperties();
    if ( !propTable )
    {
        goto probeDevice_error;
    }
    
    setPropertyTable( propTable );

    propTable->release();

    close( this, 0 );

    return true; 

probeDevice_error: ;
    close( this, 0 );
    return false;
}

/*
 *
 *
 *
 */
ATADeviceType IOATAStandardDevice::probeDeviceType()
{
    ATATaskfile         taskfile;
    ATAResults          results;

    bzero( (void *)&taskfile, sizeof(taskfile) );

    taskfile.protocol     = kATAProtocolSetRegs;
    taskfile.regmask      = ATARegtoMask(kATARegDriveHead);  

    taskfile.resultmask   = ATARegtoMask(kATARegSectorCount)
                          | ATARegtoMask(kATARegSectorNumber)
                          | ATARegtoMask(kATARegCylinderLow)
                          | ATARegtoMask(kATARegCylinderHigh)
                          | ATARegtoMask(kATARegStatus);

    taskfile.flags	  = kATACmdFlagTimingChanged;

    taskfile.ataRegs[kATARegDriveHead] = kATAModeLBA | (getUnit() << 4);

    probeCmd->setQueueInfo();
    probeCmd->setTaskfile( &taskfile );
    probeCmd->execute();

    if ( probeCmd->getResults( &results ) != kIOReturnSuccess )     
    {
        return (deviceType = kATADeviceNone);
    }
 
    if ( results.ataRegs[kATARegSectorCount] == kATASignatureSectorCount
          && results.ataRegs[kATARegSectorNumber] == kATASignatureSectorNumber
             && results.ataRegs[kATARegCylinderLow] == kATASignatureCylinderLow
                && results.ataRegs[kATARegCylinderHigh] == kATASignatureCylinderHigh )
    { 
        if ( !(results.ataRegs[kATARegStatus] & kATAStatusBSY)  
                 && (results.ataRegs[kATARegStatus] & kATAStatusDRDY) )
        {
            return (deviceType = kATADeviceATA);
        }
    }
            
    if ( results.ataRegs[kATARegCylinderLow] == kATAPISignatureCylinderLow
                && results.ataRegs[kATARegCylinderHigh] == kATAPISignatureCylinderHigh )
    {
        return (deviceType = kATADeviceATAPI);
    }       
  
    return (deviceType = kATADeviceNone);
}


/*
 *
 *
 *
 */
IOReturn IOATAStandardDevice::doSpinUp()
{
    void		*buffer = NULL;
    IOReturn		rc;

    rc = doSectorCommand( kATACommandReadSector, 0, 1, &buffer );

    if ( rc != kIOReturnSuccess )
    {
        return rc;
    }

    IOFree( buffer, 512 );

    return rc ; 
}    

/*
 *
 *
 *
 */
IOReturn IOATAStandardDevice::doIdentify( void **dataPtr )
{   
    ATACommand		ataCmd;
    IOReturn		rc;
 
    ataCmd = (deviceType == kATADeviceATA) ? kATACommandIdentify : kATACommandATAPIIdentify;

    rc = doSectorCommand( ataCmd, 0, 1, dataPtr );

    if ( rc != kIOReturnSuccess )
    {
        return rc;
    }
 
    endianConvertData( *dataPtr, AppleIdentifyEndianTable );

    return rc;
}



/*
 *
 *
 *
 */
IOReturn IOATAStandardDevice::doSectorCommand( ATACommand ataCmd, UInt32 ataLBA, UInt32 ataCount, void **dataPtr )
{
    ATATaskfile			taskfile;
    ATAResults			result;
    IOMemoryDescriptor  	*desc;
    UInt32			size;
    void			*data;
    UInt32			i;
    IOReturn			rc;

    *dataPtr = NULL;

    size = ataCount * 512;

    if ( !(data = (void *)IOMalloc(size)) )
    {
        return kIOReturnNoMemory;
    }

    bzero( &taskfile, sizeof(taskfile) );

    desc = IOMemoryDescriptor::withAddress( data, size, kIODirectionIn );
    if ( desc == NULL )
    {
        rc = kIOReturnNoMemory;
        goto doSectorCommand_error;
    }

    
    taskfile.protocol    		= kATAProtocolPIO;
    taskfile.regmask      		= ATARegtoMask(kATARegDriveHead)
                          		| ATARegtoMask(kATARegSectorCount)
                          		| ATARegtoMask(kATARegSectorNumber)
                          		| ATARegtoMask(kATARegCylinderLow)
                          		| ATARegtoMask(kATARegCylinderHigh)
                          		| ATARegtoMask(kATARegFeatures)
                          		| ATARegtoMask(kATARegCommand);


    taskfile.resultmask			= ATARegtoMask(kATARegError) 
                                        | ATARegtoMask(kATARegStatus);

    taskfile.ataRegs[kATARegSectorCount]   = ataCount;
    taskfile.ataRegs[kATARegSectorNumber]  = ataLBA         & 0xff;
    taskfile.ataRegs[kATARegCylinderLow]   = (ataLBA >> 8)  & 0xff;
    taskfile.ataRegs[kATARegCylinderHigh]  = (ataLBA >> 16) & 0xff;
    taskfile.ataRegs[kATARegDriveHead]     = (ataLBA >> 24) & 0x0f;

    taskfile.ataRegs[kATARegDriveHead]   |= kATAModeLBA | (getUnit() << 4);
    taskfile.ataRegs[kATARegCommand]      = ataCmd;

    probeCmd->setQueueInfo();

    for ( i = 0; i < 2; i++ )
    { 
        probeCmd->setTimeout( 25000 );
        probeCmd->setTaskfile( &taskfile );
        probeCmd->setPointers( desc, size, false ); 
        probeCmd->execute();
    
        rc  = probeCmd->getResults( &result );
        if ( rc == kIOReturnSuccess )
        {
            break;
        }
    }


doSectorCommand_error: ;

    desc->release();

    if ( rc != kIOReturnSuccess )
    {
        IOFree( data, size );
        return result.returnCode;
    }

    *dataPtr = data;

    return kIOReturnSuccess;
}


/*
 *
 *
 */
IOReturn IOATAStandardDevice::doInquiry( void **dataPtr )
{
    ATATaskfile			taskfile;
    ATACDBInfo			atapiCmd;
    ATAResults			result;
    void                        *data;
    IOMemoryDescriptor  	*desc;
    UInt32			size = sizeof(ATAPIInquiry);

    *dataPtr = 0;

    if ( !(data = (void *)IOMalloc(size)) )
    {
        return kIOReturnNoMemory;
    }

    bzero( data, size );
    bzero( &taskfile, sizeof(taskfile) );
    bzero( &atapiCmd, sizeof(atapiCmd) );

    desc = IOMemoryDescriptor::withAddress( data, size, kIODirectionIn );
    
    taskfile.protocol   		= kATAProtocolATAPIPIO;
    taskfile.regmask      		= ATARegtoMask(kATARegATAPIDeviceSelect) 
                          		| ATARegtoMask(kATARegATAPICommand)
                                        | ATARegtoMask(kATARegATAPIByteCountLow)
                                        | ATARegtoMask(kATARegATAPIByteCountHigh)
                                        | ATARegtoMask(kATARegATAPIFeatures);
    taskfile.ataRegs[kATARegATAPIDeviceSelect]  = kATAModeLBA | (getUnit() << 4);
    taskfile.ataRegs[kATARegATAPICommand]       = kATACommandATAPIPacket;
    taskfile.ataRegs[kATARegATAPIFeatures]      = 0;
    taskfile.ataRegs[kATARegATAPIByteCountLow]  = 0xfe;
    taskfile.ataRegs[kATARegATAPIByteCountHigh] = 0xff;

    atapiCmd.cdbLength = 12;  // Fix 16 byte cmdpkts??
    atapiCmd.cdb[0]    = 0x12;
    atapiCmd.cdb[4]    = size;

    probeCmd->setCDB( &atapiCmd );
    probeCmd->setTaskfile( &taskfile );
    probeCmd->setPointers( desc, size, false );
    probeCmd->setTimeout( 5000 ); 
    probeCmd->setQueueInfo();
    probeCmd->execute();
 
    if ( probeCmd->getResults(&result) == kIOReturnSuccess )
    {
        *dataPtr = data;
    }
    else if ( ( result.returnCode == kIOReturnUnderrun ) &&
              ( result.bytesTransferred >= 36 ) )
    {
        // The standard INQUIRY contain 36 required bytes,
        // the rest is optional and vendor specific.

        result.returnCode = kIOReturnSuccess;
        *dataPtr          = data;
    }
    else
    {
        IOFree( data, size );
    }

    desc->release();

    return result.returnCode;
}

/*
 *
 *
 */
bool IOATAStandardDevice::getDeviceCapacity( UInt32 *blockMax, UInt32 *blockSize )
{
    UInt32		i;
    UInt32		data[2];

    if ( deviceType == kATADeviceATA )
    {
        if ( identifyData != NULL )
        {
            *blockMax = *(UInt32 *)identifyData->userAddressableSectors - 1;
            *blockSize  = 512;
            return true;
        }
    }
    
    if ( deviceType == kATADeviceATAPI )
    {
        for ( i=0; i < 8; i++ )
        {
            if ( doTestUnitReady() == kIOReturnSuccess )
            {
                break;
            }
        }

        if ( doReadCapacity( data ) == kIOReturnSuccess )
        {
            *blockMax   = OSSwapBigToHostInt32( data[0] );
            *blockSize  = OSSwapBigToHostInt32( data[1] );
            return true;
        }      
    }

    return false;
}


IOReturn IOATAStandardDevice::doTestUnitReady()
{
    ATATaskfile            taskfile;
    ATACDBInfo             atapiCmd;
    ATAResults             result;

    bzero( &taskfile, sizeof(taskfile) );
    bzero( &atapiCmd, sizeof(atapiCmd) );

    taskfile.protocol   		= kATAProtocolATAPIPIO;

    taskfile.regmask      		= ATARegtoMask(kATARegATAPIDeviceSelect) 
                          		| ATARegtoMask(kATARegATAPICommand)
                                        | ATARegtoMask(kATARegATAPIByteCountLow)
                                        | ATARegtoMask(kATARegATAPIByteCountHigh)
                                        | ATARegtoMask(kATARegATAPIFeatures);

    taskfile.ataRegs[kATARegATAPIDeviceSelect]  = kATAModeLBA | (getUnit() << 4);
    taskfile.ataRegs[kATARegATAPICommand]       = kATACommandATAPIPacket;
    taskfile.ataRegs[kATARegATAPIFeatures]      = 0;
    taskfile.ataRegs[kATARegATAPIByteCountLow]  = 0xfe;
    taskfile.ataRegs[kATARegATAPIByteCountHigh] = 0xff;

    atapiCmd.cdbLength = 12;  // Fix 16 byte cmdpkts??
    atapiCmd.cdb[0]    = 0x00;

    probeCmd->setCDB( &atapiCmd );
    probeCmd->setTaskfile( &taskfile );
    probeCmd->setPointers( (IOMemoryDescriptor *)NULL, 0, false ); 
    probeCmd->setTimeout( 5000 );
    probeCmd->setQueueInfo();
    probeCmd->execute();
    probeCmd->getResults(&result);
 
    return result.returnCode;
}


/*
 *
 *
 */
IOReturn IOATAStandardDevice::doReadCapacity( void *data )
{
    ATATaskfile			taskfile;
    ATACDBInfo			atapiCmd;
    ATAResults			result;
    IOMemoryDescriptor  	*dataDesc;
    UInt32			size = 8;


    bzero( &taskfile, sizeof(taskfile) );
    bzero( &atapiCmd, sizeof(atapiCmd) );

    dataDesc = IOMemoryDescriptor::withAddress( data, size, kIODirectionIn );
    if ( dataDesc == NULL )
    {
        return kIOReturnNoMemory;
    }
    
    taskfile.protocol   		= kATAProtocolATAPIPIO;
    taskfile.regmask      		= ATARegtoMask(kATARegATAPIDeviceSelect) 
                          		| ATARegtoMask(kATARegATAPICommand)
                                        | ATARegtoMask(kATARegATAPIByteCountLow)
                                        | ATARegtoMask(kATARegATAPIByteCountHigh)
                                        | ATARegtoMask(kATARegATAPIFeatures);
    taskfile.ataRegs[kATARegATAPIDeviceSelect]  = kATAModeLBA | (getUnit() << 4);
    taskfile.ataRegs[kATARegATAPICommand]       = kATACommandATAPIPacket;
    taskfile.ataRegs[kATARegATAPIFeatures]      = 0;
    taskfile.ataRegs[kATARegATAPIByteCountLow]  = 0xfe;
    taskfile.ataRegs[kATARegATAPIByteCountHigh] = 0xff;

    atapiCmd.cdbLength = 12;  // Fix 16 byte cmdpkts??
    atapiCmd.cdb[0]    = 0x25;

    probeCmd->setCDB( &atapiCmd );
    probeCmd->setTaskfile( &taskfile );
    probeCmd->setPointers( dataDesc, size, false ); 
    probeCmd->setTimeout( 5000 );
    probeCmd->setQueueInfo();
    probeCmd->execute();
    
    probeCmd->getResults(&result);

    dataDesc->release();
 
    return result.returnCode;
}

/*
 *
 *
 */ 
bool IOATAStandardDevice::getTimingsSupported( ATATimingProtocol *timingsSupported )
{
    UInt32			i;

    *(UInt32 *)timingsSupported = 0;
 
    for ( i=0; i < numTimings; i++ )
    {
        *(UInt32 *) timingsSupported |= (UInt32)ataTimings[i].timingProtocol; 
    }

    return true;
}

/*
 *
 *
 */ 
bool IOATAStandardDevice::getTimingSelected( ATATimingProtocol *timingSelected )
{
    *timingSelected = currentTiming;
    return true;
}

/*
 *
 *
 */ 
bool IOATAStandardDevice::getProtocolsSupported( ATAProtocol *forProtocolsSupported )
{
    *(UInt32 *)forProtocolsSupported = protocolsSupported;
    return true;
}    

/*
 *
 *
 */ 
bool IOATAStandardDevice::getTiming( ATATimingProtocol *timingProtocol, ATATiming *timing )
{
    UInt32			i;

    for ( i=0; i < numTimings; i++ )
    {
        if ( ataTimings[i].timingProtocol == *timingProtocol )
        {
            bcopy( &ataTimings[i], timing, sizeof(ATATiming) );
            return true;
        }
    }

    return false;
}


/*
 *
 *
 */ 
bool IOATAStandardDevice::selectTiming( ATATimingProtocol timingProtocol, bool fNotifyMsg )
{
    ATATaskfile            taskfile;
    bool                   rc = false;
    UInt32                 i;
    IOATAStandardCommand * ataCmd;

    for ( i=0; i < numTimings; i++ )
    {
        if ( ataTimings[i].timingProtocol == timingProtocol )
        {
            rc = true;
            break;
        }
    }

    if ( rc == false )
    {
        return false;
    }

    ataCmd = allocCommand(kIOATAStandardDevice, 0);
    if ( ataCmd == 0 ) return false;

    currentTiming = timingProtocol;
    
    bzero( &taskfile, sizeof(taskfile) );

    taskfile.protocol    		= kATAProtocolPIO;
    taskfile.regmask      		= ATARegtoMask(kATARegFeatures) 
                          		| ATARegtoMask(kATARegSectorCount) 
                          		| ATARegtoMask(kATARegDriveHead) 
                          		| ATARegtoMask(kATARegCommand);
 
    taskfile.ataRegs[kATARegSectorCount]  = ataTimings[i].featureSetting;
    taskfile.ataRegs[kATARegFeatures]     = kATAFeatureTransferMode;
    taskfile.ataRegs[kATARegDriveHead]    = kATAModeLBA | (getUnit() << 4);
    taskfile.ataRegs[kATARegCommand]      = kATACommandSetFeatures;

    taskfile.flags			  = kATACmdFlagTimingChanged;

    ataCmd->setTaskfile( &taskfile );
    ataCmd->setPointers( (IOMemoryDescriptor *)NULL, 0, false );
    ataCmd->setTimeout( 5000 );
    ataCmd->setQueueInfo( kATAQTypeBypassQ );

    if ( fNotifyMsg == false )
    {
        ataCmd->setCallback(); 
        ataCmd->execute();
        if ( ataCmd->getResults( (ATAResults *) 0 ) != kIOReturnSuccess )
        {
            rc = false;
        }
        ataCmd->release();
    }
    else
    {
        ataCmd->setCallback( this, (CallbackFn)&IOATAStandardDevice::selectTimingDone, ataCmd );
        ataCmd->execute();
    }   
    return rc;
}
    
/*
 *
 *
 */ 
void IOATAStandardDevice::selectTimingDone( IOATAStandardCommand *ataCmd )
{
    bool		rc;

    rc = (ataCmd->getResults( (ATAResults *)0 ) == kIOReturnSuccess);

    client->message( kATAClientMsgSelectTiming | kATAClientMsgDone, this, (void *)rc );

    ataCmd->release();
}

/*
 *
 *
 */ 
bool IOATAStandardDevice::getATATimings()
{
    int			i, n;
    UInt32 	        mode		= 0;
    UInt32     		cycleTime	= 0;

    ATATiming		*pTimings;

    if ( controller->getProtocolsSupported( (ATAProtocol *)&protocolsSupported ) == false )
    {
        return false;
    }

    pTimings = ataTimings;

    /*
     *  PIO Cycle timing......  
     *
     *  1. Try to match Word 51 (pioCycleTime) with cycle timings
     *     in our pioModes table to get mode/CycleTime. (Valid for Modes 0-2)
     *  2. If Words 64-68 are supported and Mode 3 or 4 supported check, 
     *     update CycleTime with Word 68 (CycleTimeWithIORDY).
     */

    cycleTime = identifyData->pioMode;

    if ( cycleTime > 2 )
    {
        for ( i=AppleNumPIOModes-1; i != -1; i-- )
        {
            if ( cycleTime <= ApplePIOModes[i].minDataCycle )
            {
                mode = i;
                break;
            }
         }

         if ( i == -1 )
         {
             cycleTime = ApplePIOModes[mode].minDataCycle;
         }
    }
    else
    {
        mode      = cycleTime;
        cycleTime = ApplePIOModes[mode].minDataCycle;
    }


    if ( identifyData->validFields & identifyWords_64to70_Valid ) 
    {
	if (identifyData->advancedPIOModes & advPIOModes_Mode4_Supported)
            mode = 4;
	else if (identifyData->advancedPIOModes & advPIOModes_Mode3_Supported)
            mode = 3;

        if ( (mode >= 3) && identifyData->minPIOCyclcTimeIORDY )
        {
            cycleTime = identifyData->minPIOCyclcTimeIORDY;
        }
    }
    
    pTimings->timingProtocol = kATATimingPIO;
    pTimings->mode	      = mode;
    pTimings->featureSetting  = mode | kATATransferModePIOwFC;
    pTimings->minDataCycle    = cycleTime;
    pTimings->minDataAccess   = ApplePIOModes[mode].minDataAccess;

    if ( ((protocolsSupported & kATAProtocolPIO) == 0) 
             || (controller->calculateTiming( getUnit(), pTimings ) == false) )
    {
        IOLog("IOATAStandardDevice::%s() - Controller driver must support PIO protocol\n\r", __FUNCTION__);
        return false;
    }

    pTimings++;
    numTimings++;

    /* 
     *  Multiword DMA timing.....
     *
     *  1. Check Word 63(7:0) (Multiword DMA Modes Supported). Lookup
     *     CycleTime for highest mode we support.
     *  2. If Words 64-68 supported, update CycleTime from Word 66
     *     (RecommendedMultiWordCycleTime) if specified.
     */                                                                

    n = identifyData->dmaModes & dmaModes_Supported;
    if ( n )
    {
        for ( i=0; n; i++, n>>=1 )
          ;

        mode = i - 1;
        if ( mode > AppleNumDMAModes-1 )
        {
            mode = AppleNumDMAModes-1;
        }
        cycleTime = AppleDMAModes[mode].minDataCycle;

        if (identifyData->validFields & identifyWords_64to70_Valid) 
        {
            if ( identifyData->recDMACycleTime )
            {
                cycleTime = identifyData->recDMACycleTime;
            }
        }
        pTimings->timingProtocol = kATATimingDMA;
        pTimings->mode	         = mode;
        pTimings->featureSetting = mode | kATATransferModeDMA;
        pTimings->minDataCycle   = cycleTime;
        pTimings->minDataAccess  = AppleDMAModes[mode].minDataAccess;

        if ( ((protocolsSupported & kATAProtocolDMA) != 0)  
                && (controller->calculateTiming( getUnit(), pTimings ) == true) )
        {
            pTimings++;
            numTimings++;
        }
    }

    /* 
     *  Ultra DMA timing.....
     *
     */                                                                
    if ( identifyData->validFields & identifyWords_88to88_Valid ) 
    {
        n = identifyData->ultraDMAModes & ultraDMAModes_Supported;
        if ( n )
        {
            for ( i=0; n; i++, n>>=1 )
              ;

            mode = i - 1;
            if ( mode > AppleNumUltraModes-1 )
            {
                mode = AppleNumUltraModes-1;
            }

            /*
             * Build a separate timing entry for Ultra DMA/33 (mode <= 2) and Ultra DMA/66
             */
            while ( 1 )
            { 
                cycleTime = AppleUltraModes[mode].minDataCycle;

                pTimings->timingProtocol = (mode > 2) ? kATATimingUltraDMA66 : kATATimingUltraDMA33;
                pTimings->mode	         = mode;
                pTimings->featureSetting = mode | kATATransferModeUltraDMA33;
                pTimings->minDataCycle   = cycleTime;
                pTimings->minDataAccess  = AppleUltraModes[mode].minDataAccess;

                if ( ((protocolsSupported & kATAProtocolDMA) != 0)  
                    && (controller->calculateTiming( getUnit(), pTimings ) == true) )
                {
                    pTimings++;
                    numTimings++;
                }
                
                if ( mode < 3 ) break; 
           
                mode = 2;
            }
        }
    }
 
    maxTags = 0;

    if ( deviceType == kATADeviceATA )
    {
        if ( ((identifyData->commandSetsSupported2 & commandSetsSupported2_ValidMask) == commandSetsSupported2_Valid) 
              && ((identifyData->commandSetsSupported3 & commandSetsSupported3_ValidMask) == commandSetsSupported3_Valid) )
        { 
            if ( ((identifyData->commandSetsSupported2 & commandSetsSupported2_DMAQueued) != 0)   
                   && ((identifyData->commandSetsEnabled2 & commandSetsEnabled2_DMAQueued) != 0) )
            {
                maxTags = identifyData->queueDepth + 1;
            }
        }
    }

    if ( maxTags == 0 )
    {
        protocolsSupported &= ~(kATAProtocolDMAQueued | kATAProtocolDMAQueuedRelease);
    }


    return true;            
}

/*
 *
 *
 *
 */
ATAUnit IOATAStandardDevice::getUnit()
{
    return unit;
}

/*
 *
 *
 */
ATADeviceType IOATAStandardDevice::getDeviceType()
{
    return deviceType;
}

/*
 *
 *
 */
bool IOATAStandardDevice::getATAPIPktInt()
{
    return atapiPktInt;
}

/*
 *
 *
 */
bool IOATAStandardDevice::getIdentifyData( ATAIdentify *identifyBuffer )
{
    if ( identifyData == NULL )
    {
        bzero( identifyBuffer, sizeof(ATAIdentify) );
        return false;
    }

    bcopy( identifyData, identifyBuffer, sizeof(ATAIdentify) );
    return true;
}

/*
 *
 *
 */
bool IOATAStandardDevice::getInquiryData( UInt32 inquiryBufLength, ATAPIInquiry *inquiryBuffer )
{        
    bzero( inquiryBuffer, inquiryBufLength );

    if ( inquiryData == NULL )
    {
        return false;
    }

    bcopy( inquiryData, inquiryBuffer, inquiryBufLength );

    return true;
}


/*
 *
 *
 *
 */
void IOATAStandardDevice::setupTarget()
{   
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::getInquiryData( void *clientBuf, UInt32 clientBufSize, UInt32 *clientDataSize )
{
    UInt32		len;

    bzero( clientBuf, clientBufSize );

    len = MIN( clientBufSize, inquiryDataSize );
   
    bcopy( inquiryData, clientBuf, len );

    *clientDataSize = len;
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::abort()
{
    submitCommand( kATACommandAbortAll, 0 );
}
 
/*
 *
 *
 *
 */
void IOATAStandardDevice::reset()
{
    submitCommand( kATACommandDeviceReset, 0 );
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::holdQueue( UInt32 queueType )
{
    if ( getWorkLoop()->inGate() == false )
    {
        IOPanic( "IOATAStandardDevice::holdQueue() - must be called from workloop!!\n\r");
    }

    if ( queueType == kATAQTypeBypassQ )
    {
        bypassQHeld++;
    }
    else if ( queueType == kATAQTypeNormalQ )
    {
        normalQHeld++;   
    }
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::releaseQueue( UInt32 queueType )
{
    bool doDispatchRequest = false;

    if ( getWorkLoop()->inGate() == false )
    {
        IOPanic( "IOATAStandardDevice::releaseQueue() - must be called from workloop!!\n\r");
    }

    if ( queueType == kATAQTypeBypassQ )
    {
        if ( bypassQHeld && (--bypassQHeld == 0) )
            doDispatchRequest = true;
    }
    else if ( queueType == kATAQTypeNormalQ )
    {
        if ( normalQHeld && (--normalQHeld == 0) )
            doDispatchRequest = true;
    }

    if ( doDispatchRequest ) dispatchRequest();
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::notifyIdle(  void *target = 0, CallbackFn callback = 0, void *refcon = 0  )
{
    if ( getWorkLoop()->inGate() == false )
    {
        IOPanic( "IOATAStandardDevice:::notifyIdle() - must be called from workloop!!\n\r");
    }

    if ( callback == 0 )
    {
        idleNotifyActive = false;
        return;
    }

    if ( idleNotifyActive == true )
    {
        IOPanic( "IOATAStandardDevice:::notifyIdle() - only one idle notify may be active\n\r");
    }

    idleNotifyActive   = true;
    idleNotifyTarget   = target;
    idleNotifyCallback = callback;
    idleNotifyRefcon   = refcon;

    checkIdleNotify();    
}

   
/*
 *
 *
 *
 */
void IOATAStandardDevice::submitCommand( UInt32 cmdType, IOATAStandardCommand *ataCmd, UInt32 cmdSequenceNumber )
{
    deviceGate->runCommand( (void *)cmdType, (void *)ataCmd, (void *) cmdSequenceNumber, (void *) 0 );
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::receiveCommand( UInt32 cmdType, IOATAStandardCommand *ataCmd, UInt32 cmdSequenceNumber, void *p3 )
{
    queue_head_t		*queue;

    switch ( cmdType )
    {
        case kATACommandExecute:
            ataCmd->cmdType = (ATACommandType) cmdType;

            queue = (ataCmd->queueType == kATAQTypeBypassQ) ? &bypassList : &deviceList;

            if ( ataCmd->queuePosition == kATAQPositionHead ) 
            {
                stackCommand( queue, ataCmd );
            }
            else
            { 
                addCommand( queue, ataCmd );
            }

            dispatchRequest();
            break;
     
        case kATACommandAbortAll:
            abortAllCommands( kATACommandAbortAll );    
            break;

        case kATACommandAbort:
            abortCommand( ataCmd, cmdSequenceNumber );
            break;

        case kATACommandDeviceReset:
            abortAllCommands( kATACommandDeviceReset );            
            break;

        default:
            /* ??? */
            break;
    }    
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::abortCommand( IOATAStandardCommand *ataCmd, UInt32 sequenceNumber )
{
    if ( ataCmd->list == (queue_head_t *)deviceGate )
    {
        if ( ataCmd->sequenceNumber != sequenceNumber )
        {
            return;
        }    
        ataCmd->results.returnCode = kIOReturnAborted;
    }
    else if ( ataCmd->list == &deviceList )
    {
        if ( ataCmd->sequenceNumber != sequenceNumber )
        {
            return;
        }    

        deleteCommand( &deviceList, ataCmd );
        ataCmd->results.returnCode = kIOReturnAborted;
        finishCommand( ataCmd );
    }
    else if ( ataCmd->list == &activeList )
    {
        if ( ataCmd->sequenceNumber != sequenceNumber )
        {
            return;
        }    

        moveCommand( &activeList, &abortList, ataCmd );

        dispatchRequest();     
    }
}


/*
 *
 *
 *
 */
void IOATAStandardDevice::abortAllCommands( ATACommandType cmdType )
{

    abortCmdPending = cmdType;

    if ( abortCmdPending == kATACommandAbortAll )
    {
        if ( client != 0 )
        {
            client->message( kATAClientMsgDeviceAbort, this );
        }
    }
    else if ( abortCmdPending == kATACommandDeviceReset )
    {
        if ( client != 0 )
        {
            client->message( kATAClientMsgDeviceReset, this );
        }
    }

    dispatchRequest();
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::resetOccurred( ATAClientMessage clientMsg )
{
    moveAllCommands( &activeList, &cancelList, kIOReturnAborted );
    moveAllCommands( &abortList,  &cancelList, kIOReturnAborted );
    
    abortState        = kStateIdle;
    reqSenseState     = kStateIdle;
    commandLimit      = 1;

    isSuspended	      = false;
    AbsoluteTime_to_scalar( &suspendTime ) = 0;

    if ( (client != 0) && (clientMsg != kATAClientMsgNone) )
    {
        client->message( clientMsg, this );
    }    

    dispatchRequest();
}

void IOATAStandardDevice::resetComplete()
{
    if ( client != 0 )
    {
        client->message( kATAClientMsgBusReset | kATAClientMsgDone, this );
    }
}


/*
 *
 *
 *
 */
bool IOATAStandardDevice::checkAbortQueue()
{
    IOATAStandardCommand		*origCmd;

    if ( abortState == kStateActive )
    {
        return true;
    }
        
    if ( abortCmdPending != kATACommandNone )
    {
        abortCmd->origCommand = 0;
        abortCmd->taskfile.tagType    = kATATagTypeNone;         
        abortCmd->cmdType             = abortCmdPending;        
    
        abortCmd->timer = ( abortCmd->timeout != 0 ) ?
                                          abortCmd->timeout / kATATimerIntervalmS + 1 : 0; 

        bzero( &abortCmd->results, sizeof(ATAResults) );

        abortState = kStateActive;

        addCommand( &activeList, abortCmd ); 

        if ( (abortCmdPending == kATACommandDeviceReset) ||
             (abortCmdPending == kATACommandAbortAll) && (queue_empty( &abortList ) == false) )
        {
            controller->abortCommand( abortCmd );
        }
        else
        {
            abortCmd->complete();
        }
    }             
    else if ( queue_empty( &abortList ) == false )
    {   
        origCmd = (IOATAStandardCommand *)queue_first( &abortList );
        abortCmd->origCommand = origCmd;
        
        abortCmd->cmdType = kATACommandAbort;
        abortCmd->taskfile.tagType = origCmd->taskfile.tagType;
        abortCmd->taskfile.tag     = origCmd->taskfile.tag;

        abortCmd->timer = ( abortCmd->timeout != 0 ) ?
                                          abortCmd->timeout / kATATimerIntervalmS + 1 : 0; 

        bzero( &abortCmd->results, sizeof(ATAResults) );          

        abortState = kStateActive;

        addCommand( &activeList, abortCmd ); 
        controller->abortCommand( abortCmd );
    }   
    else
    {
        return false;
    }     
    
    return true;
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::checkCancelQueue()
{
    if ( cancelState != kStateIdle )
    {
        return;
    }
        
    if ( queue_empty( &cancelList ) == true )
    {
         return;
    }

    if ( controller->controllerInfo.disableCancelCommands == true )
    {
        return;
    }

    cancelCmd->origCommand = (IOATAStandardCommand *)queue_first( &cancelList );
    bzero( &cancelCmd->results, sizeof(ATAResults) );

    cancelState = kStateActive;
    controller->cancelCommand( cancelCmd );
}

/*
 *
 *
 *
 */
bool IOATAStandardDevice::checkReqSense()
{
    IOMemoryDescriptor		*senseData;
    UInt32			senseLength;    
              
    if ( reqSenseState == kStateIssue )
    {
        reqSenseCmd->origCommand = reqSenseOrigCmd;
        bzero( &reqSenseCmd->results, sizeof(ATAResults) );

        reqSenseOrigCmd->getPointers( &senseData, &senseLength, 0, true );
        reqSenseCmd->setPointers( senseData, senseLength, false );

        reqSenseCmd->timer = ( reqSenseCmd->timeout != 0 ) ?
                                          reqSenseCmd->timeout / kATATimerIntervalmS + 1 : 0; 

        reqSenseCmd->ataCmd.cdb[3] = (senseLength >> 8) & 0xff;
        reqSenseCmd->ataCmd.cdb[4] =  senseLength       & 0xff;
        
        reqSenseState = kStatePending;
    }
    
    if ( reqSenseState == kStatePending )
    {        
        reqSenseState = kStateActive;

        addCommand( &activeList, reqSenseCmd );
 
        commandCount++;
        controller->commandCount++;

        controller->executeCommand( reqSenseCmd );
    }  

    return (reqSenseState != kStateIdle);  
}


/*
 *
 *
 *
 */
bool IOATAStandardDevice::checkDeviceQueue( UInt32 *dispatchAction ) 
{
    IOATAStandardCommand	*ataCmd = 0;
    queue_head_t		*queue;
    UInt32			i;
    bool			rc = true;
    UInt32			queueHeld;

    do
    {
        if ( isSuspended == true )
        {
            *dispatchAction = kDispatchNextDevice;
            break;
        }
             
        if ( controller->commandCount >= controller->commandLimit )
        {
            *dispatchAction = kDispatchStop;
            break;
        }

        *dispatchAction = kDispatchNextDevice;

        if ( commandCount >= commandLimit )
        {
            break;
        }

        for ( i=0; i < 2; i++ )
        {
            queueHeld = (i == 0) ? bypassQHeld : normalQHeld;
            queue     = (i == 0) ? &bypassList : &deviceList;
        
            if ( queueHeld > 0 )
            {
                continue;
            }

            ataCmd = checkCommand( queue );
            if ( ataCmd != 0 )
            {
                *dispatchAction = kDispatchNextCommand;
                break;
            }
        }

        if ( i == 2 )
        { 
            rc = false;
            break;
        }


        if ( checkTag( ataCmd ) == false )
        {
            *dispatchAction = kDispatchNextDevice;
            break;
        }
             
        getCommand( queue );
   
        ataCmd->timer = ( ataCmd->timeout != 0 ) ? ataCmd->timeout / kATATimerIntervalmS + 1 : 0; 

        commandCount++;
        controller->commandCount++;        

        addCommand( &activeList, ataCmd );

        controller->executeCommand( ataCmd );

    } while ( 0 );

    return rc;
}   

/*
 *
 *
 *
 */
void IOATAStandardDevice::suspend()
{
    if ( AbsoluteTime_to_scalar( &suspendTime ) == 0 )
    {
        clock_get_uptime( &suspendTime );
    }

    isSuspended = true;
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::resume()
{
    AbsoluteTime_to_scalar( &suspendTime ) = 0;
    isSuspended = false;

    dispatchRequest();
}


/*
 *
 *
 *
 */
void IOATAStandardDevice::rescheduleCommand( IOATAStandardCommand *ataCmd )
{
    queue_head_t		*queue;

    if ( ataCmd->list != &activeList )
    {
        IOLog( "IOATAStandardController::rescheduleCommand() - Command not active. Cmd = %08x\n\r", (int)ataCmd );
        return;
    }

    deleteCommand( &activeList, ataCmd );
 
    switch ( ataCmd->cmdType )
    {
        case kATACommandExecute:
            if ( ataCmd->taskfile.tagType != kATATagTypeNone )
            {
                freeTag( ataCmd->taskfile.tag );
                ataCmd->taskfile.tag = kATATagTypeNone;
            }

            queue = (ataCmd->queueType == kATAQTypeBypassQ) ? &bypassList : &deviceList;

            stackCommand( queue, ataCmd );

            controller->commandCount--;
            commandCount--;
            break;

        case kATACommandReqSense:
            reqSenseState = kStatePending;
            commandCount--;
            controller->commandCount--;
            break;

        case kATACommandAbortAll:
        case kATACommandDeviceReset:
            abortCmdPending = ataCmd->cmdType;

        case kATACommandAbort:
            abortState = kStateIdle;
            break;

        default:
            ;
    } 

    dispatchRequest();

}    
 
/*
 *
 *
 *
 */
bool IOATAStandardDevice::checkTag( IOATAStandardCommand *ataCmd )
{
    ATACDBInfo		ataCDB;
    bool		rc = true;
    ATAProtocol		protocol;

    ataCmd->getCDB( &ataCDB );

    ataCmd->taskfile.tagType = kATATagTypeNone;

    protocol = ataCmd->getProtocol();

    do 
    {
        if ( protocol != kATAProtocolDMAQueued && protocol != kATAProtocolDMAQueuedRelease )
        {
            break;
        }
        if ( allocTag( &ataCmd->taskfile.tag ) == false )
        {
             rc = false;
             break;
        }

        ataCmd->taskfile.tagType = kATATagTypeSimple;
    }
    while ( 0 );

    ataCmd->setCDB( &ataCDB );

    return rc;
}

/*
 *
 *
 *
 */
bool IOATAStandardDevice::allocTag( UInt32 *tagId )
{
    UInt32		i;
    UInt32		tagIndex;
    UInt32		tagMask;
    UInt32		*tags = 0;

    tags = tagArray;
    
    if ( tags == 0 ) return false;

    for ( i = 0; i < maxTags; i++ )
    {
        tagIndex = i / 32; 
        tagMask  = 1 << (i % 32);
        if ( !(tags[tagIndex] & tagMask) )
        {
            tags[tagIndex] |= tagMask;
            *tagId = i;
            return true;
        }
    }
    return false;
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::freeTag( UInt32 tagId )
{
    UInt32		*tags = 0;

    tags = tagArray;

    if ( tags == 0 ) return;

    tags[tagId/32] &= ~(1 << (tagId % 32));
}

/*
 *
 *
 *
 */
IOATAStandardCommand *IOATAStandardDevice::findCommandWithNexus( UInt32 tagValue )
{
    IOATAStandardCommand 		*ataCmd;
    UInt32				tag;

    queue_iterate( &activeList, ataCmd, IOATAStandardCommand *, nextCommand )
    {
        switch ( ataCmd->cmdType )
        {
            case kATACommandExecute:
            case kATACommandReqSense:
                tag = (ataCmd->taskfile.tagType == kATATagTypeNone) ? (UInt32) -1 : ataCmd->taskfile.tag;
                if ( tag == tagValue )
                {
                    return ataCmd;
                }
                break;
            default:
                ;
        }
    }

    queue_iterate( &abortList, ataCmd, IOATAStandardCommand *, nextCommand )
    {
        switch ( ataCmd->cmdType )
        {
            case kATACommandExecute:
            case kATACommandReqSense:
                if ( ataCmd->taskfile.tag == tagValue )
                {
                    return ataCmd;
                }
                break;
            default:
                ;
        }
    }

    return 0;
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::timer()
{
    IOATAStandardCommand 		*ataCmd, *tmp = 0;

    queue_iterate( &activeList, ataCmd, IOATAStandardCommand *, nextCommand )
    {
        tmp = (IOATAStandardCommand *)queue_prev( &ataCmd->nextCommand );
 
        if ( ataCmd->timer )
        {
            if ( !--ataCmd->timer )
            {
                IOLog("Timeout: Unit = %d Cmd = %08x Cmd Type = %d\n\r", 
                            unit, (int)ataCmd, ataCmd->cmdType );

                controller->busResetState = kStateIssue;
                dispatchRequest();                                    
            } 
        }

        if ( queue_end( &activeList, (queue_head_t *)ataCmd ) == true )
        {
            break;
        }
    }
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::dispatchRequest()
{
    target->state = kStateActive;
    controller->dispatchRequest();
}
                        
/*
 *
 *
 *
 */
bool IOATAStandardDevice::dispatch( UInt32 *dispatchAction )
{
    bool		rc;

    checkCancelQueue();

    if ( controller->checkBusReset() == true )
    {
        *dispatchAction = kDispatchStop;
        return true;
    }

    if ( checkAbortQueue() == true )
    {
        *dispatchAction = kDispatchNextDevice;
        return true;
    }    

    do
    {
        if ( (rc = controller->commandDisable) == true )
        {
            *dispatchAction = kDispatchStop;
            break;
        }

        if ( isSuspended == true )
        {
            *dispatchAction = kDispatchNextDevice;
            break;
        }    

        if ( (rc = checkReqSense()) == true )
        {
            *dispatchAction = kDispatchNextDevice;
            break;
        }    

        rc = checkDeviceQueue( dispatchAction );

    } while ( *dispatchAction == kDispatchNextCommand );

    return rc;                
}            
            
      
/*
 *
 *
 *
 */
void IOATAStandardDevice::completeCommand( IOATAStandardCommand *ataCmd )
{
    ATACommandType		cmdType;

    cmdType = ataCmd->cmdType;
    switch ( cmdType )
    {
        case kATACommandExecute:
            executeCommandDone( ataCmd );
            break;

        case kATACommandReqSense:
            executeReqSenseDone( ataCmd );
            break;
       
        case kATACommandAbort:
        case kATACommandAbortAll:
        case kATACommandDeviceReset:
            abortCommandDone( ataCmd );
            break;

        case kATACommandCancel:
            cancelCommandDone( ataCmd );
            break;

        default:
            ;
    }

    checkIdleNotify();

    dispatchRequest();
}     

/*
 *
 *
 *
 */
void IOATAStandardDevice::checkIdleNotify()
{
    if ( idleNotifyActive == false )
    {
        return;
    }

    if ( (queue_empty( &activeList ) == true) 
            &&  (queue_empty( &abortList ) == true)
               &&  (queue_empty( &cancelList ) == true) )
    {
        idleNotifyActive = false;
        (idleNotifyCallback)( idleNotifyTarget, idleNotifyRefcon );
    }
}  

/*
 *
 *
 *
 */
void IOATAStandardDevice::flushQueue( UInt32 queueType, IOReturn rc )
{
    queue_head_t		*queue;

    queue = (queueType == kATAQTypeBypassQ) ? &bypassList : &deviceList;
    purgeAllCommands( queue, rc );
}
             
/*
 *
 *
 *
 */
void IOATAStandardDevice::executeCommandDone( IOATAStandardCommand *ataCmd )
{
    deleteCommand( ataCmd->list, ataCmd );

    commandCount--;
    controller->commandCount--;

    if ( ataCmd->taskfile.tagType != kATATagTypeNone )
    {
        freeTag( ataCmd->taskfile.tag );
        ataCmd->taskfile.tagType = kATATagTypeNone;
    }

    if ( deviceType == kATADeviceATAPI 
            && ataCmd->results.adapterStatus == kATAReturnStatusError 
               && ataCmd->results.requestSenseDone == false
                   && ataCmd->senseData != 0 ) 
    {
        reqSenseOrigCmd = ataCmd;
        reqSenseState   = kStateIssue;
        return;
    }

    finishCommand( ataCmd );
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::executeReqSenseDone( IOATAStandardCommand *ataCmd )
{
    IOATAStandardCommand 		*origCommand;

    deleteCommand( ataCmd->list, ataCmd );

    commandCount--;
    controller->commandCount--;

    reqSenseState = kStateIdle;
    
    reqSenseOrigCmd = 0;
    
    origCommand = ataCmd->origCommand;

    if ( (ataCmd->results.returnCode == kIOReturnSuccess) || (ataCmd->results.returnCode == kIOReturnUnderrun))
    {
        origCommand->results.requestSenseDone   = true;
        origCommand->results.requestSenseLength = ataCmd->results.bytesTransferred;
    }
    else
    {
        origCommand->results.requestSenseDone   = false;
        origCommand->results.requestSenseLength = 0;
    }

    finishCommand( ataCmd->origCommand );
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::abortCommandDone( IOATAStandardCommand *ataCmd )
{
    IOATAStandardCommand		*origATACmd;

    deleteCommand( ataCmd->list, ataCmd );

    if ( ataCmd->cmdType == kATACommandAbortAll )
    {
        resetOccurred( (ATAClientMessage) (kATAClientMsgDeviceAbort | kATAClientMsgDone) );
        abortCmdPending = kATACommandNone;
    }
    if ( ataCmd->cmdType == kATACommandDeviceReset )
    {
        resetOccurred( (ATAClientMessage) (kATAClientMsgDeviceReset | kATAClientMsgDone) );
        abortCmdPending = kATACommandNone;
    }
    else if ( ataCmd->cmdType == kATACommandAbort )
    {
        origATACmd = ataCmd->origCommand;
        
        if ( findCommand( &abortList, origATACmd ) == true )
        {
            moveCommand( &abortList, &cancelList, origATACmd, kIOReturnAborted );
        }
    }

    abortState = kStateIdle;

    return;
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::cancelCommandDone( IOATAStandardCommand *ataCmd )
{
    IOATAStandardCommand		*origATACmd;

    cancelState = kStateIdle;

    origATACmd = ataCmd->origCommand;
    
    if ( findCommand( &cancelList, origATACmd ) == true )
    {
        IOLog( "IOATAStandardDevice::cancelCommandDone - Cancelled command not completed - ataCmd = %08x\n\r", (int)origATACmd );
        deleteCommand( &cancelList, origATACmd );
    }    
}    

/*
 *
 *
 *
 */
void IOATAStandardDevice::finishCommand( IOATAStandardCommand *ataCmd )
{
    if ( ataCmd->completionInfo.async.callback )
    {
        (*ataCmd->completionInfo.async.callback)( ataCmd->completionInfo.async.target, 
                                                   ataCmd->completionInfo.async.refcon );
    }
    else
    {
        ataCmd->completionInfo.sync.lock->signal();
    }
}

    
/*
 *
 *
 */
OSDictionary *IOATAStandardDevice::createProperties()
{
    OSDictionary 	*propTable = 0;
    OSObject		*regObj;
    char		tmpbuf[81];
    const char		*s;
    char		*d;
   

    propTable = OSDictionary::withCapacity(kATAMaxProperties);
    if ( propTable == NULL )
    {
        return NULL;
    }

    s = (deviceType == kATADeviceATA) ? kATAPropertyProtocolATA : kATAPropertyProtocolATAPI;
    regObj = (OSObject *)OSString::withCString( s );
    if ( addToRegistry( propTable, regObj, kATAPropertyProtocol ) != true )
    {
        goto createprop_error;
    }

    regObj = (OSObject *)OSNumber::withNumber(unit,32);
    if ( addToRegistry( propTable, regObj, kATAPropertyDeviceNumber ) != true )
    {
        goto createprop_error;
    }

    regObj = (OSObject *)OSNumber::withNumber(unit,32);
    if ( addToRegistry( propTable, regObj, kATAPropertyLocation ) != true )
    {
        goto createprop_error;
    }

    d = tmpbuf;
    stripBlanks( d, (char *)identifyData->modelNumber, sizeof(identifyData->modelNumber));
    regObj = (OSObject *)OSString::withCString( d );
    if ( addToRegistry( propTable, regObj, kATAPropertyModelNumber ) != true )
    {
        goto createprop_error;
    }

    d = tmpbuf;
    stripBlanks( d, (char *)identifyData->firmwareRevision, sizeof(identifyData->firmwareRevision));
    regObj = (OSObject *)OSString::withCString( d );
    if ( addToRegistry( propTable, regObj, kATAPropertyFirmwareRev ) != true )
    {
        goto createprop_error;
    }

    if ( inquiryData )
    {
        stripBlanks( d, (char *)inquiryData->vendorName, sizeof(inquiryData->vendorName) );
        regObj = (OSObject *)OSString::withCString( d );
        if ( addToRegistry( propTable, regObj, kATAPropertyVendorName ) != true )
        {
            goto createprop_error;
        }

        stripBlanks( d, (char *)inquiryData->productName, sizeof(inquiryData->productName) );
        regObj = (OSObject *)OSString::withCString( d );
        if ( addToRegistry( propTable, regObj, kATAPropertyProductName ) != true )
        {
            goto createprop_error;
        }

        stripBlanks( d, (char *)inquiryData->productRevision, sizeof(inquiryData->productRevision) );
        regObj = (OSObject *)OSString::withCString( d );
        if ( addToRegistry( propTable, regObj, kATAPropertyProductRevision ) != true )
        {
            goto createprop_error;
        }
    }
    return propTable;

createprop_error: ;
    propTable->release();
    return NULL;
}


/*
 *
 *
 */
bool IOATAStandardDevice::addToRegistry( OSDictionary *propTable, OSObject *regObj, char *key,
                                         bool doRelease = true )
{
    bool                 rc;

    if ( regObj == NULL )
    {
        return false;
    }
    
    rc  = propTable->setObject( key, regObj );

    if ( doRelease )
    {
        // If 'doRelease' is true, then a reference count is consumed.
        regObj->release();
    }

    return rc;
}


/*
 *
 *
 *
 */
bool IOATAStandardDevice::matchPropertyTable(OSDictionary * table)
{
  return( controller->matchNubWithPropertyTable( this, table ));
}


/*
 *
 *
 *
 */
IOService *IOATAStandardDevice::matchLocation(IOService * client)
{
    return this;
}


/*
 *
 *
 *
 */
void IOATAStandardDevice::stripBlanks( char *d, char *s, UInt32 l )
{
    char	*p, c;

    for ( p = d, c = *s; l && c ; l--)
    {
        c = (*d++ = *s++);
        if ( c != ' ' )
        {
            p = d;
        }
    }
    *p = 0;
}   

/*
 *
 *
 */
void IOATAStandardDevice::endianConvertData( void *data, void *endianTable )
{
    EndianTable		*t;

    union EndianPtr 
    {
        void            *voidPtr;
        UInt8		*bytePtr;
        UInt16		*shortPtr;
        UInt32		*longPtr;
        UInt64		*longlongPtr;
    } p;

    UInt32		i,j;

    p.voidPtr = data;

    t = (EndianTable *)endianTable;

    for ( ; t->type; t++ )
    {
        i = t->size/t->type;

        switch ( t->type )
        {
        
            /* Note:
             *
             * The ATA standard defines identify strings as arrays of short ints,
             * with the left-most character of the string as the most significant  
             * byte of the short int. Strings are not normally affected by the host
             * endianess. However, the way ATA defines strings would cause strings
             * to appear byte reversed. We do a manditory short int byte-swap here, 
             * although strictly speaking this is not an endian issue.
             *
             */
            case sizeof(UInt8):
              for ( j = 0; j < i/2; j++ )
              {
                  *p.shortPtr++ = OSSwapInt16(*p.shortPtr);
              }  
              
              break;
        
            case sizeof(UInt16):
              for ( j = 0; j < i; j++ )
              {
                  *p.shortPtr++ = OSSwapLittleToHostInt16(*p.shortPtr);
              }  
              break;

            case sizeof(UInt32):
              for ( j = 0; j < i; j++ )
              {
                  *p.longPtr++ = OSSwapLittleToHostInt32(*p.longPtr);
              }  
              break;

            case sizeof(UInt64):
              for ( j = 0; j < i; j++ )
              {
                  *p.longlongPtr++ = OSSwapLittleToHostInt64(*p.longlongPtr);
              }  
              break;

            default:
              ;
        }
    } 
}

/*
 *
 *
 *
 */
IOATACommand *IOATAStandardDevice::allocCommand( IOATADevice *, UInt32 clientDataSize )
{
    return (IOATAStandardCommand *) allocCommand( kIOATAStandardDevice, clientDataSize );
}

IOCDBCommand *IOATAStandardDevice::allocCommand( IOCDBDevice *, UInt32 clientDataSize )
{
    return (IOCDBCommand *) allocCommand( kIOATAStandardDevice, clientDataSize );
}

IOATAStandardCommand *IOATAStandardDevice::allocCommand( IOATAStandardDevice *, UInt32 clientDataSize )
{
    IOATAStandardCommand	*cmd;

    if ( (cmd = controller->allocCommand( clientDataSize )) )
    {
        cmd->device = this;
    }
    return cmd;
}


/*
 *
 *
 */
IOWorkLoop *IOATAStandardDevice::getWorkLoop() const
{
    return controller->workLoop;
}


/*
 *
 *
 *
 */
bool IOATAStandardDevice::open( IOService *forClient, IOOptionBits options, void *arg )
{
    if ( client != 0 ) return false;

    client = forClient;

    return super::open( forClient, options, arg );
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::close( IOService *forClient, IOOptionBits options )
{
    client = 0;

    return super::close( forClient, options );
}

/*
 *
 *
 *
 */
void IOATAStandardDevice::free()
{    
    if ( deviceGate != 0 )
    {
        controller->workLoop->removeEventSource( deviceGate );
        deviceGate->release();
    }

    if ( reqSenseCmd != 0 ) 		reqSenseCmd->release();
    if ( abortCmd != 0 ) 		abortCmd->release();
    if ( cancelCmd != 0 ) 		cancelCmd->release();
    if ( probeCmd != 0 ) 		probeCmd->release();

    if ( tagArray != 0 ) 		IOFree( tagArray, tagArraySize );
    if ( inquiryData != 0 )		IOFree( inquiryData, inquiryDataSize );
    if ( devicePrivateData != 0 )	IOFreeContiguous( devicePrivateData, controller->controllerInfo.devicePrivateDataSize );
    if ( clientSem != 0 ) 		IORWLockFree( clientSem );

    super::free();
}


