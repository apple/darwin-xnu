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
 * IOATAHDCommand.cpp - Performs ATA command processing.
 *
 * HISTORY
 * Aug 27, 1999	jliu - Ported from AppleATADrive.
 */

#include <IOKit/assert.h>
#include <IOKit/IOSyncer.h>
#include <IOKit/storage/ata/IOATAHDDrive.h>

// Enable this define to generate debugging messages.
// #define DEBUG_LOG 1

//---------------------------------------------------------------------------
// Select the device timing protocol.

bool
IOATAHDDrive::selectTimingProtocol()
{
	bool              ret;
	UInt8             ataReadCmd;
	UInt8             ataWriteCmd;
    ATATimingProtocol timing;
    char *            protocolName;

    ret = _ataDevice->getTimingsSupported(&timing);
    if (ret == false)
    {
        IOLog("%s: getTimingsSupported() error\n", getName());
        timing = kATATimingPIO;
    }

	// IOLog("%s: device supported timings: %08x\n", getName(), timing);
	
	if (timing & (kATATimingUltraDMA66 | kATATimingUltraDMA33 | kATATimingDMA)) 
	{
		if (timing & kATATimingUltraDMA66)
		{
            protocolName = "U-DMA/66";
			timing = kATATimingUltraDMA66;
		}
		else if (timing & kATATimingUltraDMA33)
		{
            protocolName = "U-DMA/33";
			timing = kATATimingUltraDMA33;
		}
		else
		{
            protocolName = "DMA";
			timing = kATATimingDMA;
		}

        selectCommandProtocol(true);

        switch ( _ataProtocol )
        {
            case kATAProtocolDMAQueued:
  		        ataReadCmd  = kIOATACommandReadDMAQueued;
		        ataWriteCmd = kIOATACommandWriteDMAQueued;
                break;

            case kATAProtocolDMA:
            default:
  		        ataReadCmd  = kIOATACommandReadDMA;
		        ataWriteCmd = kIOATACommandWriteDMA;
        }
	}
	else
	{
        protocolName = "PIO";
		timing       = kATATimingPIO;
		ataReadCmd   = kIOATACommandReadPIO;
		ataWriteCmd  = kIOATACommandWritePIO;
        selectCommandProtocol(false);
	}

    _timingProtocol = timing;
    _ataReadCmd     = ataReadCmd;
    _ataWriteCmd    = ataWriteCmd;
    ret             = true;

    // Select device timing.
    //
    ret = _ataDevice->selectTiming( _timingProtocol, false );

	if (ret == false)
	{
		IOLog("%s: %s selectTiming() failed\n", getName(), protocolName);

		if (_timingProtocol != kATATimingPIO)
		{
			// Non PIO mode selection failed, defaulting to PIO mode and
			// try one more time.

			protocolName    = "PIO";
			_timingProtocol = kATATimingPIO;
			_ataReadCmd     = kIOATACommandReadPIO;
			_ataWriteCmd    = kIOATACommandWritePIO;
			selectCommandProtocol(false);

			ret = _ataDevice->selectTiming( _timingProtocol, false );
			if (ret == false)
				IOLog("%s: %s selectTiming() retry failed\n",
				      getName(), protocolName);
		}
	}

	if (ret && _logSelectedTimingProtocol)
		IOLog("%s: Using %s transfers\n", getName(), protocolName);

	return ret;
}

//---------------------------------------------------------------------------
// Select the command protocol to use (e.g. ataProtocolPIO, ataProtocolDMA).

bool
IOATAHDDrive::selectCommandProtocol(bool isDMA)
{
    ATAProtocol	protocolsSupported;

    if ( _ataDevice->getProtocolsSupported( &protocolsSupported ) == false )
    {
        IOLog("%s: getProtocolsSupported() failed\n", getName());
        return false;
    }

    if ( (protocolsSupported & kATAProtocolDMAQueued) != 0 )
    {
#if 0
        _ataProtocol = kATAProtocolDMAQueued;
#else
        _ataProtocol = kATAProtocolDMA;
#endif
    }
    else if ( (protocolsSupported & kATAProtocolDMA) != 0 )
    {    
        _ataProtocol = kATAProtocolDMA;
    }
    else
    {
        _ataProtocol = kATAProtocolPIO;
    }

    return true;
}

//---------------------------------------------------------------------------
// Configure the ATA/ATAPI device when the driver is initialized, and
// after every device reset.

bool
IOATAHDDrive::configureDevice(IOATADevice * device)
{
    bool ret;

    // Select device timing.
    //
    ret = device->selectTiming( _timingProtocol, true );
	if (ret == false) {
		IOLog("%s: selectTiming() failed\n", getName());
        return false;
    }

    return true;
}

//---------------------------------------------------------------------------
// Setup an ATATaskFile from the parameters given, and write the taskfile
// to the ATATaskfile structure pointer provided.
//
// taskfile - pointer to a taskfile structure.
// protocol - An ATA transfer protocol (ataProtocolPIO, ataProtocolDMA, etc)
// command  - ATA command byte.
// block    - Initial transfer block.
// nblks    - Number of blocks to transfer.

void
IOATAHDDrive::setupReadWriteTaskFile(ATATaskfile * taskfile,
                                     ATAProtocol   protocol,
                                     UInt8         command,
                                     UInt32        block,
                                     UInt32        nblks)
{
    bzero( taskfile, sizeof(ATATaskfile) );

	taskfile->protocol = protocol;

	// Mask of all taskfile registers that shall contain valid
	// data and should be written to the hardware registers.
	//
	taskfile->regmask  = ATARegtoMask(kATARegSectorNumber)	|
                         ATARegtoMask(kATARegCylinderLow)	|
                         ATARegtoMask(kATARegCylinderHigh)	|
						 ATARegtoMask(kATARegDriveHead)		|
						 ATARegtoMask(kATARegSectorCount)	|
						 ATARegtoMask(kATARegFeatures)		|
						 ATARegtoMask(kATARegCommand);

	taskfile->resultmask = 0;

	taskfile->ataRegs[kATARegSectorNumber] = block & 0x0ff;
	taskfile->ataRegs[kATARegCylinderLow]  = (block >> 8) & 0xff;
	taskfile->ataRegs[kATARegCylinderHigh] = (block >> 16) & 0xff;
	taskfile->ataRegs[kATARegDriveHead]    = ((block >> 24) & 0x0f) |
                                             kATAModeLBA | (_unit << 4); 

    if ( protocol == kATAProtocolDMAQueued )
    {
        taskfile->ataRegs[kATARegFeatures]    =
            (nblks == kIOATAMaxBlocksPerXfer) ? 0 : nblks;
        taskfile->ataRegs[kATARegSectorCount] = 0;
    }
    else
    {
        taskfile->ataRegs[kATARegFeatures]    = 0;
        taskfile->ataRegs[kATARegSectorCount] =
            (nblks == kIOATAMaxBlocksPerXfer) ? 0 : nblks;
    }

    taskfile->ataRegs[kATARegCommand] = command;
}

//---------------------------------------------------------------------------
// Allocate and return an IOATACommand that is initialized to perform
// a read/write operation.
//
// buffer   - IOMemoryDescriptor object describing this transfer.
// block    - Initial transfer block.
// nblks    - Number of blocks to transfer.

IOATACommand *
IOATAHDDrive::ataCommandReadWrite(IOMemoryDescriptor * buffer,
                                  UInt32               block,
                                  UInt32               nblks)
{
	ATATaskfile    taskfile;
	bool           isWrite;
	IOATACommand * cmd = allocateCommand();

	assert(buffer);

	if (!cmd) return 0;		// error, command allocation failed.

	isWrite = (buffer->getDirection() == kIODirectionOut) ?
	          true : false;

#ifdef DEBUG_LOG
	IOLog("%s::ataCommandReadWrite %08x (%d) %s %d %d\n",
		getName(),
		buffer,
		buffer->getLength(),
		isWrite ? "WR" : "RD",
		block,
		nblks);
#endif

#if 0	// used for testing - force PIO mode
	setupReadWriteTaskFile(&taskfile,
	                       kATAProtocolPIO,
	                       isWrite ? kIOATACommandWritePIO : 
						   kIOATACommandReadPIO,
	                       block,
	                       nblks);
#else

	// Setup the taskfile structure with the size and direction of the
	// transfer. This structure will be written to the actual taskfile
	// registers when this command is processed.
	//
	setupReadWriteTaskFile(&taskfile,
	                       _ataProtocol,
	                       isWrite ? _ataWriteCmd : _ataReadCmd,
	                       block,
	                       nblks);
#endif

	// Get a pointer to the client data buffer, and record parameters
	// which shall be later used by the completion routine.
	//
	ATA_CLIENT_DATA(cmd)->buffer = buffer;

	cmd->setTaskfile(&taskfile);

	cmd->setPointers(buffer,                /* (IOMemoryDescriptor *) */
                     buffer->getLength(),   /* transferCount (bytes) */
                     isWrite);              /* isWrite */

	return cmd;
}

//---------------------------------------------------------------------------
// Allocate and return a ATA SetFeatures command.

IOATACommand *
IOATAHDDrive::ataCommandSetFeatures(UInt8 features,
                                    UInt8 SectorCount,
                                    UInt8 SectorNumber,
                                    UInt8 CylinderLow,
                                    UInt8 CyclinderHigh)
{
	ATATaskfile    taskfile;
	IOATACommand * cmd = allocateCommand();

    if (!cmd) return 0;		// error, command allocation failed.

	taskfile.protocol   = kATAProtocolPIO;

	taskfile.regmask    = ATARegtoMask(kATARegSectorNumber)  |
                          ATARegtoMask(kATARegCylinderLow)   |
                          ATARegtoMask(kATARegCylinderHigh)  |
                          ATARegtoMask(kATARegDriveHead)     |
                          ATARegtoMask(kATARegSectorCount)   |
                          ATARegtoMask(kATARegCommand);

	taskfile.resultmask = ATARegtoMask(kATARegError) |
                          ATARegtoMask(kATARegStatus);

	taskfile.ataRegs[kATARegFeatures]     = features;
	taskfile.ataRegs[kATARegSectorNumber] = SectorNumber;
	taskfile.ataRegs[kATARegCylinderLow]  = CylinderLow;
	taskfile.ataRegs[kATARegCylinderHigh] = CyclinderHigh;
    taskfile.ataRegs[kATARegDriveHead]    = kATAModeLBA | (_unit << 4);
	taskfile.ataRegs[kATARegSectorCount]  = SectorCount;
    taskfile.ataRegs[kATARegCommand]      = kIOATACommandSetFeatures;

	cmd->setTaskfile(&taskfile);

    // This is a way to issue a command which will wait
    // for an interrupt, but does no data transfer.

    cmd->setPointers(0, 0, false);
    
	return cmd;
}

//---------------------------------------------------------------------------
// Return a Flush Cache command.

IOATACommand *
IOATAHDDrive::ataCommandFlushCache()
{
    ATATaskfile    taskfile;
	IOATACommand * cmd = allocateCommand();

    if (!cmd) return 0;		// error, command allocation failed.

    // kATAProtocolSetRegs does not wait for an interrupt from the drive.

    taskfile.protocol   = kATAProtocolPIO;

    taskfile.regmask    = ATARegtoMask(kATARegDriveHead) |
                            ATARegtoMask(kATARegCommand);

    taskfile.resultmask = ATARegtoMask(kATARegError)        |
                            ATARegtoMask(kATARegSectorNumber) |
                            ATARegtoMask(kATARegCylinderLow)  |
                            ATARegtoMask(kATARegCylinderHigh) |
                            ATARegtoMask(kATARegDriveHead)    |
                            ATARegtoMask(kATARegStatus);

    taskfile.ataRegs[kATARegDriveHead] = kATAModeLBA | (_unit << 4);
    taskfile.ataRegs[kATARegCommand]   = kIOATACommandFlushCache;

    cmd->setTaskfile(&taskfile);

    // This is a way to issue a command which will wait
    // for an interrupt, but does no data transfer.

    cmd->setPointers(0, 0, false);

    return cmd;
}

//---------------------------------------------------------------------------
// Return a STANDBY IMMEDIATE command.

IOATACommand *
IOATAHDDrive::ataCommandStandby()
{
    ATATaskfile    taskfile;
	IOATACommand * cmd = allocateCommand();

	if (!cmd) return 0;		// error, command allocation failed.

    // kATAProtocolSetRegs does not wait for an interrupt from the drive.

    taskfile.protocol   = kATAProtocolPIO;

    taskfile.regmask    = ATARegtoMask(kATARegDriveHead) |
                          ATARegtoMask(kATARegCommand);

    taskfile.resultmask = ATARegtoMask(kATARegError)     |
                          ATARegtoMask(kATARegStatus);

    taskfile.ataRegs[kATARegDriveHead] = kATAModeLBA | (_unit << 4);
    taskfile.ataRegs[kATARegCommand]   = kIOATACommandStandbyImmediate;

    cmd->setTaskfile(&taskfile);

    // This is a way to issue a command which will wait
    // for an interrupt, but does no data transfer.

    cmd->setPointers(0, 0, false);

    return cmd;
}

//---------------------------------------------------------------------------
// This routine is called by our provider when a command processing has
// completed.

void
IOATAHDDrive::sHandleCommandCompletion(IOATAHDDrive * self,
                                       IOATACommand * cmd)
{
	ATAResults        results;
    IOATADevice *     device;
    IOATAClientData * clientData;

	assert(cmd);
    device = cmd->getDevice(kIOATADevice);
    assert(device);

	clientData = ATA_CLIENT_DATA(cmd);
	assert(clientData);

	if ((cmd->getResults(&results) != kIOReturnSuccess) &&
		(clientData->maxRetries-- > 0))
    {
        cmd->execute();
        return;
    }
    
#if 0
	// Force command retry to test retry logic.
	// Controller will reset the IOMemoryDescriptor's position, right?
	//
	cmd->getResults(&results);
	if (clientData->maxRetries-- > 2) {		
		cmd->execute();
        return;
	}
#endif

#ifdef DEBUG_LOG
	IOLog("%s: sHandleCommandCompletion %08x %08x %08x %08x %d\n",
		getName(), device, cmd, refcon, results.returnCode,
		results.bytesTransferred);
#endif

	// Return IOReturn for sync commands.
	//
	clientData->returnCode = results.returnCode;

	if (clientData->isSync) {
		// For sync commands, unblock the client thread.
		//
		assert(clientData->completion.syncLock);
		clientData->completion.syncLock->signal();	// unblock the client.
	}
	else {
		// Signal the completion routine that the request has been completed.
		//

        IOStorage::complete(clientData->completion.async,
                            results.returnCode,
                            (UInt64) results.bytesTransferred);
	}

	// Release the IOMemoryDescriptor.
	//
	if (clientData->buffer)
		clientData->buffer->release();

	// Command processing is complete, release the command object.
	//
	cmd->release();
}

//---------------------------------------------------------------------------
// Issue a synchronous ATA command.

IOReturn
IOATAHDDrive::syncExecute(IOATACommand *       cmd,       /* command object */
                          UInt32               timeout,   /* timeout in ms */
                          UInt                 retries,   /* max retries */
                          IOMemoryDescriptor * senseData)
{
	IOATAClientData * clientData = ATA_CLIENT_DATA(cmd);

    if ( _pmReady )
    {
        activityTickle( kIOPMSuperclassPolicy1, 1 );
    }

	// Bump the retain count on the command. The completion handler
	// will decrement the retain count.
	//
	cmd->retain();

	// Set timeout and register the completion handler.
	//
    cmd->setPointers(senseData, 
                     senseData ? senseData->getLength() : 0,
                     false,  /* isWrite */
                     true ); /* isSense */
    cmd->setTimeout(timeout);
    cmd->setCallback(this,
                     (CallbackFn) &IOATAHDDrive::sHandleCommandCompletion,
                     (void *) cmd);

	// Increment the retain count on the IOMemoryDescriptor.
	// Release when the completion routine gets called.
	//
	if (clientData->buffer)
		clientData->buffer->retain();

	// Set the max retry count. If retry count is 0, then the command shall
	// not be retried if an error occurs.
	//
	clientData->maxRetries = retries;
	clientData->completion.syncLock = IOSyncer::create();
	clientData->isSync = true;

	cmd->execute();

	// Block client thread on lock until the completion handler
	// receives an indication that the processing is complete.
	//
    clientData->completion.syncLock->wait();

	return clientData->returnCode;
}

//---------------------------------------------------------------------------
// Issue an asynchronous ATA command.

IOReturn
IOATAHDDrive::asyncExecute(IOATACommand *      cmd,      /* command object */
                           IOStorageCompletion completion,
                           UInt32              timeout,  /* timeout in ms */
                           UInt                retries)  /* max retries */
{
	IOATAClientData * clientData = ATA_CLIENT_DATA(cmd);

    if ( _pmReady )
    {
        activityTickle( kIOPMSuperclassPolicy1, 1 );
    }

	// Bump the retain count on the command. The completion handler
	// will decrement the retain count.
	//
	cmd->retain();

	// Set timeout and register the completion handler.
	//
	cmd->setTimeout(timeout);
    cmd->setCallback(this,
                     (CallbackFn) &IOATAHDDrive::sHandleCommandCompletion,
                     (void *) cmd);

	// Increment the retain count on the IOMemoryDescriptor.
	// Release when the completion routine gets called.
	//
	if (clientData->buffer)
		clientData->buffer->retain();

	// Set the max retry count. If retry count is 0, then the command shall
	// not be retried if an error occurs.
	//
	clientData->maxRetries = retries;
	clientData->isSync     = false;
	
	clientData->completion.async = completion;

	return (cmd->execute() ? kIOReturnSuccess : kIOReturnNoResources);
}

//---------------------------------------------------------------------------
// Allocate an IOATACommand object with a fixed client data area.

IOATACommand *
IOATAHDDrive::allocateCommand()
{
	return _ataDevice->allocCommand(kIOATADevice, sizeof(IOATAClientData));
}
