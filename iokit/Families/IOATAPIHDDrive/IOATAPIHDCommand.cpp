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
 * IOATAPIHDCommand.cpp - Performs ATAPI command processing.
 *
 * HISTORY
 * Sep 2, 1999	jliu - Ported from AppleATAPIDrive.
 */

#include <IOKit/assert.h>
#include <IOKit/storage/ata/IOATAPIHDDrive.h>

#define	super IOATAHDDrive

// Enable this define to generate debugging messages.
// #define DEBUG_LOG 1

//---------------------------------------------------------------------------
// Returns the Command protocol to use (e.g. ataProtocolPIO, ataProtocolDMA).

bool
IOATAPIHDDrive::selectCommandProtocol(bool isDMA)
{
	super::selectCommandProtocol(isDMA);

	if (isDMA)
		_atapiProtocol = kATAProtocolATAPIDMA;
	else
		_atapiProtocol = kATAProtocolATAPIPIO;
	
	return true;
}

//---------------------------------------------------------------------------
// Setup a ATATaskFile for an ATAPI packet command from the parameters given.

void
IOATAPIHDDrive::setupPacketTaskFile(ATATaskfile * taskfile,
                                    ATAProtocol   protocol,
                                    UInt16        byteCount)
{
    bzero( taskfile, sizeof(ATATaskfile) );

	taskfile->protocol = protocol;

	taskfile->regmask  = ATARegtoMask(kATARegATAPIDeviceSelect) 
                       | ATARegtoMask(kATARegATAPICommand)
                       | ATARegtoMask(kATARegATAPIByteCountLow)
                       | ATARegtoMask(kATARegATAPIByteCountHigh)
                       | ATARegtoMask(kATARegATAPIFeatures);
					
	taskfile->resultmask = ATARegtoMask(kATARegATAPIError);

	taskfile->ataRegs[kATARegATAPIDeviceSelect]  = kATAModeLBA | (_unit << 4);
	taskfile->ataRegs[kATARegATAPICommand]       = kATACommandATAPIPacket;
    taskfile->ataRegs[kATARegATAPIByteCountLow]  = byteCount & 0xff;
    taskfile->ataRegs[kATARegATAPIByteCountHigh] = (byteCount >> 8) & 0xff;
	taskfile->ataRegs[kATARegATAPIFeatures]      = (protocol ==
                                                   kATAProtocolATAPIPIO) ?
                                                   0 : kIOATAPIFeaturesDMA;
}

//---------------------------------------------------------------------------
// Create a generic ATAPI command object.

IOATACommand *
IOATAPIHDDrive::atapiCommand(ATACDBInfo *         packetCommand,
                             IOMemoryDescriptor * transferBuffer = 0)
{
	ATATaskfile    taskfile;
	bool           isWrite;
	UInt32         transferLength;
	IOATACommand * cmd = allocateCommand();

	if (!cmd) return 0;		// error, command allocation failed.
	
	// Create ATA packet command.
	//
	setupPacketTaskFile(&taskfile, _atapiProtocol, kIOATAPIMaxTransfer);

	// Get a pointer to the client data buffer, and record parameters
	// which shall be later used by the completion routine.
	//
	IOATAClientData * clientData = ATA_CLIENT_DATA(cmd);
	assert(clientData);

	clientData->buffer  = transferBuffer;

	cmd->setTaskfile(&taskfile);
	cmd->setCDB(packetCommand);
    
	if (transferBuffer) {
		isWrite = (transferBuffer->getDirection() == kIODirectionOut);
		transferLength = transferBuffer->getLength();
	}
	else {
		isWrite = false;
		transferLength = 0;
	}
	cmd->setPointers(transferBuffer, transferLength, isWrite);

	return cmd;
}

//---------------------------------------------------------------------------
// Allocates and return an IOATACommand to perform a read/write operation.

IOATACommand *
IOATAPIHDDrive::atapiCommandReadWrite(IOMemoryDescriptor * buffer,
                                      UInt32               block,
                                      UInt32               nblks)
{
    ATACDBInfo	atapiCmd;

	assert(buffer);

#ifdef DEBUG_LOG
	IOLog("%s: atapiCommandReadWrite %08x (%d) %s %d %d\n",
		getName(),
		buffer,
		buffer->getLength(),
		(buffer->getDirection() == kIODirectionOut) ? "WR" :
		"RD",
		block,
		nblks);
#endif

	// Create the ATAPI packet (bytes 1, 10, 11 are reserved).
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = (buffer->getDirection() == kIODirectionOut) ? 
                          kIOATAPICommandWrite : kIOATAPICommandRead;
    atapiCmd.cdb[2]    = (UInt8)(block >> 24);
	atapiCmd.cdb[3]    = (UInt8)(block >> 16);
	atapiCmd.cdb[4]    = (UInt8)(block >>  8);
	atapiCmd.cdb[5]    = (UInt8)(block);
    atapiCmd.cdb[6]    = (UInt8)(nblks >> 24);
	atapiCmd.cdb[7]    = (UInt8)(nblks >> 16);
	atapiCmd.cdb[8]    = (UInt8)(nblks >>  8);
	atapiCmd.cdb[9]    = (UInt8)(nblks);

	return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// ATAPI Start/Stop Unit command (1B).

IOATACommand *
IOATAPIHDDrive::atapiCommandStartStopUnit(bool doStart,
                                          bool doLoadEject,
                                          bool immediate)
{
    ATACDBInfo	atapiCmd;

#ifdef DEBUG_LOG
	IOLog("%s: atapiCommandStartStopUnit: %s\n", getName(),
		doStart ? "start" : "stop");
#endif

	// Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandStartStopUnit;
	atapiCmd.cdb[1]    = immediate ?    0x01 : 0x00;
	atapiCmd.cdb[4]    = (doStart     ? 0x01 : 0) |
                         (doLoadEject ? 0x02 : 0);

	return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// ATAPI Format Unit command (04).

IOATACommand *
IOATAPIHDDrive::atapiCommandFormatUnit(UInt16               interleave,
                                       UInt8                flagBits,
                                       UInt8                vendorBits,
                                       IOMemoryDescriptor * formatData)
{
    ATACDBInfo	atapiCmd;

	// Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandFormatUnit;
	atapiCmd.cdb[1]    = flagBits;
    atapiCmd.cdb[3]    = (UInt8)(interleave >> 8);
    atapiCmd.cdb[4]    = (UInt8)(interleave);
	atapiCmd.cdb[5]    = vendorBits;

    if (formatData)
        atapiCmd.cdb[1] |= 0x10;

	return atapiCommand(&atapiCmd, formatData);
}

//---------------------------------------------------------------------------
// ATAPI Synchronize Cache command (35).

IOATACommand *
IOATAPIHDDrive::atapiCommandSynchronizeCache()
{
    ATACDBInfo	atapiCmd;

	// Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandSynchronizeCache;

	return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// ATAPI Prevent/Allow medium removal command (1E).

IOATACommand *
IOATAPIHDDrive::atapiCommandPreventAllowRemoval(bool doLock)
{
    ATACDBInfo	atapiCmd;

	// Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandPreventAllow;
	atapiCmd.cdb[4]    = doLock ? 0x01 : 0;

	return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// ATAPI Test Unit Ready command (00).

IOATACommand *
IOATAPIHDDrive::atapiCommandTestUnitReady()
{
    ATACDBInfo	atapiCmd;

#ifdef DEBUG_LOG
	IOLog("%s: atapiCommandTestUnitReady\n", getName());
#endif

	// Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandTestUnitReady;

	return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// atapiCommandModeSense

IOATACommand *
IOATAPIHDDrive::atapiCommandModeSense(IOMemoryDescriptor * buffer,
                                      UInt8                pageCode,
                                      UInt8                pageControl)
{
    ATACDBInfo atapiCmd;

    assert(buffer);

    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandModeSense;
    atapiCmd.cdb[2]    = (pageCode & 0x3f) | ((pageControl & 0x3) << 6);
    atapiCmd.cdb[7]    = (buffer->getLength() >> 8) & 0xff;
    atapiCmd.cdb[8]    =  buffer->getLength() & 0xff;

    return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// atapiCommandModeSelect

IOATACommand *
IOATAPIHDDrive::atapiCommandModeSelect(IOMemoryDescriptor * buffer)
{
    ATACDBInfo atapiCmd;

    assert(buffer);

    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandModeSelect;
    atapiCmd.cdb[1]    = 0x10;
    atapiCmd.cdb[7]    = (buffer->getLength() >> 8) & 0xff;
    atapiCmd.cdb[8]    =  buffer->getLength() & 0xff;

    return atapiCommand(&atapiCmd, buffer);
}
