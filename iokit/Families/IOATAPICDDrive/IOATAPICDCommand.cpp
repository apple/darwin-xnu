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

#include <IOKit/assert.h>
#include <IOKit/storage/ata/IOATAPICDDrive.h>

//---------------------------------------------------------------------------
// ATAPI Read TOC command (43).

IOATACommand *
IOATAPICDDrive::atapiCommandReadTOC(IOMemoryDescriptor * buffer,
                                    bool                 msf,
                                    UInt8                format,
                                    UInt8                startTrackSession)
{
    ATACDBInfo	atapiCmd;

	assert(buffer);

	// Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandReadTOC;
	atapiCmd.cdb[1]    = msf ? 0x02 : 0x00;
	atapiCmd.cdb[6]    = startTrackSession;
	atapiCmd.cdb[7]    = (UInt8)(buffer->getLength() >> 8);
	atapiCmd.cdb[8]    = (UInt8)(buffer->getLength());

    if ((format & 0x04))
        atapiCmd.cdb[2] = (format & 0x07);  // new format field
    else
        atapiCmd.cdb[9] = (format & 0x03) << 6;  // old format field

	return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// atapiCommandPlayAudioMSF

IOATACommand *
IOATAPICDDrive::atapiCommandPlayAudioMSF(CDMSF timeStart, CDMSF timeStop)
{
    ATACDBInfo	atapiCmd;

    bzero(&atapiCmd, sizeof(atapiCmd));
    atapiCmd.cdbLength = 12;

    atapiCmd.cdb[0]    = kIOATAPICommandPlayAudioMSF;

    // starting MSF address
    atapiCmd.cdb[3]    = timeStart.minute;
    atapiCmd.cdb[4]    = timeStart.second;
    atapiCmd.cdb[5]    = timeStart.frame;

    // ending MSF address
    atapiCmd.cdb[6]    = timeStop.minute;
    atapiCmd.cdb[7]    = timeStop.second;
    atapiCmd.cdb[8]    = timeStop.frame;

    return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// atapiCommandPauseResume

IOATACommand *
IOATAPICDDrive::atapiCommandPauseResume(bool resume)
{
    ATACDBInfo	atapiCmd;

    bzero(&atapiCmd, sizeof(atapiCmd));
    atapiCmd.cdbLength = 12;

    atapiCmd.cdb[0]    = kIOATAPICommandPauseResume;

    // set resume bit
    if (resume) atapiCmd.cdb[8]    = 0x01;

    return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// atapiCommandStopPlay

IOATACommand *
IOATAPICDDrive::atapiCommandStopPlay()
{
    ATACDBInfo	atapiCmd;

    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandStopPlay;

    return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// atapiCommandReadSubChannel

IOATACommand *
IOATAPICDDrive::atapiCommandReadSubChannel(IOMemoryDescriptor * buffer,
                                           UInt8                dataFormat,
                                           UInt8                trackNumber)
{
    ATACDBInfo atapiCmd;

    assert(buffer);

    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandReadSubChannel;
    atapiCmd.cdb[1]    = 0x02;
    atapiCmd.cdb[2]    = 0x40;
    atapiCmd.cdb[3]    = dataFormat;
    atapiCmd.cdb[6]    = trackNumber;
    atapiCmd.cdb[7]    = (buffer->getLength() >> 8) & 0xff;
    atapiCmd.cdb[8]    =  buffer->getLength() & 0xff;

    return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// atapiCommandScan

IOATACommand *
IOATAPICDDrive::atapiCommandScan(CDMSF timeStart, bool reverse)
{
    ATACDBInfo	atapiCmd;

    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandScan;
    atapiCmd.cdb[1]    = reverse ? 0x10 : 0x00;
    atapiCmd.cdb[3]    = timeStart.minute;
    atapiCmd.cdb[4]    = timeStart.second;
    atapiCmd.cdb[5]    = timeStart.frame;
    atapiCmd.cdb[9]    = 0x40;  // MSF

    return atapiCommand(&atapiCmd);
}

//---------------------------------------------------------------------------
// Allocates and return an IOATACommand to perform a read/write operation.

IOATACommand *
IOATAPICDDrive::atapiCommandReadCD(IOMemoryDescriptor * buffer,
                                   UInt32               block,
                                   UInt32               nblks,
                                   CDSectorArea         sectorArea,
                                   CDSectorType         sectorType)
{
    ATACDBInfo	atapiCmd;

    assert(buffer);

    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[ 0]   = kIOATAPICommandReadCD;
    atapiCmd.cdb[ 1]   = (sectorType & 0x7) << 2;
    atapiCmd.cdb[ 2]   = (block >> 24) & 0xFF;
    atapiCmd.cdb[ 3]   = (block >> 16) & 0xFF;
    atapiCmd.cdb[ 4]   = (block >>  8) & 0xFF;
    atapiCmd.cdb[ 5]   = (block      ) & 0xFF;
    atapiCmd.cdb[ 6]   = (nblks >> 16) & 0xFF;
    atapiCmd.cdb[ 7]   = (nblks >>  8) & 0xFF;
    atapiCmd.cdb[ 8]   = (nblks      ) & 0xFF;
    atapiCmd.cdb[ 9]   = (sectorArea & ~kCDSectorAreaSubChannel);
    atapiCmd.cdb[10]   = (sectorArea &  kCDSectorAreaSubChannel);

	return atapiCommand(&atapiCmd, buffer);
}
