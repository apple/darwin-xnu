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
#include <IOKit/storage/ata/IOATAPIDVDDrive.h>

//---------------------------------------------------------------------------
// SEND KEY command.

IOATACommand *
IOATAPIDVDDrive::atapiCommandSendKey(IOMemoryDescriptor * buffer,
                                     const DVDKeyClass    keyClass,
                                     const UInt8          agid,
                                     const DVDKeyFormat   keyFormat)
{
    ATACDBInfo	atapiCmd;

	assert(buffer);

    // Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandSendKey;
    atapiCmd.cdb[7]    = keyClass;
    atapiCmd.cdb[8]    = (UInt8)(buffer->getLength() >> 8);
    atapiCmd.cdb[9]    = (UInt8)(buffer->getLength());
    atapiCmd.cdb[10]   = agid << 6 | keyFormat;

    return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// REPORT KEY command.

IOATACommand *
IOATAPIDVDDrive::atapiCommandReportKey(IOMemoryDescriptor * buffer,
                                       const DVDKeyClass    keyClass,
                                       const UInt32         lba,
                                       const UInt8          agid,
                                       const DVDKeyFormat   keyFormat)
{
    ATACDBInfo	atapiCmd;

	assert(buffer);

    // Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandReportKey;

    if (keyFormat == kTitleKey) {
        atapiCmd.cdb[2] = (UInt8)(lba >> 24);
        atapiCmd.cdb[3] = (UInt8)(lba >> 16);
        atapiCmd.cdb[4] = (UInt8)(lba >> 8);
        atapiCmd.cdb[5] = (UInt8)(lba);
    }
    atapiCmd.cdb[7]    = keyClass;
    atapiCmd.cdb[8]    = (UInt8)(buffer->getLength() >> 8);
    atapiCmd.cdb[9]    = (UInt8)(buffer->getLength());
    atapiCmd.cdb[10]   = agid << 6 | keyFormat;

    return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// GET CONFIGURATION command.

IOATACommand *
IOATAPIDVDDrive::atapiCommandGetConfiguration(IOMemoryDescriptor * buffer,
                                              UInt8                rt,
                                              UInt16               sfn = 0)
{
    ATACDBInfo	atapiCmd;

	assert(buffer);

    // Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandGetConfiguration;
    atapiCmd.cdb[1]    = rt & 0x03;
    atapiCmd.cdb[2]    = (UInt8)(sfn >> 8);  // starting feature number MSB
    atapiCmd.cdb[3]    = (UInt8)(sfn);       // starting feature number LSB
    atapiCmd.cdb[7]    = (UInt8)(buffer->getLength() >> 8);
    atapiCmd.cdb[8]    = (UInt8)(buffer->getLength());

    return atapiCommand(&atapiCmd, buffer);
}

//---------------------------------------------------------------------------
// READ DVD STRUCTURE command.

IOATACommand *
IOATAPIDVDDrive::atapiCommandReadDVDStructure(IOMemoryDescriptor * buffer,
                                              UInt8                format,
                                              UInt32               address = 0,
                                              UInt8                layer   = 0,
                                              UInt8                agid    = 0)
{
    ATACDBInfo	atapiCmd;

	assert(buffer);

    // Create the ATAPI packet.
	//
    bzero(&atapiCmd, sizeof(atapiCmd));

    atapiCmd.cdbLength = 12;
    atapiCmd.cdb[0]    = kIOATAPICommandReadDVDStructure;
    atapiCmd.cdb[2]    = (UInt8)(address >> 24);
    atapiCmd.cdb[3]    = (UInt8)(address >> 16);
    atapiCmd.cdb[4]    = (UInt8)(address >> 8);
    atapiCmd.cdb[5]    = (UInt8)(address);
    atapiCmd.cdb[6]    = layer;
    atapiCmd.cdb[7]    = format;
    atapiCmd.cdb[8]    = (UInt8)(buffer->getLength() >> 8);
    atapiCmd.cdb[9]    = (UInt8)(buffer->getLength());
    atapiCmd.cdb[10]   = (agid & 0x3) << 6;

    return atapiCommand(&atapiCmd, buffer);
}
