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
 *
 * SCSICommand.h
 *
 */

#ifndef _SCSICOMMAND_H
#define _SCSICOMMAND_H

typedef struct SCSICDBInfo
{

    UInt32		cdbFlags;

    UInt32		cdbTagMsg;
    UInt32		cdbTag;

    UInt32		cdbAbortMsg;

    UInt32		cdbLength;
    UInt8		cdb[16];
    
    UInt32              reserved[16];
} SCSICDBInfo;


enum SCSICDBFlags
{
    kCDBFNoDisconnect		= 0x00000001,

/*  
 *  Note: These flags are for IOSCSIController subclasses only
 */
    kCDBFlagsNegotiatePPR	= 0x04000000,
    kCDBFlagsDisableParity      = 0x08000000,
    kCDBFlagsNoDisconnect       = 0x10000000,
    kCDBFlagsNegotiateSDTR	= 0x20000000,
    kCDBFlagsNegotiateWDTR	= 0x40000000,
//                              = 0x80000000,           // reserved
};

enum SCSIAdapterStatus
{
    kSCSIAdapterStatusSuccess   	= 0,
    kSCSIAdapterStatusProtocolError,
    kSCSIAdapterStatusSelectionTimeout,
    kSCSIAdapterStatusMsgReject,
    kSCSIAdapterStatusParityError,
    kSCSIAdapterStatusOverrun,
};

typedef struct SCSIResults
{
    IOReturn			returnCode;

    UInt32			bytesTransferred;

    enum SCSIAdapterStatus 	adapterStatus;
    UInt8			scsiStatus;

    Boolean			requestSenseDone;
    UInt32			requestSenseLength;
    
    UInt32              	reserved[16];
} SCSIResults;

    
#endif
