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
 * ATACommand.h
 *
 */

#ifndef _ATACOMMAND_H
#define _ATACOMMAND_H


enum ATADeviceType
{
    kATADeviceNone,
    kATADeviceATA,
    kATADeviceATAPI,
};


enum ATATimingProtocol
{
    kATATimingPIO		= (1 << 0),
    kATATimingDMA     		= (1 << 1),
    kATATimingUltraDMA33	= (1 << 2),
    kATATimingUltraDMA66	= (1 << 3),
    kATAMaxTimings		= 4,

};

enum ATAProtocol
{
   kATAProtocolNone		= 0,
   kATAProtocolSetRegs		= (1 << 0),
   kATAProtocolPIO		= (1 << 1),
   kATAProtocolDMA		= (1 << 2),
   kATAProtocolDMAQueued	= (1 << 3),
   kATAProtocolDMAQueuedRelease	= (1 << 4),

   kATAProtocolATAPIPIO		= (1 << 16),
   kATAProtocolATAPIDMA		= (1 << 17),
};



typedef struct ATATiming
{
    enum ATATimingProtocol	timingProtocol;

    UInt32		featureSetting;

    UInt32		mode;
    UInt32		minDataAccess;
    UInt32		minDataCycle;
    UInt32		minCmdAccess;
    UInt32		minCmdCycle;
    UInt32		reserved_3[9];
} ATATiming;


enum ATATagType
{
    kATATagTypeNone	= 0,
    kATATagTypeSimple,
};

enum ATAReturnCode
{
    kATAReturnSuccess,
    kATAReturnNotSupported,
    kATAReturnNoResource,
    kATAReturnRetryPIO,
    kATAReturnBusyError,
    kATAReturnInterruptTimeout,
    kATAReturnStatusError,
    kATAReturnProtocolError,
    kATAReturnDMAError,
    kATAReturnBusReset,
};

#define ATARegtoMask(reg) (1<<(reg))

typedef struct ATATaskfile	
{
    enum ATAProtocol	protocol;
   
    UInt32		flags;
  
    UInt8		tagType;
    UInt32		tag;

    UInt32		resultmask;

    UInt32		regmask;
    UInt32              ataRegs[kMaxATARegs];

} ATATaskfile;


enum ATACmdFlags
{
    kATACmdFlagTimingChanged		= 0x00000001,
};

typedef struct ATACDBInfo
{

    UInt32		cdbFlags;

    UInt32		cdbLength;
    UInt8		cdb[16];
    
    UInt32              reserved[16];
} ATACDBInfo;


enum ATACDBFlags
{
};

typedef struct ATAResults
{
    IOReturn		returnCode;
 
    UInt32		bytesTransferred;

    enum ATAReturnCode  adapterStatus;

    Boolean		requestSenseDone;
    UInt32		requestSenseLength;

    UInt32              ataRegs[kMaxATARegs];
    
    UInt32              reserved[16];
} ATAResults;

    
#endif
