/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/* Sym8xxSRB.h created by russb2 on Sat 30-May-1998 */

/*
 * The SRB is the main per-request data structure used by the driver.
 *
 * It contains an embedded Nexus structure which is used as a per-request
 * communication area between the script and the driver.
 */ 

typedef struct SRB 		SRB;

struct	SRB
{
    SRB				*srbPhys;

    IOSCSIParallelCommand	*scsiCommand;

    UInt32   			srbCDBFlags;

    IOReturn     		srbReturnCode;
    SCSIAdapterStatus		srbAdapterStatus;
    UInt8      			srbSCSIStatus;

    UInt8      			srbMsgResid;
    UInt8      			srbMsgLength;

    UInt8      			target;
    UInt8      			lun;
    UInt8      			tag;

    UInt8			negotiateSDTRComplete;
    UInt8			negotiateWDTRComplete;

    UInt32   			directionMask;

    IOMemoryDescriptor		*xferDesc;
    UInt32   			xferOffset;
    UInt32   			xferOffsetPrev;
    UInt32          		xferCount;
    UInt32   			xferDone;

    Nexus			nexus;  

};

