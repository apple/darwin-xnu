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
 *	ATAParallelController.h
 *
 */
 
#ifndef _ATASTANDARDCONTROLLER_H
#define _ATASTANDARDCONTROLLER_H

class IOSyncer;

typedef struct ATAControllerInfo
{
    UInt32	maxDevicesSupported;
 
    UInt32	devicePrivateDataSize;
    UInt32	commandPrivateDataSize;

    bool	disableCancelCommands;

    UInt32	reserved[64];

} ATAControllerInfo;

/*
 * Private for IOATAClass
 */
enum WorkLoopReqType
{
    kWorkLoopInitDevice			= 1,
    kWorkLoopReleaseDevice,
};

enum DispatchAction
{
    kDispatchNextCommand	= 1,
    kDispatchNextDevice,
    kDispatchStop,
};

typedef struct WorkLoopRequest
{
    WorkLoopReqType     type;
    IOSyncer *		sync;
    bool		rc;
} WorkLoopRequest;

#endif

