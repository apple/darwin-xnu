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
 *  1 Dec 1998 suurballe  Created.
 */

#include <IOKit/adb/IOADBController.h>

class AppleCuda;


class IOCudaADBController : public IOADBController
{
OSDeclareDefaultStructors(IOCudaADBController)

private:

AppleCuda *	CudaDriver;
UInt32		pollList;		// ADB autopoll device bitmap
bool		autopollOn;		// TRUE: PMU is autopolling

public:

bool init ( OSDictionary * properties, AppleCuda * driver );
bool start ( IOService * );
IOReturn setAutoPollPeriod ( int microseconds );
IOReturn getAutoPollPeriod ( int * microseconds );
IOReturn setAutoPollList ( UInt16 activeAddressMask );
IOReturn getAutoPollList ( UInt16 * activeAddressMask );
IOReturn setAutoPollEnable ( bool enable );
IOReturn resetBus ( void );
IOReturn flushDevice ( IOADBAddress address );
IOReturn readFromDevice ( IOADBAddress address, IOADBRegister adbRegister,
			UInt8 * data, IOByteCount * length );
IOReturn writeToDevice ( IOADBAddress address, IOADBRegister adbRegister,
			UInt8 * data, IOByteCount * length );
};
