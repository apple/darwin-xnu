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
 * 12 Nov 1998 suurballe  Created.
 */

#include <IOKit/adb/IOADBController.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOSyncer.h>

class IOPMUADBController : public IOADBController
{
    OSDeclareDefaultStructors(IOPMUADBController)

private:
    enum {
        kPMUNoError         = 0,
        kPMUInitError       = 1,    // PMU failed to initialize
        kPMUParameterError  = 2,    // Bad parameters
        kPMUNotSupported    = 3,    // PMU don't do that (Cuda does, though)
        kPMUIOError         = 4     // Nonspecific I/O failure
        };
    
    enum {
        kPMUpMgrADB	= 0x20, 		// send ADB command
        kPMUpMgrADBoff	= 0x21, 		// turn ADB auto-poll off
        kPMUreadADB	= 0x28, 		// Apple Desktop Bus
        kPMUpMgrADBInt	= 0x2F, 		// get ADB interrupt data (Portable only)
    };

    enum {
        kPMUADBAddressField = 4
    };

    enum {
        kPMUResetADBBus	= 0x00,
        kPMUFlushADB	= 0x01,
        kPMUWriteADB	= 0x08,
        kPMUReadADB     = 0x0C,
        kPMURWMaskADB	= 0x0C
    };

    enum {			          // when kPMUADBint is set
        kPMUADBint          = 0x10,
        kPMUwaitinglsc	    = 0x01,       // waiting to listen to charger
        kPMUautoSRQpolling  = 0x02,	  // auto/SRQ polling is enabled
        kPMUautopoll	    = 0x04	  // input is autopoll data
    };
    
    // We need this to callPlatformFunction when sending to sendMiscCommand
    typedef struct SendMiscCommandParameterBlock {
        int command;
        IOByteCount sLength;
        UInt8 *sBuffer;
        IOByteCount *rLength;
        UInt8 *rBuffer;
    } SendMiscCommandParameterBlock;
    typedef SendMiscCommandParameterBlock *SendMiscCommandParameterBlockPtr;
    
    // Local data:
    IOService	 	*PMUdriver;
    UInt32		pollList;		// ADB autopoll device bitmap
    bool		autopollOn;		// TRUE: PMU is autopolling

    UInt32		dataLen;		// data len as result of an interrupt
    UInt8		dataBuffer[256];	// data as result of an interrupt
    IOSyncer	*waitingForData;	// syncronizer for reads and writes.

    // Local interrupt handlers:
    static void handleADBInterrupt(IOService *client, UInt8 matchingMask, UInt32 length, UInt8 *buffer);

    // This lock protects the access to the common varialbes of this object:
    IOLock *requestMutexLock;

    // A simpler way to interface with the pmu SendMiscCommand
    IOReturn localSendMiscCommand(int command, IOByteCount sLength, UInt8 *sBuffer);

public:
        IOService *probe( IOService * nub, SInt32 * score );
    bool start ( IOService * );
    void free ();
    IOReturn setAutoPollPeriod ( int microseconds );
    IOReturn getAutoPollPeriod ( int * microseconds );
    IOReturn setAutoPollList ( UInt16 activeAddressMask );
    IOReturn getAutoPollList ( UInt16 * activeAddressMask );
    IOReturn setAutoPollEnable ( bool enable );
    IOReturn resetBus ( void );
    IOReturn cancelAllIO ( void );
    IOReturn flushDevice ( IOADBAddress address );
    IOReturn readFromDevice ( IOADBAddress address, IOADBRegister adbRegister, UInt8 * data, IOByteCount * length );
    IOReturn writeToDevice ( IOADBAddress address, IOADBRegister adbRegister, UInt8 * data, IOByteCount * length );
};
